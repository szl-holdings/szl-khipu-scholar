# SPDX-License-Identifier: Apache-2.0
"""A small tiled transparency log writer for signed receipts.

Entries are opaque bytes: append the receipt exactly as it was signed. The log
never parses, re-serializes or canonicalizes an entry, so it cannot change
what a receipt means; it only commits to its bytes.

    log = TileLog(DirTileStore(dir), origin="example.com/receipts", signer=signer,
                  state_path="/var/lib/receipts-log.state")   # outside `dir`
    idx = log.append(receipt_bytes)
    checkpoint_bytes = log.publish()      # writes tiles + `checkpoint`

Single writer. `publish` writes the tiles for the current size before the
checkpoint that refers to them, so a reader never sees a checkpoint whose tiles
are missing.

The log key never signs a tree that does not extend a checkpoint it already
signed (c2sp.org/tlog-checkpoint). Before signing, `publish` checks the new
tree against the checkpoint served in the store (verified under the log key),
the last checkpoint this object published, and, when `state_path` is given,
the last checkpoint recorded in that file. The file is written durably before
the signature exists; keep it outside the served directory, so that whoever
can write that directory cannot roll back what the writer remembers. After a
restart, `TileLog.resume` rebuilds the tree from the entry bundles.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Sequence

from . import merkle, tiles
from .checkpoint import Checkpoint, CheckpointError, open_checkpoint, sign_checkpoint
from .note import NoteError, Signer


class LogStateError(ValueError):
    """The writer refuses to sign: the tree would not extend a checkpoint this
    log key already signed, or the recorded state cannot be used."""


def _inside(path: Path, root: "str | os.PathLike[str] | None") -> bool:
    if root is None:
        return False
    return Path(os.path.realpath(path)).is_relative_to(os.path.realpath(root))


def _write_durably(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.urandom(8).hex()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class TileLog:
    def __init__(self, store: tiles.DirTileStore, origin: str, signer: Signer,
                 state_path: "str | os.PathLike[str] | None" = None):
        if signer.name != origin:
            raise ValueError("the log's signing key name must equal the origin")
        self.store = store
        self.origin = origin
        self.signer = signer
        self.state_path = None if state_path is None else Path(state_path)
        if self.state_path is not None and _inside(self.state_path, getattr(store, "root", None)):
            raise ValueError("keep the state file outside the served log directory")
        self._leaves: List[bytes] = []     # leaf hashes
        self._entries: List[bytes] = []
        self._levels: List[List[bytes]] = [[]]   # complete-subtree hashes by level
        self._published: Optional[Checkpoint] = None

    @classmethod
    def resume(cls, store: tiles.DirTileStore, origin: str, signer: Signer,
               state_path: "str | os.PathLike[str] | None" = None) -> "TileLog":
        """Reopen a log after a restart. The entries of the largest checkpoint
        this key signed or recorded are read back from the entry bundles and
        must rebuild its root exactly."""
        log = cls(store, origin, signer, state_path)
        earlier = log._earlier(log._read_state())
        if not earlier:
            return log
        last = max(earlier, key=lambda c: c.size)
        for index in range((last.size + tiles.TILE_WIDTH - 1) // tiles.TILE_WIDTH):
            width = tiles.tile_width_at(last.size, 0, index)
            entries = tiles.decode_bundle(store.get(tiles.entries_path(index, width)))
            if len(entries) != width:
                raise LogStateError(f"entry bundle {index} does not hold {width} entries")
            for e in entries:
                log.append(e)
        if log.root() != last.root:
            raise LogStateError("the entry bundles do not rebuild the signed root")
        log._check_extends(log.checkpoint(), earlier)
        return log

    @property
    def size(self) -> int:
        return len(self._leaves)

    def _node(self, level: int, index: int) -> bytes:
        return self._levels[level][index]

    def append(self, entry: bytes) -> int:
        entry = bytes(entry)
        if len(entry) > tiles.MAX_ENTRY:
            raise ValueError("entry longer than 65535 bytes")
        h = merkle.hash_leaf(entry)
        self._entries.append(entry)
        self._leaves.append(h)
        self._levels[0].append(h)
        level = 0
        while len(self._levels[level]) % 2 == 0:
            n = len(self._levels[level])
            parent = merkle.hash_children(self._levels[level][n - 2], self._levels[level][n - 1])
            if level + 1 == len(self._levels):
                self._levels.append([])
            self._levels[level + 1].append(parent)
            level += 1
        return self.size - 1

    def root(self) -> bytes:
        return merkle.tree_hash(self._node, self.size)

    def checkpoint(self) -> Checkpoint:
        return Checkpoint(self.origin, self.size, self.root())

    def write_tiles(self) -> None:
        """Write every tile and entry bundle for the current size."""
        self._write_tiles(None)

    def _write_tiles(self, signed: Optional[int]) -> None:
        # With `signed` set, a resource beyond that size was never signed: it is
        # a leftover of an interrupted publish and may be replaced. Everything
        # else is immutable.
        def immutable(level: int, index: int, width: int) -> bool:
            return signed is None or width <= tiles.tile_width_at(signed, level, index)

        size = self.size
        for level, index, width in tiles.tiles_for_size(size):
            first = index * tiles.TILE_WIDTH
            hashes = [self._node(level * tiles.TILE_HEIGHT, first + i) for i in range(width)]
            self.store.put(tiles.tile_path(level, index, width), b"".join(hashes),
                           immutable=immutable(level, index, width))
        for index in range((size + tiles.TILE_WIDTH - 1) // tiles.TILE_WIDTH):
            width = tiles.tile_width_at(size, 0, index)
            first = index * tiles.TILE_WIDTH
            self.store.put(tiles.entries_path(index, width),
                           tiles.encode_bundle(self._entries[first:first + width]),
                           immutable=immutable(0, index, width))

    def _read_state(self) -> Optional[Checkpoint]:
        if self.state_path is None:
            return None
        try:
            raw = self.state_path.read_bytes()
        except FileNotFoundError:
            return None
        try:
            cp = Checkpoint.parse(raw.decode("utf-8"))
        except (UnicodeDecodeError, CheckpointError) as e:
            raise LogStateError(f"unreadable state file: {e}") from e
        if cp.origin != self.origin:
            raise LogStateError("the state file is for a different origin")
        return cp

    def _earlier(self, recorded: Optional[Checkpoint]) -> List[Checkpoint]:
        """Every checkpoint the next one must extend."""
        out = [] if self._published is None else [self._published]
        if recorded is not None:
            out.append(recorded)
        try:
            served = self.store.get("checkpoint")
        except tiles.TileNotFound:
            return out
        try:
            out.append(open_checkpoint(served, [self.signer.verifier], origin=self.origin)[0])
        except NoteError as e:
            raise LogStateError(f"the served checkpoint does not verify under this log's key: {e}") from e
        return out

    def _check_extends(self, cp: Checkpoint, earlier: Sequence[Checkpoint]) -> None:
        for old in earlier:
            if cp.size < old.size:
                raise LogStateError(f"refusing to sign size {cp.size}: this key already signed size {old.size}")
            try:
                merkle.verify_consistency(old.size, cp.size,
                                          merkle.consistency_proof(self._node, old.size, cp.size),
                                          old.root, cp.root)
            except merkle.ProofError as e:
                raise LogStateError(f"refusing to sign a tree that does not extend the signed "
                                    f"size-{old.size} checkpoint") from e

    def publish(self) -> bytes:
        cp = self.checkpoint()
        earlier = self._earlier(self._read_state())
        self._check_extends(cp, earlier)
        # Only with a state file is "the largest size this key signed" known well
        # enough to replace leftovers beyond it; without one, every tile stays
        # immutable (a rolled-back directory could hide a signed size).
        self._write_tiles(None if self.state_path is None
                          else max((c.size for c in earlier), default=0))
        if self.state_path is not None:
            _write_durably(self.state_path, cp.text().encode("utf-8"))
        signed = sign_checkpoint(cp, [self.signer])
        self.store.put("checkpoint", signed, immutable=False)
        self._published = cp
        return signed
