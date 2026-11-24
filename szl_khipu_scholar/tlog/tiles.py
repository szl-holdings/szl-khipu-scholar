# SPDX-License-Identifier: Apache-2.0
"""Tile layout (c2sp.org/tlog-tiles): height-8 tiles, full and partial, plus
entry bundles.

    tile/<L>/<N>[.p/<W>]        hashes   (32 bytes each, 256 when full)
    tile/entries/<N>[.p/<W>]    entries  (uint16 big-endian length prefix each)
    checkpoint                  signed note

<N> is zero-padded 3-digit path elements, all but the last prefixed with "x"
(1234067 -> x001/x234/067). Level L tile N holds the hashes of tree level 8*L
for indices N*256 .. N*256+255. A partial tile for tree size s at level L has
floor(s / 256**L) mod 256 hashes and is never hashed into the level above.
"""
from __future__ import annotations

import errno
import os
import re
import stat
from pathlib import Path
from typing import Callable, Dict, List, Sequence, Tuple

from . import merkle

TILE_HEIGHT = 8
TILE_WIDTH = 1 << TILE_HEIGHT        # 256 hashes
MAX_LEVEL = 63
MAX_ENTRY = 0xFFFF                   # uint16 length prefix

_INDEX_RE = re.compile(r"(?:x\d{3}/)*\d{3}")

# fetch(path) -> bytes; raises TileNotFound when the resource does not exist
Fetch = Callable[[str], bytes]


class TileNotFound(KeyError):
    pass


class TileError(ValueError):
    pass


def encode_index(n: int) -> str:
    if n < 0:
        raise TileError("negative tile index")
    groups: List[str] = []
    while True:
        groups.append(f"{n % 1000:03d}")
        n //= 1000
        if n == 0:
            break
    groups.reverse()
    return "/".join(["x" + g for g in groups[:-1]] + [groups[-1]])


def decode_index(s: str) -> int:
    if not _INDEX_RE.fullmatch(s):
        raise TileError("malformed tile index")
    n = 0
    for part in s.split("/"):
        n = n * 1000 + int(part.lstrip("x"))
    if encode_index(n) != s:           # rejects redundant x000 groups in front
        raise TileError("non-canonical tile index")
    return n


def _suffix(width: int) -> str:
    if not 1 <= width <= TILE_WIDTH:
        raise TileError("tile width out of range")
    return "" if width == TILE_WIDTH else f".p/{width}"


def tile_path(level: int, index: int, width: int = TILE_WIDTH) -> str:
    if not 0 <= level <= MAX_LEVEL:
        raise TileError("tile level out of range")
    return f"tile/{level}/{encode_index(index)}{_suffix(width)}"


def entries_path(index: int, width: int = TILE_WIDTH) -> str:
    return f"tile/entries/{encode_index(index)}{_suffix(width)}"


def tile_width_at(size: int, level: int, index: int) -> int:
    """Width of tile (level, index) in a tree of `size` leaves; 0 = not served."""
    have = size >> (TILE_HEIGHT * level)
    return max(0, min(TILE_WIDTH, have - index * TILE_WIDTH))


def tiles_for_size(size: int) -> List[Tuple[int, int, int]]:
    """Every (level, index, width) the log serves for a tree of this size."""
    out: List[Tuple[int, int, int]] = []
    level = 0
    while size >> (TILE_HEIGHT * level):
        have = size >> (TILE_HEIGHT * level)
        for idx in range((have + TILE_WIDTH - 1) // TILE_WIDTH):
            out.append((level, idx, tile_width_at(size, level, idx)))
        level += 1
    return out


def encode_bundle(entries: Sequence[bytes]) -> bytes:
    out = bytearray()
    for e in entries:
        if len(e) > MAX_ENTRY:
            raise TileError("entry longer than 65535 bytes")
        out += len(e).to_bytes(2, "big") + e
    return bytes(out)


def decode_bundle(data: bytes) -> List[bytes]:
    out: List[bytes] = []
    i = 0
    while i < len(data):
        if i + 2 > len(data):
            raise TileError("truncated entry length")
        n = int.from_bytes(data[i:i + 2], "big")
        i += 2
        if i + n > len(data):
            raise TileError("truncated entry")
        out.append(data[i:i + n])
        i += n
    return out


def split_hashes(data: bytes, width: int) -> List[bytes]:
    if len(data) != width * merkle.HASH_SIZE:
        raise TileError("tile is not exactly width * 32 bytes")
    return [data[i:i + 32] for i in range(0, len(data), 32)]


def _fold(hashes: Sequence[bytes]) -> bytes:
    """Root of a full binary tree whose leaves are already hashes."""
    layer = list(hashes)
    while len(layer) > 1:
        layer = [merkle.hash_children(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
_TEMP_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0))


def _read_at(dir_fd: int, name: str) -> "bytes | None":
    """A regular file in an open directory, never through a symlink; None if absent."""
    try:
        fd = os.open(name, _READ_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise TileError(f"refusing to follow a symlink at {name!r}") from None
        raise
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise TileError(f"{name!r} is not a regular file")
        return f.read()


class DirTileStore:
    """Tiles as plain files under a directory, laid out exactly as served.

    Full tiles are immutable and written once. Partial tiles are kept for every
    published size: the spec obliges the log to serve the partial tiles of any
    size it has checkpointed. Writes are atomic and durable: an exclusive temp
    file next to the target, fsync, rename, fsync of the directory.

    Nothing below the root is opened through a symlink, so whoever can write the
    served directory (but holds no key) cannot make the writer write or read
    outside it. The root itself is the operator's choice. Needs a POSIX system
    (directory file descriptors)."""

    def __init__(self, root: "str | os.PathLike[str]"):
        self.root = Path(root)

    @staticmethod
    def _parts(rel: str) -> List[str]:
        parts = rel.split("/")
        if rel.startswith("/") or any(p in ("", ".", "..") for p in parts):
            raise TileError("bad resource path")
        return parts

    def _open_dir(self, parts: Sequence[str], create: bool) -> int:
        if create:
            self.root.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            for name in parts:
                if create:
                    try:
                        os.mkdir(name, 0o755, dir_fd=fd)
                    except FileExistsError:
                        pass
                try:
                    nxt = os.open(name, _DIR_FLAGS, dir_fd=fd)
                except OSError as e:
                    if e.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise TileError(f"refusing a symlink or non-directory at {name!r} "
                                        "below the log root") from None
                    raise
                os.close(fd)
                fd = nxt
            return fd
        except BaseException:
            os.close(fd)
            raise

    def put(self, rel: str, data: bytes, *, immutable: bool = True) -> None:
        parts = self._parts(rel)
        dfd = self._open_dir(parts[:-1], create=True)
        try:
            name = parts[-1]
            if immutable:
                have = _read_at(dfd, name)
                if have is not None:
                    if have != data:
                        raise TileError(f"refusing to change immutable resource {rel}")
                    return
            tmp = f".{name}.{os.urandom(8).hex()}.tmp"
            fd = os.open(tmp, _TEMP_FLAGS, 0o644, dir_fd=dfd)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            except BaseException:
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except OSError:
                    pass
                raise
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def get(self, rel: str) -> bytes:
        parts = self._parts(rel)
        try:
            dfd = self._open_dir(parts[:-1], create=False)
        except FileNotFoundError:
            raise TileNotFound(rel) from None
        try:
            data = _read_at(dfd, parts[-1])
        finally:
            os.close(dfd)
        if data is None:
            raise TileNotFound(rel)
        return data

    __call__ = get


class TileReader:
    """Client side: node hashes, roots and proofs computed only from fetched
    tiles. This is what a monitor or verifier does.

    Give it the size and root of a checkpoint you have verified
    (`open_checkpoint`): before it answers anything, the reader checks that the
    tiles reproduce that root, and raises TileError if they do not. Every full
    tile is also checked against its hash in the tile above before any hash
    from it is used, so a forged tile cannot hide under a good parent. Without
    `root` only that second check runs, and the caller must compare `root()`
    with the checkpoint before trusting any answer."""

    def __init__(self, fetch: Fetch, size: int, root: "bytes | None" = None):
        self._fetch = fetch
        self.size = size
        self.expected_root = None if root is None else bytes(root)
        self._root_ok = root is None
        self._tiles: Dict[Tuple[int, int], List[bytes]] = {}
        self._nodes: Dict[Tuple[int, int], bytes] = {}

    def _tile(self, level: int, index: int) -> List[bytes]:
        key = (level, index)
        if key not in self._tiles:
            width = tile_width_at(self.size, level, index)
            if width == 0:
                raise TileError("tile is beyond the tree size")
            path = tile_path(level, index, width)
            try:
                data = self._fetch(path)
            except TileNotFound:
                if width == TILE_WIDTH:
                    raise
                # a partial may be pruned once the full tile exists
                data = self._fetch(tile_path(level, index))
                data = data[:width * merkle.HASH_SIZE]
            hashes = split_hashes(data, width)
            # A full tile is never read by root(): it sits under a hash in the
            # tile above, which must agree with it. (Partial tiles form the
            # right edge, which root() reads and the pinned root covers.)
            if width == TILE_WIDTH and _fold(hashes) != self._node(TILE_HEIGHT * (level + 1), index):
                raise TileError(f"tile level {level} index {index} does not hash to its parent")
            self._tiles[key] = hashes
        return self._tiles[key]

    def _node(self, level: int, index: int) -> bytes:
        if (index + 1) << level > self.size:
            raise TileError("node is not part of a complete subtree of this tree")
        key = (level, index)
        if key not in self._nodes:
            if level % TILE_HEIGHT == 0:
                tl = level // TILE_HEIGHT
                self._nodes[key] = self._tile(tl, index // TILE_WIDTH)[index % TILE_WIDTH]
            else:
                self._nodes[key] = merkle.hash_children(
                    self._node(level - 1, 2 * index), self._node(level - 1, 2 * index + 1))
        return self._nodes[key]

    def _checked(self) -> None:
        if self._root_ok:
            return
        try:
            got = merkle.tree_hash(self._node, self.size)
        except BaseException:
            self._tiles.clear()
            self._nodes.clear()
            raise
        if got != self.expected_root:
            self._tiles.clear()
            self._nodes.clear()
            raise TileError("tiles do not reproduce the checkpoint root")
        self._root_ok = True

    def node(self, level: int, index: int) -> bytes:
        self._checked()
        return self._node(level, index)

    def root(self) -> bytes:
        self._checked()
        return merkle.tree_hash(self._node, self.size)

    def inclusion_proof(self, index: int) -> List[bytes]:
        self._checked()
        return merkle.inclusion_proof(self._node, index, self.size)

    def consistency_proof(self, old_size: int) -> List[bytes]:
        self._checked()
        return merkle.consistency_proof(self._node, old_size, self.size)

    def leaf_hash(self, index: int) -> bytes:
        return self.node(0, index)

    def audit(self) -> int:
        """Check every full tile against its hash in the tile above it (and,
        with a pinned root, the right edge against that root).

        Lookups only read the tiles they need, and `root()` reads only the right
        edge, so this walks all of them. Returns the number of full tiles
        checked; raises TileError on the first disagreement."""
        self._checked()
        checked = 0
        level = 0
        while self.size >> (TILE_HEIGHT * (level + 1)):
            for idx in range((self.size >> (TILE_HEIGHT * level)) // TILE_WIDTH):
                self._tile(level, idx)
                checked += 1
            level += 1
        return checked

    def audit_bundle(self, index: int, bundle: bytes) -> int:
        """Check an entry bundle against the level-0 tile it belongs to."""
        self._checked()
        entries = decode_bundle(bundle)
        tile = self._tile(0, index)
        if len(entries) != len(tile):
            raise TileError("entry bundle and level-0 tile have different widths")
        for e, h in zip(entries, tile):
            if merkle.hash_leaf(e) != h:
                raise TileError("an entry does not hash to its level-0 tile hash")
        return len(entries)
