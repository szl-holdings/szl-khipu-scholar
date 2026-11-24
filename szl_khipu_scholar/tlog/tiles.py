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

import os
import re
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


class DirTileStore:
    """Tiles as plain files under a directory, laid out exactly as served.

    Full tiles are immutable and written once. Partial tiles are kept for every
    published size: the spec obliges the log to serve the partial tiles of any
    size it has checkpointed. Writes are atomic (temp file + rename)."""

    def __init__(self, root: "str | os.PathLike[str]"):
        self.root = Path(root)

    def _p(self, rel: str) -> Path:
        if rel.startswith("/") or ".." in rel.split("/"):
            raise TileError("bad resource path")
        return self.root / rel

    def put(self, rel: str, data: bytes, *, immutable: bool = True) -> None:
        p = self._p(rel)
        if immutable and p.exists():
            if p.read_bytes() != data:
                raise TileError(f"refusing to change immutable resource {rel}")
            return
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, p)

    def get(self, rel: str) -> bytes:
        p = self._p(rel)
        try:
            return p.read_bytes()
        except FileNotFoundError:
            raise TileNotFound(rel) from None

    __call__ = get


class TileReader:
    """Client side: node hashes, roots and proofs computed only from fetched
    tiles. This is what a monitor or verifier does; it trusts nothing but the
    checkpoint it was handed (root + size)."""

    def __init__(self, fetch: Fetch, size: int):
        self._fetch = fetch
        self.size = size
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
            self._tiles[key] = split_hashes(data, width)
        return self._tiles[key]

    def node(self, level: int, index: int) -> bytes:
        if (index + 1) << level > self.size:
            raise TileError("node is not part of a complete subtree of this tree")
        key = (level, index)
        if key not in self._nodes:
            if level % TILE_HEIGHT == 0:
                tl = level // TILE_HEIGHT
                self._nodes[key] = self._tile(tl, index // TILE_WIDTH)[index % TILE_WIDTH]
            else:
                self._nodes[key] = merkle.hash_children(
                    self.node(level - 1, 2 * index), self.node(level - 1, 2 * index + 1))
        return self._nodes[key]

    def root(self) -> bytes:
        return merkle.tree_hash(self.node, self.size)

    def inclusion_proof(self, index: int) -> List[bytes]:
        return merkle.inclusion_proof(self.node, index, self.size)

    def consistency_proof(self, old_size: int) -> List[bytes]:
        return merkle.consistency_proof(self.node, old_size, self.size)

    def leaf_hash(self, index: int) -> bytes:
        return self.node(0, index)

    def audit(self) -> int:
        """Check that every tile agrees with the tile above it.

        `root()` only reads the tiles it needs, so a bad lower tile can hide
        behind a good higher one. This walks every tile of level >= 1 and
        recomputes each of its hashes from the full tile below. Returns the
        number of hashes checked; raises TileError on the first disagreement."""
        checked = 0
        level = 1
        while self.size >> (TILE_HEIGHT * level):
            have = self.size >> (TILE_HEIGHT * level)
            for idx in range((have + TILE_WIDTH - 1) // TILE_WIDTH):
                upper = self._tile(level, idx)
                for i, h in enumerate(upper):
                    below = self._tile(level - 1, idx * TILE_WIDTH + i)
                    if len(below) != TILE_WIDTH:
                        raise TileError("a hash above a partial tile")
                    got = _fold(below)
                    if got != h:
                        raise TileError(
                            f"tile level {level - 1} index {idx * TILE_WIDTH + i} "
                            f"does not hash to its parent")
                    checked += 1
            level += 1
        return checked

    def audit_bundle(self, index: int, bundle: bytes) -> int:
        """Check an entry bundle against the level-0 tile it belongs to."""
        entries = decode_bundle(bundle)
        tile = self._tile(0, index)
        if len(entries) != len(tile):
            raise TileError("entry bundle and level-0 tile have different widths")
        for e, h in zip(entries, tile):
            if merkle.hash_leaf(e) != h:
                raise TileError("an entry does not hash to its level-0 tile hash")
        return len(entries)
