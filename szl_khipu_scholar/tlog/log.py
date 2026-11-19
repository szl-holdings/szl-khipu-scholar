# SPDX-License-Identifier: Apache-2.0
"""A small tiled transparency log writer for signed receipts.

Entries are opaque bytes: append the receipt exactly as it was signed. The log
never parses, re-serializes or canonicalizes an entry, so it cannot change
what a receipt means; it only commits to its bytes.

    log = TileLog(DirTileStore(dir), origin="example.com/receipts", signer=signer)
    idx = log.append(receipt_bytes)
    checkpoint_bytes = log.publish()      # writes tiles + `checkpoint`

Single writer. `publish` writes the tiles for the current size before the
checkpoint that refers to them, so a reader never sees a checkpoint whose tiles
are missing.
"""
from __future__ import annotations

from typing import List

from . import merkle, tiles
from .checkpoint import Checkpoint, sign_checkpoint
from .note import Signer


class TileLog:
    def __init__(self, store: tiles.DirTileStore, origin: str, signer: Signer):
        if signer.name != origin:
            raise ValueError("the log's signing key name must equal the origin")
        self.store = store
        self.origin = origin
        self.signer = signer
        self._leaves: List[bytes] = []     # leaf hashes
        self._entries: List[bytes] = []
        self._levels: List[List[bytes]] = [[]]   # complete-subtree hashes by level

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
        size = self.size
        for level, index, width in tiles.tiles_for_size(size):
            first = index * tiles.TILE_WIDTH
            hashes = [self._node(level * tiles.TILE_HEIGHT, first + i) for i in range(width)]
            self.store.put(tiles.tile_path(level, index, width), b"".join(hashes))
        for index in range((size + tiles.TILE_WIDTH - 1) // tiles.TILE_WIDTH):
            width = tiles.tile_width_at(size, 0, index)
            first = index * tiles.TILE_WIDTH
            self.store.put(tiles.entries_path(index, width),
                           tiles.encode_bundle(self._entries[first:first + width]))

    def publish(self) -> bytes:
        self.write_tiles()
        signed = sign_checkpoint(self.checkpoint(), [self.signer])
        self.store.put("checkpoint", signed, immutable=False)
        return signed
