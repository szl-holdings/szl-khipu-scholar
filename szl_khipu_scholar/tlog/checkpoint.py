# SPDX-License-Identifier: Apache-2.0
"""Checkpoints (c2sp.org/tlog-checkpoint): a signed note whose text is

    <origin>
    <tree size, ASCII decimal>
    <base64 root hash>
    [extension lines, each non-empty]

The log signs with Ed25519 (note type 0x01, key name = origin). Timestamped
cosignatures (types 0x04 and 0x06) are out of scope for this module.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Iterable, Sequence, Tuple

from .merkle import empty_root
from .note import (NoteError, OpenedNote, Signer, Verifier, b64decode_canonical,
                   open_note, sign_note)


MAX_TREE_SIZE = 2**64 - 1   # a uint64, as Go's formats/log parses it


class CheckpointError(NoteError):
    """The checkpoint text is malformed or its signature is not acceptable."""


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes
    extensions: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.origin or "\n" in self.origin:
            raise CheckpointError("origin must be a non-empty single line")
        if self.size < 0:
            raise CheckpointError("negative tree size")
        if self.size > MAX_TREE_SIZE:
            raise CheckpointError("tree size does not fit in a uint64")
        if len(self.root) != 32:
            raise CheckpointError("root hash must be 32 bytes")
        for e in self.extensions:
            if not e or "\n" in e:
                raise CheckpointError("extension lines must be non-empty single lines")

    def text(self) -> str:
        lines = [self.origin, str(self.size), base64.b64encode(self.root).decode("ascii"),
                 *self.extensions]
        return "\n".join(lines) + "\n"

    @classmethod
    def parse(cls, text: str) -> "Checkpoint":
        if not text.endswith("\n"):
            raise CheckpointError("checkpoint text must end in a newline")
        lines = text[:-1].split("\n")
        if len(lines) < 3 or any(not line for line in lines):
            raise CheckpointError("need at least three non-empty lines")
        origin, size_s, root_s, *ext = lines
        if not (size_s.isascii() and size_s.isdigit()) or (len(size_s) > 1 and size_s[0] == "0"):
            raise CheckpointError("tree size must be a canonical ASCII decimal (no zero prefix)")
        if len(size_s) > len(str(MAX_TREE_SIZE)):      # before int(), which caps digit counts
            raise CheckpointError("tree size does not fit in a uint64")
        try:
            root = b64decode_canonical(root_s)
        except NoteError as e:
            raise CheckpointError(str(e)) from e
        if len(root) != 32:
            raise CheckpointError("root hash must decode to 32 bytes")
        return cls(origin, int(size_s), root, tuple(ext))


def sign_checkpoint(cp: Checkpoint, signers: Sequence[Signer]) -> bytes:
    return sign_note(cp.text(), signers)


def open_checkpoint(msg: bytes, known: Iterable[Verifier],
                    origin: str | None = None) -> Tuple[Checkpoint, OpenedNote]:
    """Verify a signed checkpoint. The log's own key (name == the checkpoint's
    origin line) must have signed it, on every call: a signature from any other
    known key (a witness, another log) is a cosignature and never stands in
    for the log's. When `origin` is given the checkpoint must also be for
    exactly that log; without it, the caller must check `cp.origin`."""
    known = list(known)
    opened = open_note(msg, known)
    cp = Checkpoint.parse(opened.text)
    if origin is not None and cp.origin != origin:
        raise CheckpointError("checkpoint is for a different origin")
    if not any(v.name == cp.origin for v in opened.verified):
        raise CheckpointError("checkpoint is not signed by the log's own key")
    if len(set(opened.unknown)) != len(opened.unknown):
        raise CheckpointError("more than one signature line with the same key name and id")
    if cp.size == 0 and cp.root != empty_root():
        raise CheckpointError("a size-0 checkpoint must carry the empty-tree root")
    return cp, opened
