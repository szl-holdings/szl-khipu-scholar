# SPDX-License-Identifier: Apache-2.0
"""Tiled transparency log for signed receipts (C2SP tlog-tiles, tlog-checkpoint,
signed-note). Additive: nothing in `szl_khipu_scholar.receipts` is imported,
wrapped or changed here. The log commits to receipt bytes; it does not decide
what a receipt means or whether it is AUTHORIZED."""
from .checkpoint import Checkpoint, CheckpointError, open_checkpoint, sign_checkpoint
from .log import LogStateError, TileLog
from .merkle import (ProofError, consistency_proof, hash_children, hash_leaf,
                     inclusion_proof, verify_consistency, verify_inclusion)
from .note import NoteError, Signer, Verifier, open_note, sign_note
from .tiles import DirTileStore, TileNotFound, TileReader

__all__ = [
    "Checkpoint", "CheckpointError", "DirTileStore", "LogStateError", "NoteError", "ProofError",
    "Signer", "TileLog", "TileNotFound", "TileReader", "Verifier",
    "consistency_proof", "hash_children", "hash_leaf", "inclusion_proof",
    "open_checkpoint", "open_note", "sign_checkpoint", "sign_note",
    "verify_consistency", "verify_inclusion",
]
