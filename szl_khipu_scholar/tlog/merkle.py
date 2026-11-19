# SPDX-License-Identifier: Apache-2.0
"""RFC 6962 Merkle tree hashing, inclusion proofs and consistency proofs.

This is the hash tree that c2sp.org/tlog-tiles and c2sp.org/tlog-checkpoint
build on. Everything is SHA-256:

    leaf hash     = SHA-256(0x00 || entry)
    node hash     = SHA-256(0x01 || left || right)
    MTH({})       = SHA-256("")
    MTH(D[n])     = node(MTH(D[0:k]), MTH(D[k:n])), k = largest power of two < n

Proofs are produced for any tree size and checked with the iterative
algorithms of RFC 9162 sections 2.1.3.2 and 2.1.4.2, which accept a proof only
when it rebuilds the claimed root exactly (right length, right order).

Nothing here touches the existing receipt format. A receipt is hashed as raw
bytes by the caller; this module never parses one.
"""
from __future__ import annotations

import hashlib
from typing import Callable, List, Sequence

HASH_SIZE = 32

# A source of node hashes: (level, index) -> hash of the complete subtree that
# covers leaves [index << level, (index + 1) << level).
NodeFn = Callable[[int, int], bytes]


class ProofError(ValueError):
    """A proof is malformed or does not reproduce the expected root."""


def empty_root() -> bytes:
    return hashlib.sha256(b"").digest()


def hash_leaf(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + bytes(entry)).digest()


def hash_children(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def range_hash(node: NodeFn, lo: int, hi: int) -> bytes:
    """MTH(D[lo:hi]). Aligned power-of-two ranges come straight from `node`."""
    n = hi - lo
    if n < 1:
        raise ValueError("empty range")
    if n & (n - 1) == 0 and lo % n == 0:
        level = n.bit_length() - 1
        return node(level, lo >> level)
    k = _split(n)
    return hash_children(range_hash(node, lo, lo + k), range_hash(node, lo + k, hi))


def tree_hash(node: NodeFn, size: int) -> bytes:
    """MTH(D[size]); the empty tree hashes to SHA-256 of the empty string."""
    if size < 0:
        raise ValueError("negative tree size")
    return empty_root() if size == 0 else range_hash(node, 0, size)


def inclusion_proof(node: NodeFn, index: int, size: int) -> List[bytes]:
    """RFC 6962 audit path PATH(index, D[size]), ordered leaf -> root."""
    if not 0 <= index < size:
        raise ValueError("index out of range")

    def path(m: int, lo: int, hi: int) -> List[bytes]:
        n = hi - lo
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return path(m, lo, lo + k) + [range_hash(node, lo + k, hi)]
        return path(m - k, lo + k, hi) + [range_hash(node, lo, lo + k)]

    return path(index, 0, size)


def consistency_proof(node: NodeFn, size1: int, size2: int) -> List[bytes]:
    """RFC 6962 PROOF(size1, D[size2]) from the tree of size1 to size2."""
    if not 0 <= size1 <= size2:
        raise ValueError("need 0 <= size1 <= size2")
    if size1 == 0 or size1 == size2:
        return []

    def sub(m: int, lo: int, hi: int, complete: bool) -> List[bytes]:
        n = hi - lo
        if m == n:
            return [] if complete else [range_hash(node, lo, hi)]
        k = _split(n)
        if m <= k:
            return sub(m, lo, lo + k, complete) + [range_hash(node, lo + k, hi)]
        return sub(m - k, lo + k, hi, False) + [range_hash(node, lo, lo + k)]

    return sub(size1, 0, size2, True)


def _check_hashes(proof: Sequence[bytes]) -> None:
    for h in proof:
        if not isinstance(h, (bytes, bytearray)) or len(h) != HASH_SIZE:
            raise ProofError("proof element is not a 32-byte hash")


def root_from_inclusion_proof(index: int, size: int, leaf_hash: bytes,
                              proof: Sequence[bytes]) -> bytes:
    """Rebuild the root implied by an inclusion proof (RFC 9162 2.1.3.2)."""
    if size < 1 or not 0 <= index < size:
        raise ProofError("index out of range for tree size")
    if len(leaf_hash) != HASH_SIZE:
        raise ProofError("leaf hash is not 32 bytes")
    _check_hashes(proof)
    fn, sn, r = index, size - 1, leaf_hash
    for p in proof:
        if sn == 0:
            raise ProofError("proof is longer than the path")
        if fn & 1 or fn == sn:
            r = hash_children(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hash_children(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ProofError("proof is shorter than the path")
    return r


def verify_inclusion(index: int, size: int, leaf_hash: bytes,
                     proof: Sequence[bytes], root: bytes) -> None:
    """Raise ProofError unless `proof` puts `leaf_hash` at `index` under `root`."""
    if root_from_inclusion_proof(index, size, leaf_hash, proof) != bytes(root):
        raise ProofError("inclusion proof does not reproduce the root")


def verify_consistency(size1: int, size2: int, proof: Sequence[bytes],
                       root1: bytes, root2: bytes) -> None:
    """Raise ProofError unless the tree of size2 extends the tree of size1
    (RFC 9162 2.1.4.2)."""
    if size1 < 0 or size2 < size1:
        raise ProofError("need 0 <= size1 <= size2")
    _check_hashes(proof)
    if size1 == size2:
        if proof:
            raise ProofError("equal sizes take an empty proof")
        if bytes(root1) != bytes(root2):
            raise ProofError("same size, different roots")
        return
    if size1 == 0:
        if proof:
            raise ProofError("an empty tree takes an empty proof")
        if bytes(root1) != empty_root():
            raise ProofError("size 0 root is not the empty-tree hash")
        return
    path = list(proof)
    if size1 & (size1 - 1) == 0:       # size1 is a power of two: root1 is the seed
        path = [bytes(root1)] + path
    if not path:
        raise ProofError("proof is empty")
    fn, sn = size1 - 1, size2 - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            raise ProofError("proof is longer than the path")
        if fn & 1 or fn == sn:
            fr = hash_children(c, fr)
            sr = hash_children(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = hash_children(sr, c)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ProofError("proof is shorter than the path")
    if fr != bytes(root1):
        raise ProofError("consistency proof does not reproduce the old root")
    if sr != bytes(root2):
        raise ProofError("consistency proof does not reproduce the new root")
