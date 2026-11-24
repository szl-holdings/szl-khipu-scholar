# SPDX-License-Identifier: Apache-2.0
"""RFC 6962 hashing and proofs: published vectors, exhaustive small trees,
and refusal of malformed or tampered proofs."""
import hashlib

import pytest

from szl_khipu_scholar.tlog import merkle
from szl_khipu_scholar.tlog.merkle import ProofError

# Leaves and roots from the Certificate Transparency reference test vectors.
CT_LEAVES = [bytes.fromhex(h) for h in (
    "", "00", "10", "2021", "3031", "40414243", "5051525354555657",
    "606162636465666768696a6b6c6d6e6f")]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def build(n):
    """All node hashes for n leaves, as a NodeFn."""
    levels = [[merkle.hash_leaf(bytes([i % 251, i // 251])) for i in range(n)]]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        levels.append([merkle.hash_children(prev[i], prev[i + 1])
                       for i in range(0, len(prev) - 1, 2)])
    return lambda level, index: levels[level][index]


def test_empty_root_is_sha256_of_nothing():
    assert merkle.empty_root() == hashlib.sha256(b"").digest()
    assert merkle.tree_hash(lambda l, i: b"", 0) == hashlib.sha256(b"").digest()


def test_leaf_and_node_domain_separation():
    assert merkle.hash_leaf(b"x") == hashlib.sha256(b"\x00x").digest()
    a, b = b"a" * 32, b"b" * 32
    assert merkle.hash_children(a, b) == hashlib.sha256(b"\x01" + a + b).digest()


@pytest.mark.parametrize("n", range(1, 9))
def test_ct_reference_roots(n):
    leaves = [merkle.hash_leaf(e) for e in CT_LEAVES]
    level0 = {(0, i): h for i, h in enumerate(leaves[:n])}

    def node(level, index):
        if (level, index) in level0:
            return level0[(level, index)]
        h = merkle.hash_children(node(level - 1, 2 * index), node(level - 1, 2 * index + 1))
        level0[(level, index)] = h
        return h

    assert merkle.tree_hash(node, n).hex() == CT_ROOTS[n - 1]


def test_every_inclusion_proof_verifies_up_to_70_leaves():
    for n in range(1, 71):
        node = build(n)
        root = merkle.tree_hash(node, n)
        for i in range(n):
            proof = merkle.inclusion_proof(node, i, n)
            merkle.verify_inclusion(i, n, node(0, i), proof, root)


def test_every_consistency_proof_verifies_up_to_40_leaves():
    for n2 in range(1, 41):
        node = build(n2)
        r2 = merkle.tree_hash(node, n2)
        for n1 in range(0, n2 + 1):
            r1 = merkle.tree_hash(node, n1)
            proof = merkle.consistency_proof(node, n1, n2)
            merkle.verify_consistency(n1, n2, proof, r1, r2)


def test_inclusion_proof_rejects_wrong_index_leaf_root_and_shape():
    n = 13
    node = build(n)
    root = merkle.tree_hash(node, n)
    proof = merkle.inclusion_proof(node, 5, n)
    leaf = node(0, 5)
    merkle.verify_inclusion(5, n, leaf, proof, root)
    with pytest.raises(ProofError):
        merkle.verify_inclusion(6, n, leaf, proof, root)
    with pytest.raises(ProofError):
        merkle.verify_inclusion(5, n, node(0, 6), proof, root)
    with pytest.raises(ProofError):
        merkle.verify_inclusion(5, n, leaf, proof, b"\x00" * 32)
    with pytest.raises(ProofError):
        merkle.verify_inclusion(5, n, leaf, proof[:-1], root)
    with pytest.raises(ProofError):
        merkle.verify_inclusion(5, n, leaf, proof + [proof[0]], root)
    with pytest.raises(ProofError):
        merkle.verify_inclusion(5, n, leaf, [proof[0][:-1]] + proof[1:], root)
    with pytest.raises(ProofError):
        merkle.verify_inclusion(13, n, leaf, proof, root)   # index == size
    flipped = bytearray(proof[1]); flipped[0] ^= 1
    with pytest.raises(ProofError):
        merkle.verify_inclusion(5, n, leaf, [proof[0], bytes(flipped), *proof[2:]], root)


def test_consistency_proof_rejects_forks_and_bad_shapes():
    node = build(20)
    r = lambda n: merkle.tree_hash(node, n)
    proof = merkle.consistency_proof(node, 6, 20)
    merkle.verify_consistency(6, 20, proof, r(6), r(20))
    with pytest.raises(ProofError):
        merkle.verify_consistency(6, 20, proof, r(7), r(20))      # wrong old root
    with pytest.raises(ProofError):
        merkle.verify_consistency(6, 20, proof, r(6), r(19))      # wrong new root
    with pytest.raises(ProofError):
        merkle.verify_consistency(6, 20, proof[:-1], r(6), r(20))
    with pytest.raises(ProofError):
        merkle.verify_consistency(6, 20, proof + [proof[0]], r(6), r(20))
    with pytest.raises(ProofError):
        merkle.verify_consistency(20, 6, proof, r(20), r(6))      # shrinking
    with pytest.raises(ProofError):
        merkle.verify_consistency(5, 5, [r(5)], r(5), r(5))       # equal size, non-empty proof
    with pytest.raises(ProofError):
        merkle.verify_consistency(5, 5, [], r(5), r(6))           # equal size, different roots
    with pytest.raises(ProofError):
        merkle.verify_consistency(0, 5, [], b"\x01" * 32, r(5))   # bad empty root
    merkle.verify_consistency(0, 5, [], merkle.empty_root(), r(5))


def test_boundary_arguments():
    node = build(4)
    with pytest.raises(ValueError):
        merkle.inclusion_proof(node, 4, 4)
    with pytest.raises(ValueError):
        merkle.consistency_proof(node, 5, 4)
    assert merkle.inclusion_proof(build(1), 0, 1) == []


def test_size_zero_consistency_needs_the_empty_tree_root():
    """C2SP tlog-witness: a size-0 checkpoint has the empty-tree root. The
    equal-size shortcut must not skip that rule for size1 == size2 == 0."""
    empty, bogus = merkle.empty_root(), b"\x11" * 32
    merkle.verify_consistency(0, 0, [], empty, empty)
    with pytest.raises(ProofError, match="empty-tree hash"):
        merkle.verify_consistency(0, 0, [], bogus, bogus)
    with pytest.raises(ProofError, match="different roots"):
        merkle.verify_consistency(0, 0, [], empty, bogus)
