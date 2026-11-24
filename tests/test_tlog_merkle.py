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


# --- crafted forgeries that only the shape and size guards stop ----------------
# Each one reproduces the claimed root(s), so a root comparison alone accepts it.

def test_inclusion_proof_borrowed_from_another_index_is_shorter_than_the_path():
    node = build(7)
    root = merkle.tree_hash(node, 7)
    proof6 = merkle.inclusion_proof(node, 6, 7)                 # [MTH(4..6), MTH(0..4)]
    merkle.verify_inclusion(6, 7, node(0, 6), proof6, root)
    with pytest.raises(ProofError, match="shorter than the path"):
        merkle.verify_inclusion(3, 7, node(0, 6), proof6, root)  # entry 6 claimed at index 3


def test_consistency_proof_for_a_smaller_tree_is_shorter_than_the_path():
    node = build(16)
    r = lambda n: merkle.tree_hash(node, n)
    proof = merkle.consistency_proof(node, 4, 8)                 # [MTH(4..8)]
    merkle.verify_consistency(4, 8, proof, r(4), r(8))
    with pytest.raises(ProofError, match="shorter than the path"):
        merkle.verify_consistency(4, 16, proof, r(4), r(8))      # an 8-leaf root claimed as size 16


def test_consistency_refuses_a_rollback_even_when_the_hashes_line_up():
    r5 = merkle.tree_hash(build(5), 5)
    c1, c2 = b"\x0c" * 32, b"\x0d" * 32
    forged = merkle.hash_children(merkle.hash_children(r5, c1), c2)
    with pytest.raises(ProofError, match=r"need 0 <= size1 <= size2"):
        merkle.verify_consistency(5, 4, [r5, c1, c2], r5, forged)


def test_consistency_from_the_empty_tree_takes_an_empty_proof():
    r3 = merkle.tree_hash(build(3), 3)
    for junk in ([b"\x07" * 32], [r3]):
        with pytest.raises(ProofError, match="an empty tree takes an empty proof"):
            merkle.verify_consistency(0, 3, junk, merkle.empty_root(), r3)


def test_proof_elements_must_be_32_byte_hashes():
    node = build(5)
    proof = merkle.inclusion_proof(node, 1, 5)
    with pytest.raises(ProofError, match="not a 32-byte hash"):
        merkle.verify_inclusion(1, 5, node(0, 1), [proof[0] + b"\x00"] + proof[1:],
                                merkle.tree_hash(node, 5))


# --- differential check against a reference written from the RFC 6962 text ------
# The reference below is recursive and follows the RFC 6962 definitions of MTH,
# PATH and SUBPROOF; the verifiers under test are the iterative RFC 9162
# algorithms. A verifier cannot tell a leaf hash from a node hash, so "valid"
# means: the proof has exactly the shape PATH/SUBPROOF has for the claimed index
# and sizes, and rebuilds the claimed root(s). Whether a root belongs to a real
# tree of that size is the signed checkpoint's job, not the proof's.

def _H(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def _k(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _ref_mth(d):                       # MTH over leaf hashes
    if not d:
        return hashlib.sha256(b"").digest()
    if len(d) == 1:
        return d[0]
    k = _k(len(d))
    return _H(_ref_mth(d[:k]), _ref_mth(d[k:]))


def _ref_path(m, d):                   # PATH(m, D[n])
    if len(d) == 1:
        return []
    k = _k(len(d))
    if m < k:
        return _ref_path(m, d[:k]) + [_ref_mth(d[k:])]
    return _ref_path(m - k, d[k:]) + [_ref_mth(d[:k])]


def _ref_subproof(m, d, b):            # SUBPROOF(m, D[n], b)
    if m == len(d):
        return [] if b else [_ref_mth(d)]
    k = _k(len(d))
    if m <= k:
        return _ref_subproof(m, d[:k], b) + [_ref_mth(d[k:])]
    return _ref_subproof(m - k, d[k:], False) + [_ref_mth(d[:k])]


def _ref_root_from_path(i, n, leaf, proof):
    """Invert PATH(i, D[n]): the root a proof implies, or None for a wrong shape."""
    if n == 1:
        return None if proof else leaf
    if not proof:
        return None
    k, rest, last = _k(n), proof[:-1], proof[-1]
    if i < k:
        sub = _ref_root_from_path(i, k, leaf, rest)
        return None if sub is None else _H(sub, last)
    sub = _ref_root_from_path(i - k, n - k, leaf, rest)
    return None if sub is None else _H(last, sub)


def _ref_roots_from_subproof(m, n, proof, b, old_root):
    """Invert SUBPROOF(m, D[n], b): the (old, new) subtree hashes, or None."""
    if m == n:
        if b:
            return None if proof else (old_root, old_root)
        return (proof[0], proof[0]) if len(proof) == 1 else None
    if not proof:
        return None
    k, rest, last = _k(n), proof[:-1], proof[-1]
    if m <= k:
        sub = _ref_roots_from_subproof(m, k, rest, b, old_root)
        return None if sub is None else (sub[0], _H(sub[1], last))
    sub = _ref_roots_from_subproof(m - k, n - k, rest, False, old_root)
    return None if sub is None else (_H(last, sub[0]), _H(last, sub[1]))


def _ok_inclusion(i, n, leaf, proof, root):
    return 0 <= i < n and _ref_root_from_path(i, n, leaf, list(proof)) == root


def _ok_consistency(m, n, proof, r1, r2):
    empty = hashlib.sha256(b"").digest()
    if not 0 <= m <= n:
        return False
    if m == 0:
        return not proof and r1 == empty and (n > 0 or r2 == empty)
    if m == n:
        return not proof and r1 == r2
    return _ref_roots_from_subproof(m, n, list(proof), True, r1) == (r1, r2)


def test_proof_generators_match_the_reference():
    leaves = [merkle.hash_leaf(b"g%d" % i) for i in range(40)]
    for n in range(1, 41):
        levels = [leaves[:n]]
        while len(levels[-1]) > 1:
            prev = levels[-1]
            levels.append([merkle.hash_children(prev[j], prev[j + 1])
                           for j in range(0, len(prev) - 1, 2)])
        node = lambda level, index: levels[level][index]
        assert merkle.tree_hash(node, n) == _ref_mth(leaves[:n])
        for i in range(n):
            assert merkle.inclusion_proof(node, i, n) == _ref_path(i, leaves[:n])
        for m in range(1, n):
            assert merkle.consistency_proof(node, m, n) == _ref_subproof(m, leaves[:n], True)


def test_verifiers_agree_with_the_reference_on_borrowed_and_mutated_proofs():
    """Honest proofs (from the reference) are claimed for other indexes and
    sizes, and truncated, extended, swapped and bit-flipped. The verdicts of
    verify_inclusion / verify_consistency must match the reference exactly."""
    n_max = 33
    leaves = [merkle.hash_leaf(b"d%d" % i) for i in range(n_max)]
    roots = [_ref_mth(leaves[:n]) for n in range(n_max + 1)]

    def variants(proof, extra):
        out = [proof, proof[:-1], proof[1:], proof + [extra], [extra] + proof, proof + proof[-1:]]
        if len(proof) > 1:
            out.append([proof[1], proof[0]] + proof[2:])
        for j in range(len(proof)):
            flipped = bytearray(proof[j])
            flipped[j % 32] ^= 1
            out.append(proof[:j] + [bytes(flipped)] + proof[j + 1:])
        return out

    bad, verdicts = [], {True: 0, False: 0}

    def check(verify, oracle, *args):
        try:
            verify(*args)
            got = True
        except ProofError:
            got = False
        want = oracle(*args)
        verdicts[want] += 1
        if got != want:
            bad.append((verify.__name__, args[0], args[1], len(args[2 + (verify is merkle.verify_inclusion)]), got))

    for n in range(1, n_max + 1):
        for i in range(n):
            leaf, proof = leaves[i], _ref_path(i, leaves[:n])
            claims = {(j, n) for j in range(-1, n + 1)}
            claims |= {(i, n2) for n2 in (n - 1, n + 1, 2 * n, n // 2)}
            for ci, cn in claims:
                for root in {roots[n], roots[cn] if 0 <= cn <= n_max else roots[n]}:
                    check(merkle.verify_inclusion, _ok_inclusion, ci, cn, leaf, proof, root)
            for p in variants(proof, roots[n]):
                check(merkle.verify_inclusion, _ok_inclusion, i, n, leaf, p, roots[n])
    for n in range(n_max + 1):
        for m in range(n + 1):
            proof = _ref_subproof(m, leaves[:n], True) if 0 < m < n else []
            r1, r2 = roots[m], roots[n]
            for cm in {m - 1, m, m + 1, 2 * m, n, 0}:
                for cn in {n - 1, n, n + 1, 2 * n, m}:
                    check(merkle.verify_consistency, _ok_consistency, cm, cn, proof, r1, r2)
            for p in variants(proof, r1) + variants(proof, r2) + [[b"\x07" * 32]]:
                check(merkle.verify_consistency, _ok_consistency, m, n, p, r1, r2)
    assert not bad, bad[:5]
    assert verdicts[True] > 1000 and verdicts[False] > 10000, verdicts
