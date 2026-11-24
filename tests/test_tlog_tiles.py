# SPDX-License-Identifier: Apache-2.0
"""Tile layout, entry bundles, the log writer and the tile-only reader
(c2sp.org/tlog-tiles). Keys are throwaway and generated per test."""
import hashlib

import pytest

pytest.importorskip("nacl.signing")

from szl_khipu_scholar.tlog import merkle, tiles  # noqa: E402
from szl_khipu_scholar.tlog.checkpoint import open_checkpoint  # noqa: E402
from szl_khipu_scholar.tlog.log import TileLog  # noqa: E402
from szl_khipu_scholar.tlog.note import Signer  # noqa: E402
from szl_khipu_scholar.tlog.tiles import (DirTileStore, TileError, TileNotFound,  # noqa: E402
                                          TileReader)

ORIGIN = "example.com/receipts"


def entry(i):
    return b'{"n":%d,"note":"khipu receipt bytes are opaque"}' % i


@pytest.fixture()
def signer():
    return Signer.generate(ORIGIN)


# --- paths (examples straight from the spec) ---------------------------------

def test_index_encoding_matches_spec():
    assert tiles.encode_index(1234067) == "x001/x234/067"
    assert tiles.encode_index(0) == "000" and tiles.encode_index(999) == "999"
    assert tiles.encode_index(1000) == "x001/000"
    for n in (0, 1, 255, 999, 1000, 65535, 1234067, 10**9):
        assert tiles.decode_index(tiles.encode_index(n)) == n


@pytest.mark.parametrize("bad", ["", "1", "0001", "x001", "x000/001", "001/002", "x001/x234/67", "-01"])
def test_non_canonical_indexes_rejected(bad):
    with pytest.raises(TileError):
        tiles.decode_index(bad)


def test_tile_and_entry_paths():
    assert tiles.tile_path(0, 0) == "tile/0/000"
    assert tiles.tile_path(2, 1234067, 17) == "tile/2/x001/x234/067.p/17"
    assert tiles.tile_path(1, 5, 256) == "tile/1/005"
    assert tiles.entries_path(273, 112) == "tile/entries/273.p/112"
    for bad in ((64, 0, 256), (0, 0, 0), (0, 0, 257)):
        with pytest.raises(TileError):
            tiles.tile_path(*bad)


def test_spec_example_tree_of_size_70000():
    got = tiles.tiles_for_size(70000)
    by_level = {}
    for level, idx, width in got:
        by_level.setdefault(level, []).append((idx, width))
    assert len(by_level[0]) == 274 and by_level[0][-1] == (273, 112)
    assert all(w == 256 for _, w in by_level[0][:-1])           # 273 full + 1 partial of 112
    assert by_level[1] == [(0, 256), (1, 17)]                    # one full, one partial of 17
    assert by_level[2] == [(0, 1)]                               # partial of width 1
    assert 3 not in by_level


def test_tree_of_size_256_has_full_tile_and_partial_level_one():
    assert tiles.tiles_for_size(256) == [(0, 0, 256), (1, 0, 1)]
    assert tiles.tiles_for_size(255) == [(0, 0, 255)]
    assert tiles.tiles_for_size(0) == []


# --- entry bundles -------------------------------------------------------------

def test_bundle_roundtrip_and_limits():
    es = [b"", b"a", b"b" * 65535, entry(3)]
    assert tiles.decode_bundle(tiles.encode_bundle(es)) == es
    assert tiles.encode_bundle([b"xy"]) == b"\x00\x02xy"
    with pytest.raises(TileError):
        tiles.encode_bundle([b"x" * 65536])
    for bad in (b"\x00", b"\x00\x05abc"):
        with pytest.raises(TileError):
            tiles.decode_bundle(bad)


# --- writer + reader --------------------------------------------------------------

def make_log(tmp_path, signer, n):
    log = TileLog(DirTileStore(tmp_path), ORIGIN, signer)
    for i in range(n):
        log.append(entry(i))
    return log


def test_origin_must_match_signing_key(tmp_path, signer):
    with pytest.raises(ValueError):
        TileLog(DirTileStore(tmp_path), "other.example/log", signer)


@pytest.mark.parametrize("n", [1, 2, 3, 255, 256, 257, 511, 512, 513, 1000])
def test_reader_recomputes_the_published_root_from_tiles_only(tmp_path, signer, n):
    log = make_log(tmp_path, signer, n)
    msg = log.publish()
    cp, _ = open_checkpoint(msg, [signer.verifier], origin=ORIGIN)
    assert cp.size == n
    reader = TileReader(DirTileStore(tmp_path), n)
    assert reader.root() == cp.root == log.root()
    # leaf hashes in level-0 tiles are exactly the RFC 6962 hashes of the entries
    assert reader.leaf_hash(n - 1) == merkle.hash_leaf(entry(n - 1))


def test_tile_files_have_spec_sizes(tmp_path, signer):
    n = 70000 if False else 600       # 2 full + 1 partial(88) level-0 tiles, level-1 partial(2)
    make_log(tmp_path, signer, n).publish()
    sizes = {p.relative_to(tmp_path).as_posix(): p.stat().st_size
             for p in tmp_path.rglob("*") if p.is_file()}
    assert sizes["tile/0/000"] == 8192 and sizes["tile/0/001"] == 8192
    assert sizes["tile/0/002.p/88"] == 88 * 32
    assert sizes["tile/1/000.p/2"] == 64
    assert "tile/1/000" not in sizes and "tile/0/002" not in sizes
    assert set(sizes) >= {"checkpoint", "tile/entries/000", "tile/entries/002.p/88"}
    bundle = (tmp_path / "tile/entries/002.p/88").read_bytes()
    assert tiles.decode_bundle(bundle) == [entry(i) for i in range(512, 600)]


def test_inclusion_and_consistency_across_checkpoints(tmp_path, signer):
    log = TileLog(DirTileStore(tmp_path), ORIGIN, signer)
    published = {}
    for n in (1, 5, 256, 300, 700):
        while log.size < n:
            log.append(entry(log.size))
        published[n] = open_checkpoint(log.publish(), [signer.verifier], origin=ORIGIN)[0]
    latest = published[700]
    reader = TileReader(DirTileStore(tmp_path), latest.size)
    for i in (0, 1, 255, 256, 511, 512, 699):
        proof = reader.inclusion_proof(i)
        merkle.verify_inclusion(i, latest.size, merkle.hash_leaf(entry(i)), proof, latest.root)
    for old, cp in published.items():
        proof = reader.consistency_proof(old)
        merkle.verify_consistency(old, latest.size, proof, cp.root, latest.root)
    # an old checkpoint is still verifiable from its own (now historical) partial tiles
    old_reader = TileReader(DirTileStore(tmp_path), 300)
    assert old_reader.root() == published[300].root


def test_audit_catches_a_bad_lower_tile_that_root_alone_misses(tmp_path, signer):
    log = make_log(tmp_path, signer, 300)
    cp, _ = open_checkpoint(log.publish(), [signer.verifier], origin=ORIGIN)
    assert TileReader(DirTileStore(tmp_path), 300).audit() == 1
    p = tmp_path / "tile/0/000"
    raw = bytearray(p.read_bytes()); raw[100] ^= 1; p.write_bytes(bytes(raw))
    r = TileReader(DirTileStore(tmp_path), 300)
    assert r.root() == cp.root          # root() reads tile 1, which is still right ...
    with pytest.raises(TileError, match="does not hash to its parent"):
        r.audit()                       # ... the audit does not let it hide


def test_corrupt_top_tile_changes_the_root(tmp_path, signer):
    log = make_log(tmp_path, signer, 300)
    cp, _ = open_checkpoint(log.publish(), [signer.verifier], origin=ORIGIN)
    p = tmp_path / "tile/0/001.p/44"
    raw = bytearray(p.read_bytes()); raw[0] ^= 1; p.write_bytes(bytes(raw))
    assert TileReader(DirTileStore(tmp_path), 300).root() != cp.root


def test_audit_bundle_matches_tile_and_detects_edits(tmp_path, signer):
    log = make_log(tmp_path, signer, 300)
    log.publish()
    r = TileReader(DirTileStore(tmp_path), 300)
    good = (tmp_path / "tile/entries/000").read_bytes()
    assert r.audit_bundle(0, good) == 256
    with pytest.raises(TileError):
        r.audit_bundle(0, good.replace(b'"n":7,', b'"n":8,', 1))
    with pytest.raises(TileError):
        r.audit_bundle(0, good[: len(good) // 2])


def test_reader_missing_and_oversized_requests(tmp_path, signer):
    make_log(tmp_path, signer, 10).publish()
    r = TileReader(DirTileStore(tmp_path), 10)
    with pytest.raises(TileError):
        r.node(0, 10)
    with pytest.raises(TileError):
        r.node(4, 0)      # level-4 subtree would need 16 leaves
    with pytest.raises(TileNotFound):
        TileReader(DirTileStore(tmp_path), 11).root()


def test_reader_falls_back_to_full_tile_when_partial_was_pruned(tmp_path, signer):
    log = make_log(tmp_path, signer, 300)
    log.publish()
    (tmp_path / "tile/0/000").exists()
    log2 = make_log(tmp_path / "b", signer, 256)
    log2.publish()
    # ask for tree size 100 while only the full tile 0 exists (partial .p/100 never written)
    r = TileReader(DirTileStore(tmp_path / "b"), 100)
    assert r.root() == merkle.tree_hash(lambda l, i: log2._levels[l][i], 100)


def test_immutable_resources_cannot_be_rewritten(tmp_path):
    s = DirTileStore(tmp_path)
    s.put("tile/0/000", b"a" * 32)
    s.put("tile/0/000", b"a" * 32)             # idempotent
    with pytest.raises(TileError):
        s.put("tile/0/000", b"b" * 32)
    s.put("checkpoint", b"1", immutable=False)
    s.put("checkpoint", b"2", immutable=False)
    for bad in ("../x", "/etc/passwd", "tile/../../x"):
        with pytest.raises(TileError):
            s.put(bad, b"x")


def test_log_commits_to_raw_bytes_and_never_parses_entries(tmp_path, signer):
    log = TileLog(DirTileStore(tmp_path), ORIGIN, signer)
    odd = [b"", b"\xff\xfe not json", b'{"b":1,"a":2}  ', b'{"a":1,"a":2}']
    for e in odd:
        log.append(e)
    for i, e in enumerate(odd):
        assert log._leaves[i] == hashlib.sha256(b"\x00" + e).digest()
    with pytest.raises(ValueError):
        log.append(b"x" * 65536)


def test_tlog_package_does_not_touch_receipt_canonicalization():
    """The tlog package must neither import the receipt verifier nor serialize
    JSON: entries are opaque bytes and the canonical form stays in receipts.py."""
    import re
    from pathlib import Path
    import szl_khipu_scholar.tlog as pkg
    for p in Path(pkg.__file__).parent.glob("*.py"):
        src = p.read_text()
        assert not re.search(r"^\s*(from|import)\s+.*\breceipts\b", src, re.M), p.name
        assert not re.search(r"^\s*import\s+json|from\s+json\s", src, re.M), p.name
        assert "sort_keys" not in src, p.name


# --- the store never leaves its directory (someone may write it without the key) ---

def _outside(tmp_path):
    logdir, outside = tmp_path / "log", tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.conf"
    victim.write_bytes(b"important=1\n")
    return logdir, outside, victim


def test_store_does_not_write_through_planted_symlinks(tmp_path):
    import os
    logdir, outside, victim = _outside(tmp_path)
    s = DirTileStore(logdir)
    s.put("checkpoint", b"cp1", immutable=False)
    os.symlink(victim, logdir / "checkpoint.tmp")         # the old fixed temp name
    s.put("checkpoint", b"cp2", immutable=False)
    assert victim.read_bytes() == b"important=1\n"
    assert not (logdir / "checkpoint").is_symlink() and (logdir / "checkpoint").read_bytes() == b"cp2"
    os.unlink(logdir / "checkpoint")
    os.symlink(victim, logdir / "checkpoint")             # the target itself
    s.put("checkpoint", b"cp3", immutable=False)          # replaces the link, not its target
    assert victim.read_bytes() == b"important=1\n"
    assert not (logdir / "checkpoint").is_symlink() and (logdir / "checkpoint").read_bytes() == b"cp3"


def test_store_refuses_symlinks_below_its_root(tmp_path):
    import os
    logdir, outside, victim = _outside(tmp_path)
    s = DirTileStore(logdir)
    s.put("tile/0/000.p/1", b"a" * 32)
    os.symlink(outside, logdir / "tile" / "entries")      # a symlinked directory
    with pytest.raises(TileError, match="symlink"):
        s.put("tile/entries/000.p/3", b"\x00\x01x")
    with pytest.raises(TileError, match="symlink"):
        s.get("tile/entries/victim.conf")
    os.symlink(victim, logdir / "tile" / "0" / "000")     # a symlinked immutable tile
    with pytest.raises(TileError, match="symlink"):
        s.put("tile/0/000", b"important=1\n")             # neither read through nor kept
    with pytest.raises(TileError, match="symlink"):
        s.get("tile/0/000")
    assert sorted(os.listdir(outside)) == ["victim.conf"]
    assert victim.read_bytes() == b"important=1\n"


def test_publish_refuses_a_symlinked_tile_directory_and_keeps_the_old_checkpoint(tmp_path, signer):
    import os
    logdir, outside, victim = _outside(tmp_path)
    log = TileLog(DirTileStore(logdir), ORIGIN, signer)
    log.append(entry(0))
    first = log.publish()
    os.rename(logdir / "tile" / "entries", tmp_path / "entries.bak")
    os.symlink(outside, logdir / "tile" / "entries")
    log.append(entry(1))
    with pytest.raises(TileError, match="symlink"):
        log.publish()
    assert sorted(os.listdir(outside)) == ["victim.conf"]
    assert (logdir / "checkpoint").read_bytes() == first


def test_store_writes_are_durable_and_leave_no_temp_files(tmp_path, monkeypatch):
    import os
    events = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        events.append("fsync")
        return real_fsync(fd)

    def replace(*a, **kw):
        events.append("replace")
        return real_replace(*a, **kw)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    s = DirTileStore(tmp_path)
    s.put("tile/0/000.p/1", b"a" * 32)
    assert events == ["fsync", "replace", "fsync"]        # file, rename, directory

    def broken(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", broken)
    with pytest.raises(OSError):
        s.put("tile/0/000.p/2", b"a" * 64)
    assert sorted(p.name for p in (tmp_path / "tile" / "0").iterdir()) == ["000.p"]
    assert sorted(p.name for p in (tmp_path / "tile" / "0" / "000.p").iterdir()) == ["1"]
