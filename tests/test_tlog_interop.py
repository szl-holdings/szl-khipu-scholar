# SPDX-License-Identifier: Apache-2.0
"""Interop: the Python tiled log against independent Go implementations.

Builds a log in a temp directory with throwaway keys, then runs the Go harness
in tests/interop/go, which checks it with golang.org/x/mod/sumdb/{note,tlog},
github.com/transparency-dev/{merkle,formats,tessera/client}. Go also signs a
checkpoint with its own throwaway key, which Python must accept.

Skipped when `go` is not installed. Needs the Go modules (network on first run,
or a populated module cache); set TLOG_REQUIRE_GO=1 to turn a skip into a failure.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("nacl.signing")

from szl_khipu_scholar.tlog import merkle  # noqa: E402
from szl_khipu_scholar.tlog.checkpoint import open_checkpoint  # noqa: E402
from szl_khipu_scholar.tlog.log import TileLog  # noqa: E402
from szl_khipu_scholar.tlog.note import Signer, Verifier  # noqa: E402
from szl_khipu_scholar.tlog.tiles import DirTileStore, TileReader  # noqa: E402

GO_DIR = Path(__file__).parent / "interop" / "go"
ORIGIN = "example.com/receipts-interop"
SIZES = [1, 2, 3, 7, 8, 255, 256, 257, 300, 513, 1024, 65536, 65793]
GO_TESTS = [
    "TestSumdbNoteOpensPythonCheckpoints",
    "TestSumdbTlogReadsPythonTiles",
    "TestTransparencyDevMerkleVerifiesPythonProofs",
    "TestEntryBundlesHashToLevel0Tiles",
    "TestTesseraClientFileFetcher",
    "TestTesseraClientHTTPFetcher",
    "TestGoSignedCheckpointForPython",
]


def entry(i):
    return b'{"n":%d,"note":"khipu receipt bytes are opaque"}' % i


def sample_indexes(n):
    picks = {0, n - 1, n // 2, 1, 254, 255, 256, 257, 511, 512, 65535, 65536}
    return sorted(i for i in picks if 0 <= i < n)


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("tlog-interop")
    logdir, out = root / "log", root / "out"
    out.mkdir()
    signer = Signer.generate(ORIGIN)
    log = TileLog(DirTileStore(logdir), ORIGIN, signer)
    checkpoints, roots = {}, {}
    for n in SIZES:
        while log.size < n:
            log.append(entry(log.size))
        msg = log.publish()
        checkpoints[str(n)] = msg.decode("utf-8")
        roots[str(n)] = log.root().hex()
    store = DirTileStore(logdir)
    inclusion = {}
    consistency = []
    for new in SIZES:
        reader = TileReader(store, new)
        inclusion[str(new)] = [[i, [h.hex() for h in reader.inclusion_proof(i)]]
                               for i in sample_indexes(new)]
        for old in SIZES:
            if old < new:
                consistency.append({"old": old, "new": new,
                                    "proof": [h.hex() for h in reader.consistency_proof(old)]})
    fixture = {"origin": ORIGIN, "vkey": signer.verifier.vkey(), "log_dir": str(logdir),
               "sizes": SIZES, "checkpoints": checkpoints, "roots": roots,
               "inclusion": inclusion, "consistency": consistency, "out": str(out)}
    path = root / "fixture.json"
    path.write_text(json.dumps(fixture))
    return {"fixture": fixture, "path": path, "out": out, "signer": signer}


@pytest.fixture(scope="module")
def go_run(built):
    if shutil.which("go") is None:
        if os.environ.get("TLOG_REQUIRE_GO"):
            pytest.fail("go is required (TLOG_REQUIRE_GO is set)")
        pytest.skip("go is not installed")
    env = dict(os.environ, TLOG_FIXTURE=str(built["path"]))
    proc = subprocess.run(["go", "test", "-count=1", "-v", "./..."], cwd=GO_DIR, env=env,
                          capture_output=True, text=True, timeout=900)
    (built["out"] / "go_test.log").write_text(proc.stdout + proc.stderr)
    return proc


def test_python_fixture_is_self_consistent(built):
    fx = built["fixture"]
    v = Verifier.from_vkey(fx["vkey"])
    last = fx["sizes"][-1]
    for n in fx["sizes"]:
        cp, _ = open_checkpoint(fx["checkpoints"][str(n)].encode(), [v], origin=ORIGIN)
        assert cp.size == n and cp.root.hex() == fx["roots"][str(n)]
    reader = TileReader(DirTileStore(fx["log_dir"]), last)
    assert reader.root().hex() == fx["roots"][str(last)]
    assert reader.audit() > 0
    for row in fx["inclusion"][str(last)]:
        i, proof = row
        merkle.verify_inclusion(i, last, merkle.hash_leaf(entry(i)),
                                [bytes.fromhex(h) for h in proof], bytes.fromhex(fx["roots"][str(last)]))


def test_go_harness_passes(go_run):
    out = go_run.stdout + go_run.stderr
    assert go_run.returncode == 0, out[-4000:]
    for name in GO_TESTS:
        assert f"--- PASS: {name}" in out, f"{name} did not pass\n{out[-4000:]}"
    assert "--- SKIP" not in out and "--- FAIL" not in out


def test_python_accepts_checkpoint_signed_by_go(built, go_run):
    assert go_run.returncode == 0
    out = built["out"]
    vkey = (out / "go_vkey.txt").read_text().strip()
    msg = (out / "go_checkpoint.txt").read_bytes()
    v = Verifier.from_vkey(vkey)
    cp, opened = open_checkpoint(msg, [v], origin="go.example/receipts-log")
    fx = built["fixture"]
    assert cp.size == fx["sizes"][-1] and cp.root.hex() == fx["roots"][str(cp.size)]
    assert [x.name for x in opened.verified] == ["go.example/receipts-log"]
    # the Go signature is not accepted under the Python log's key
    with pytest.raises(Exception):
        open_checkpoint(msg, [built["signer"].verifier])
