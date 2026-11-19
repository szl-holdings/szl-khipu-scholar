#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# (c) 2026 Lutar, Stephen P. - SZL Holdings - ORCID 0009-0001-0110-4173
"""The /receipts feed reports AUTHORIZED only for lanes pinned in the trust root."""
import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
SigningKey = pytest.importorskip("nacl.signing").SigningKey

from fastapi.testclient import TestClient  # noqa: E402

import server.app as app_module  # noqa: E402

NODE = "khipu-scholar-v1"


def _receipt(sk, rtype, **payload):
    doc = {"node": NODE, "type": rtype, "ts": 1.0, "payload": dict(payload)}
    doc["sig"] = sk.sign(json.dumps(doc, sort_keys=True).encode()).signature.hex()
    return doc


@pytest.fixture()
def feed(tmp_path, monkeypatch):
    """A fake runs repo: one self-carried `complete`, one keyless `state`, one forgery."""
    lane, stranger = SigningKey.generate(), SigningKey.generate()
    files = {
        "mesh/a-complete.json": _receipt(lane, "complete", pubkey=lane.verify_key.encode().hex()),
        "mesh/b-state.json": _receipt(lane, "state", step=10),
        "mesh/c-forged.json": _receipt(stranger, "complete",
                                       pubkey=stranger.verify_key.encode().hex()),
    }
    for name, doc in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(doc), encoding="utf-8")

    class _Api:
        def list_repo_files(self, repo, repo_type=None):
            return sorted(files)

    monkeypatch.setattr(app_module, "_hub",
                        lambda: (_Api(), lambda repo, name, repo_type=None: str(tmp_path / name)))

    def root(keys):
        path = tmp_path / "lane_keys.json"
        path.write_text(json.dumps({"schema": "szl.khipu-scholar.lane-keys/v1", "keys": keys}),
                        encoding="utf-8")
        monkeypatch.setenv("KHIPU_TRUST_ROOT", str(path))

    return {"lane_key": lane.verify_key.encode().hex(), "root": root, "tmp": tmp_path,
            "setenv": monkeypatch.setenv}


def _verdicts(body):
    return {r["file"]: (r["verdict"], r["signature"], r["key_state"]) for r in body["receipts"]}


def test_nothing_is_authorized_without_pins(feed):
    feed["root"]([])
    body = TestClient(app_module.app).get("/receipts").json()
    assert body["trust_root"] == {"state": "LOADED", "pinned_nodes": 0}
    assert _verdicts(body) == {
        "mesh/a-complete.json": ("OBSERVED", "VALID", "UNPINNED"),
        "mesh/b-state.json": ("OBSERVED", "UNCHECKED", "ABSENT"),
        "mesh/c-forged.json": ("OBSERVED", "VALID", "UNPINNED"),
    }


def test_pinned_lane_is_authorized_and_the_forgery_is_refused(feed):
    feed["root"]([{"node": NODE, "pubkey": feed["lane_key"], "basis": "TEST"}])
    body = TestClient(app_module.app).get("/receipts").json()
    assert body["trust_root"] == {"state": "LOADED", "pinned_nodes": 1}
    assert _verdicts(body) == {
        "mesh/a-complete.json": ("AUTHORIZED", "VALID", "PINNED"),
        "mesh/b-state.json": ("AUTHORIZED", "VALID", "PINNED"),
        "mesh/c-forged.json": ("OBSERVED", "UNCHECKED", "MISMATCH"),
    }


def test_unreadable_trust_root_authorizes_nothing(feed):
    feed["setenv"]("KHIPU_TRUST_ROOT", str(feed["tmp"] / "absent.json"))
    body = TestClient(app_module.app).get("/receipts").json()
    assert body["trust_root"]["state"] == "UNAVAILABLE"
    assert all(r["verdict"] == "OBSERVED" for r in body["receipts"])


def test_packaged_trust_root_is_well_formed():
    from szl_khipu_scholar.receipts import load_trust_root
    assert isinstance(load_trust_root(), dict)
