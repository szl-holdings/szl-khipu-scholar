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
import szl_khipu_scholar.receipts as receipts_module  # noqa: E402

NODE = "khipu-scholar-v1"
SCHEMA = "szl.khipu-scholar.lane-keys/v1"


def _receipt(sk, rtype, node=NODE, **payload):
    doc = {"node": node, "type": rtype, "ts": 1.0, "payload": dict(payload)}
    doc["sig"] = sk.sign(json.dumps(doc, sort_keys=True).encode()).signature.hex()
    return doc


@pytest.fixture()
def feed(tmp_path, monkeypatch):
    """A fake runs repo: one self-carried `complete`, one keyless `state`, one forgery."""
    lane, stranger = SigningKey.generate(), SigningKey.generate()
    files = {
        "mesh/khipu-scholar-v1-complete.json": json.dumps(
            _receipt(lane, "complete", pubkey=lane.verify_key.encode().hex())),
        "mesh/khipu-scholar-v1-state.json": json.dumps(_receipt(lane, "state", step=10)),
        "mesh/forged-complete.json": json.dumps(
            _receipt(stranger, "complete", pubkey=stranger.verify_key.encode().hex())),
    }

    def write_all():
        for name, raw in files.items():
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(raw, encoding="utf-8")

    class _Api:
        def list_repo_files(self, repo, repo_type=None):
            return sorted(files)

    monkeypatch.setattr(app_module, "_hub",
                        lambda: (_Api(), lambda repo, name, repo_type=None: str(tmp_path / name)))

    def root(keys, path=None):
        target = path or tmp_path / "lane_keys.json"
        target.write_text(json.dumps({"schema": SCHEMA, "keys": keys}), encoding="utf-8")
        monkeypatch.setenv("KHIPU_TRUST_ROOT", str(target))
        return target

    write_all()
    return {"lane": lane, "lane_key": lane.verify_key.encode().hex(), "root": root,
            "tmp": tmp_path, "files": files, "write_all": write_all, "monkeypatch": monkeypatch}


def _get(feed):
    response = TestClient(app_module.app).get("/receipts")
    assert response.status_code == 200
    return response.json()


def _verdicts(body):
    return {r["file"]: (r["verdict"], r["signature"], r["key_state"]) for r in body["receipts"]}


def test_nothing_is_authorized_without_pins(feed):
    feed["root"]([])
    body = _get(feed)
    assert body["trust_root"] == {"state": "LOADED", "pinned_nodes": 0}
    assert _verdicts(body) == {
        "mesh/khipu-scholar-v1-complete.json": ("OBSERVED", "VALID", "UNPINNED"),
        "mesh/khipu-scholar-v1-state.json": ("OBSERVED", "UNCHECKED", "ABSENT"),
        "mesh/forged-complete.json": ("OBSERVED", "VALID", "UNPINNED"),
    }


def test_pinned_lane_is_authorized_and_the_forgery_is_refused(feed):
    feed["root"]([{"node": NODE, "pubkey": feed["lane_key"], "basis": "TEST"}])
    body = _get(feed)
    assert body["trust_root"] == {"state": "LOADED", "pinned_nodes": 1}
    assert _verdicts(body) == {
        "mesh/khipu-scholar-v1-complete.json": ("AUTHORIZED", "VALID", "PINNED"),
        "mesh/khipu-scholar-v1-state.json": ("AUTHORIZED", "VALID", "PINNED"),
        "mesh/forged-complete.json": ("OBSERVED", "UNCHECKED", "MISMATCH"),
    }


def test_unreadable_trust_root_authorizes_nothing(feed):
    feed["monkeypatch"].setenv("KHIPU_TRUST_ROOT", str(feed["tmp"] / "absent.json"))
    body = _get(feed)
    assert body["trust_root"]["state"] == "UNAVAILABLE"
    assert all(r["verdict"] == "OBSERVED" for r in body["receipts"])


def test_unreadable_trust_root_never_falls_back_to_the_packaged_one(feed):
    packaged = feed["root"]([{"node": NODE, "pubkey": feed["lane_key"], "basis": "TEST"}],
                            path=feed["tmp"] / "packaged.json")
    feed["monkeypatch"].setattr(receipts_module, "DEFAULT_TRUST_ROOT", packaged)
    feed["monkeypatch"].setenv("KHIPU_TRUST_ROOT", str(feed["tmp"] / "absent.json"))
    body = _get(feed)
    assert body["trust_root"]["state"] == "UNAVAILABLE"
    assert all(r["verdict"] == "OBSERVED" for r in body["receipts"])


def test_set_but_empty_trust_root_variable_authorizes_nothing(feed):
    feed["monkeypatch"].setenv("KHIPU_TRUST_ROOT", "")
    body = _get(feed)
    assert body["trust_root"]["state"] == "UNAVAILABLE"
    assert "empty" in body["trust_root"]["error"]


def test_a_valid_receipt_under_another_lanes_file_name_is_not_authorized(feed):
    feed["root"]([{"node": NODE, "pubkey": feed["lane_key"], "basis": "TEST"}])
    feed["files"]["mesh/khipu-scholar-4b-v1-complete.json"] = \
        feed["files"]["mesh/khipu-scholar-v1-complete.json"]
    feed["write_all"]()
    row = {r["file"]: r for r in _get(feed)["receipts"]}["mesh/khipu-scholar-4b-v1-complete.json"]
    assert row["verdict"] == "OBSERVED"
    assert row["file_matches_receipt"] is False


@pytest.mark.parametrize("raw", [
    '{"node": "x", "type": "\\ud800", "payload": {}}',
    '{"node": ' + "[" * 400 + "]" * 400 + ', "type": "boot", "payload": {}}',
    '{"node": {"toString": "x"}, "type": "boot", "payload": {}}',
    "not json",
    '{"node": "a", "node": "b", "type": "boot", "payload": {}}',
])
def test_one_malformed_file_does_not_blank_the_feed(feed, raw):
    feed["root"]([{"node": NODE, "pubkey": feed["lane_key"], "basis": "TEST"}])
    feed["files"]["mesh/z.json"] = raw
    feed["write_all"]()
    rows = {r["file"]: r for r in _get(feed)["receipts"]}
    assert rows["mesh/z.json"]["verdict"] == "OBSERVED"
    assert rows["mesh/khipu-scholar-v1-complete.json"]["verdict"] == "AUTHORIZED"
    assert rows["mesh/z.json"]["node"] is None or isinstance(rows["mesh/z.json"]["node"], str)


def test_rows_carry_the_reason(feed):
    feed["root"]([])
    rows = {r["file"]: r for r in _get(feed)["receipts"]}
    assert "not pinned" in rows["mesh/khipu-scholar-v1-complete.json"]["error"]


def test_packaged_trust_root_is_well_formed():
    from szl_khipu_scholar.receipts import load_trust_root
    assert isinstance(load_trust_root(), dict)
