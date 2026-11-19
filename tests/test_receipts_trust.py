#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# (c) 2026 Lutar, Stephen P. - SZL Holdings - ORCID 0009-0001-0110-4173
"""Trust-anchor contract for mesh receipt verification.

A signature that verifies against a key carried inside the same receipt shows
that the receipt is self-consistent. It does not show who signed it. These
tests pin the difference: AUTHORIZED requires a key the caller pinned.
"""
import json

import pytest

nacl_signing = pytest.importorskip("nacl.signing")
SigningKey = nacl_signing.SigningKey

from szl_khipu_scholar.receipts import (  # noqa: E402
    TrustRootError,
    load_trust_root,
    verify_receipt_dict,
    verify_receipt_file,
)

NODE = "khipu-scholar-v1"


def _hex(sk):
    return sk.verify_key.encode().hex()


def _sign(doc, sk):
    body = dict(doc)
    body.pop("sig", None)
    signed = dict(doc)
    signed["sig"] = sk.sign(json.dumps(body, sort_keys=True).encode()).signature.hex()
    return signed


def _receipt(sk, *, node=NODE, rtype="complete", embed=True, **payload):
    body = dict(payload)
    if embed:
        body["pubkey"] = _hex(sk)
    return _sign({"node": node, "type": rtype, "ts": "2026-11-19T00:00:00Z", "payload": body}, sk)


@pytest.fixture()
def lane():
    return SigningKey.generate()


@pytest.fixture()
def stranger():
    return SigningKey.generate()


# --- the defect -------------------------------------------------------------

def test_self_signed_receipt_is_not_authorized(stranger):
    """A key nobody pinned cannot authorize the receipt that carries it."""
    v = verify_receipt_dict(_receipt(stranger, final_loss=0.0001))
    assert v["ok"] is False
    assert v["verdict"] == "OBSERVED"
    assert v["signature"] == "VALID"
    assert v["key_state"] == "UNPINNED"


def test_embedded_key_never_overrides_a_pinned_key(lane, stranger):
    """With a key pinned for the node, a receipt carrying another key is refused."""
    v = verify_receipt_dict(_receipt(stranger), {NODE: _hex(lane)})
    assert v["ok"] is False
    assert v["verdict"] == "OBSERVED"
    assert v["key_state"] == "MISMATCH"


def test_stranger_signature_without_embedded_key_fails_under_the_pin(lane, stranger):
    v = verify_receipt_dict(_receipt(stranger, embed=False), {NODE: _hex(lane)})
    assert v["ok"] is False
    assert v["signature"] == "INVALID"
    assert v["key_state"] == "PINNED"


# --- the authorized path ----------------------------------------------------

def test_pinned_key_authorizes(lane):
    v = verify_receipt_dict(_receipt(lane), {NODE: _hex(lane)})
    assert (v["ok"], v["verdict"], v["signature"], v["key_state"]) == (True, "AUTHORIZED", "VALID", "PINNED")
    assert v["pubkey"] == _hex(lane)


def test_pinned_key_authorizes_a_receipt_that_carries_no_key(lane):
    v = verify_receipt_dict(_receipt(lane, rtype="state", embed=False, step=10), {NODE: _hex(lane)})
    assert v["ok"] is True
    assert v["verdict"] == "AUTHORIZED"


def test_a_node_may_have_several_pinned_keys(lane):
    """A lane that restarts publishes a new boot key; each one is pinned separately."""
    second = SigningKey.generate()
    pins = {NODE: [_hex(lane), _hex(second)]}
    assert verify_receipt_dict(_receipt(lane), pins)["verdict"] == "AUTHORIZED"
    assert verify_receipt_dict(_receipt(second), pins)["verdict"] == "AUTHORIZED"


def test_a_pin_for_one_node_does_not_authorize_another(lane):
    v = verify_receipt_dict(_receipt(lane, node="some-other-lane"), {NODE: _hex(lane)})
    assert v["ok"] is False
    assert v["key_state"] == "UNPINNED"


# --- integrity and malformed input stay fail-closed --------------------------

def test_tampered_body_is_refused_even_with_the_right_pin(lane):
    doc = _receipt(lane, final_loss=0.0085)
    doc["payload"] = dict(doc["payload"], final_loss=0.0001)
    v = verify_receipt_dict(doc, {NODE: _hex(lane)})
    assert v["ok"] is False
    assert v["signature"] == "INVALID"


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("sig"),
    lambda d: d.__setitem__("sig", ""),
    lambda d: d.__setitem__("sig", "zz"),
    lambda d: d.__setitem__("sig", 7),
    lambda d: d.__setitem__("payload", None),
    lambda d: d.__setitem__("payload", "not-a-dict"),
    lambda d: d.__setitem__("node", None),
])
def test_malformed_receipts_are_observed_not_errors(lane, mutate):
    doc = _receipt(lane)
    mutate(doc)
    v = verify_receipt_dict(doc, {NODE: _hex(lane)})
    assert v["ok"] is False
    assert v["verdict"] == "OBSERVED"


@pytest.mark.parametrize("not_a_receipt", [None, [], "x", 3])
def test_non_dict_input_is_observed(not_a_receipt):
    v = verify_receipt_dict(not_a_receipt)
    assert v["ok"] is False
    assert v["verdict"] == "OBSERVED"


def test_no_key_anywhere(lane):
    v = verify_receipt_dict(_receipt(lane, embed=False))
    assert v["ok"] is False
    assert v["signature"] == "UNCHECKED"
    assert v["key_state"] == "ABSENT"


def test_malformed_pin_is_refused_not_ignored(lane):
    """A pin that cannot be a key must not silently fall back to the embedded key."""
    v = verify_receipt_dict(_receipt(lane), {NODE: "not-hex"})
    assert v["ok"] is False
    assert v["key_state"] == "MISMATCH"


# --- trust root file ----------------------------------------------------------

def _root(tmp_path, keys, schema="szl.khipu-scholar.lane-keys/v1"):
    p = tmp_path / "lane_keys.json"
    p.write_text(json.dumps({"schema": schema, "keys": keys}), encoding="utf-8")
    return p


def test_trust_root_round_trip(tmp_path, lane):
    pins = load_trust_root(_root(tmp_path, [{"node": NODE, "pubkey": _hex(lane), "basis": "TEST"}]))
    assert pins == {NODE: [_hex(lane)]}
    receipt = tmp_path / "r.json"
    receipt.write_text(json.dumps(_receipt(lane)), encoding="utf-8")
    assert verify_receipt_file(receipt, pins)["verdict"] == "AUTHORIZED"
    assert verify_receipt_file(receipt)["verdict"] == "OBSERVED"


@pytest.mark.parametrize("keys", [
    [{"node": NODE, "pubkey": "abc", "basis": "TEST"}],
    [{"node": NODE, "pubkey": "zz" * 32, "basis": "TEST"}],
    [{"node": "", "pubkey": "00" * 32, "basis": "TEST"}],
    [{"pubkey": "00" * 32, "basis": "TEST"}],
    [{"node": NODE, "pubkey": "00" * 32}],
    "not-a-list",
])
def test_trust_root_rejects_malformed_entries(tmp_path, keys):
    with pytest.raises(TrustRootError):
        load_trust_root(_root(tmp_path, keys))


def test_trust_root_rejects_unknown_schema(tmp_path, lane):
    with pytest.raises(TrustRootError):
        load_trust_root(_root(tmp_path, [{"node": NODE, "pubkey": _hex(lane), "basis": "TEST"}], schema="v0"))


def test_trust_root_rejects_duplicate_json_keys(tmp_path, lane):
    p = tmp_path / "lane_keys.json"
    p.write_text('{"schema": "szl.khipu-scholar.lane-keys/v1", "keys": [], "keys": []}', encoding="utf-8")
    with pytest.raises(TrustRootError):
        load_trust_root(p)


def test_missing_trust_root_is_an_error_not_an_empty_root(tmp_path):
    with pytest.raises(TrustRootError):
        load_trust_root(tmp_path / "absent.json")


def test_unreadable_receipt_file_is_observed(tmp_path):
    v = verify_receipt_file(tmp_path / "absent.json")
    assert v["ok"] is False
    assert v["verdict"] == "OBSERVED"
