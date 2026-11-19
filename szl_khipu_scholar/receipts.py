"""Verification for SZLHOLDINGS mesh receipts (ed25519 over sorted-key JSON).

    sig   = doc["sig"]            hex ed25519 signature
    body  = doc minus "sig"       json.dumps(body, sort_keys=True)
    key   = a key the CALLER pinned for doc["node"]

A receipt may also carry a key in payload.pubkey. Whoever writes a receipt
chooses the key it carries, so that key can show the receipt is
self-consistent and nothing more. It never authorizes the receipt, and it
never replaces a key the caller pinned.

Fail-closed: a receipt is AUTHORIZED only when its signature verifies against
a pinned key for its node. Everything else is OBSERVED, with two fields that
say why:

    signature   VALID | INVALID | MISSING | UNCHECKED
    key_state   PINNED    checked against a pinned key
                UNPINNED  only the receipt's own key was available
                MISMATCH  the receipt carries a key other than the pinned one
                ABSENT    no key at all

These receipts are plain signed JSON. They are not DSSE envelopes: there is
no payloadType and no pre-authentication encoding.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

TRUST_ROOT_SCHEMA = "szl.khipu-scholar.lane-keys/v1"
DEFAULT_TRUST_ROOT = Path(__file__).with_name("trust") / "lane_keys.json"
_KEY_HEX_LEN = 64

Pins = Mapping[str, Union[str, Iterable[str]]]


class TrustRootError(ValueError):
    """The trust root is missing or malformed. Never treated as an empty root."""


def _key_hex(value: Any) -> Optional[str]:
    if not isinstance(value, str) or len(value) != _KEY_HEX_LEN:
        return None
    try:
        bytes.fromhex(value)
    except ValueError:
        return None
    return value.lower()


def _pins_for(known_pubkeys: Optional[Pins], node: Any) -> Optional[List[Optional[str]]]:
    """Pinned keys for a node, or None when the caller pinned nothing for it.

    A malformed pin is kept as None inside the list: the node stays pinned, so
    the receipt's own key cannot stand in for a pin nobody can read.
    """
    if not known_pubkeys or not isinstance(node, str) or node not in known_pubkeys:
        return None
    raw = known_pubkeys[node]
    values = [raw] if isinstance(raw, str) else list(raw or [])
    return [_key_hex(v) for v in values] or [None]


def _signature_ok(body: Dict[str, Any], sig_hex: str, key_hex: str) -> bool:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
    try:
        VerifyKey(bytes.fromhex(key_hex)).verify(
            json.dumps(body, sort_keys=True).encode(), bytes.fromhex(sig_hex))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def verify_receipt_dict(doc: Any, known_pubkeys: Optional[Pins] = None) -> Dict[str, Any]:
    """Verify one receipt. `known_pubkeys` maps node -> pinned key (hex) or keys."""
    out: Dict[str, Any] = {"ok": False, "verdict": "OBSERVED", "node": None, "type": None,
                           "ts": None, "signature": "UNCHECKED", "key_state": "ABSENT"}
    if not isinstance(doc, dict):
        out["error"] = "receipt is not a JSON object"
        return out
    out.update(node=doc.get("node"), type=doc.get("type"), ts=doc.get("ts"))
    if importlib.util.find_spec("nacl") is None:
        out["error"] = "pynacl not installed (pip install pynacl)"
        return out

    payload = doc.get("payload")
    carried_raw = payload.get("pubkey") if isinstance(payload, dict) else None
    carried = _key_hex(carried_raw)
    pins = _pins_for(known_pubkeys, doc.get("node"))

    if pins is not None:
        usable = [p for p in pins if p]
        if carried_raw is not None and carried not in usable:
            out["key_state"] = "MISMATCH"
            out["error"] = "receipt carries a key that is not pinned for this node"
            return out
        if not usable:
            out["key_state"] = "MISMATCH"
            out["error"] = "pinned key for this node is not a 32-byte hex key"
            return out
        out["key_state"] = "PINNED"
        candidates = [carried] if carried else usable
    elif carried_raw is not None:
        out["key_state"] = "UNPINNED"
        if carried is None:
            out["signature"] = "INVALID"
            out["error"] = "carried key is not a 32-byte hex key"
            return out
        candidates = [carried]
    else:
        out["error"] = "no pinned key for this node and no key in the receipt"
        return out

    sig_hex = doc.get("sig")
    if not isinstance(sig_hex, str) or not sig_hex:
        out["signature"] = "MISSING"
        out["error"] = "missing sig"
        return out
    body = dict(doc)
    body.pop("sig", None)
    try:
        matched = next((k for k in candidates if _signature_ok(body, sig_hex, k)), None)
    except Exception as e:  # unserializable body and the like: never raise to the caller
        out["signature"] = "INVALID"
        out["error"] = repr(e)[:200]
        return out
    if matched is None:
        out["signature"] = "INVALID"
        out["error"] = "signature does not verify"
        return out

    out["signature"] = "VALID"
    out["pubkey"] = matched
    if out["key_state"] == "PINNED":
        out["ok"] = True
        out["verdict"] = "AUTHORIZED"
    else:
        out["error"] = "self-consistent only: the signing key is not pinned for this node"
    return out


def verify_receipt_file(path: Union[str, Path],
                        known_pubkeys: Optional[Pins] = None) -> Dict[str, Any]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        return {"ok": False, "verdict": "OBSERVED", "node": None, "type": None, "ts": None,
                "signature": "UNCHECKED", "key_state": "ABSENT", "error": repr(e)[:200]}
    return verify_receipt_dict(doc, known_pubkeys)


def _no_duplicate_keys(pairs):
    seen: Dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise TrustRootError(f"duplicate key in trust root: {key!r}")
        seen[key] = value
    return seen


def load_trust_root(path: Union[str, Path] = DEFAULT_TRUST_ROOT) -> Dict[str, List[str]]:
    """Read a lane-key trust root into {node: [pinned key hex, ...]}.

    Every entry needs `node`, `pubkey` and `basis` (how the key came to be
    trusted). Anything missing or malformed raises: a broken trust root must
    not read as "nothing is pinned", which would let carried keys through as
    merely unpinned instead of stopping the caller.
    """
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"),
                         object_pairs_hook=_no_duplicate_keys)
    except TrustRootError:
        raise
    except Exception as e:
        raise TrustRootError(f"trust root unreadable: {e!r}"[:200]) from e
    if not isinstance(doc, dict) or doc.get("schema") != TRUST_ROOT_SCHEMA:
        raise TrustRootError(f"trust root schema must be {TRUST_ROOT_SCHEMA!r}")
    entries = doc.get("keys")
    if not isinstance(entries, list):
        raise TrustRootError("trust root `keys` must be a list")
    pins: Dict[str, List[str]] = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise TrustRootError(f"keys[{i}] must be an object")
        node, key, basis = entry.get("node"), _key_hex(entry.get("pubkey")), entry.get("basis")
        if not isinstance(node, str) or not node:
            raise TrustRootError(f"keys[{i}].node must be a non-empty string")
        if key is None:
            raise TrustRootError(f"keys[{i}].pubkey must be a 32-byte hex key")
        if not isinstance(basis, str) or not basis:
            raise TrustRootError(f"keys[{i}].basis must say how the key came to be trusted")
        if key not in pins.setdefault(node, []):
            pins[node].append(key)
    return pins
