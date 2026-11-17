"""DSSE-style receipt verification for SZLHOLDINGS mesh receipts.

Mirrors the production verification used by the estate's watchers:

    sig   = doc["sig"]                      (hex ed25519 signature)
    body  = doc minus "sig"                 (JSON, sort_keys=True)
    pk    = doc["payload"]["pubkey"]        (hex VerifyKey; boot receipts
                                             publish the node's public key)
    verdict = VerifyKey(pk).verify(body_json, sig)

Fail-closed: any missing field, unknown public key, or signature failure
returns ok=False with verdict OBSERVED. A receipt is only ever AUTHORIZED
when the signature actually verifies.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Union


def verify_receipt_dict(doc: Dict[str, Any], known_pubkeys: Dict[str, str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": False, "verdict": "OBSERVED",
                           "node": doc.get("node"), "type": doc.get("type"), "ts": doc.get("ts")}
    try:
        from nacl.signing import VerifyKey
    except ImportError:
        out["error"] = "pynacl not installed (pip install pynacl or szl-mesh)"
        return out
    try:
        sig_hex = doc.get("sig", "")
        body = dict(doc)
        body.pop("sig", None)
        pk_hex = (doc.get("payload") or {}).get("pubkey") or (known_pubkeys or {}).get(doc.get("node"))
        if not sig_hex or not pk_hex:
            out["error"] = "missing sig or public key"
            return out
        VerifyKey(bytes.fromhex(pk_hex)).verify(
            json.dumps(body, sort_keys=True).encode(), bytes.fromhex(sig_hex))
        out["ok"] = True
        out["verdict"] = "AUTHORIZED"
        return out
    except Exception as e:
        out["error"] = repr(e)[:200]
        return out


def verify_receipt_file(path: Union[str, Path]) -> Dict[str, Any]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        return {"ok": False, "verdict": "OBSERVED", "error": repr(e)[:200]}
    return verify_receipt_dict(doc)
