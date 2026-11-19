"""Khipu Scholar receipts + corpus API (back end).

FastAPI app serving the signed-receipt feed and corpus census.
Fail-closed by design:
- If HF_TOKEN is absent and a repository is private, endpoints return an
  honest error, never fabricated data.
- Receipt verdicts are computed, not asserted: a receipt is AUTHORIZED only
  when its signature verifies against a lane key pinned in the trust root.
  A receipt that only verifies against the key it carries is OBSERVED.

Run: uvicorn server.app:app --host 127.0.0.1 --port 8787
"""
from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

RUNS_REPO = os.environ.get("KHIPU_RUNS_REPO", "SZLHOLDINGS/khipu-scholar-runs")
CORPUS_REPO = os.environ.get("KHIPU_CORPUS_REPO", "SZLHOLDINGS/khipu-scholars-corpus-v1")
SFT_REPO = os.environ.get("KHIPU_SFT_REPO", "SZLHOLDINGS/khipu-scholars-sft-v1")
MODELS = {
    "salad-khipu-scholar-v1": "Qwen3-1.7B LoRA, scholar lane",
    "salad-khipu-scholar-4b-v1": "Qwen3-4B LoRA, scholar lane",
    "salad-khipu-structure-v1": "Qwen3-1.7B LoRA, structure lane",
}

app = FastAPI(title="Khipu Scholar API", version="0.1.0",
              description="Receipts and provenance for the SZL khipu scholar product line.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"], allow_headers=["*"])


def _hub():
    from huggingface_hub import HfApi, hf_hub_download
    return HfApi(), hf_hub_download


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "service": "khipu-scholar-api", "version": "0.1.0",
            "runs_repo": RUNS_REPO, "token_present": bool(os.environ.get("HF_TOKEN"))}


@app.get("/receipts")
def receipts() -> Dict[str, Any]:
    try:
        api, download = _hub()
        files = sorted(f for f in api.list_repo_files(RUNS_REPO, repo_type="dataset")
                       if f.startswith("mesh/") and f.endswith(".json"))
    except Exception as e:
        raise HTTPException(status_code=503, detail="runs repo unreadable: " + repr(e)[:200])
    from szl_khipu_scholar.receipts import (
        DEFAULT_TRUST_ROOT, TrustRootError, load_trust_root, parse_receipt,
        verify_receipt_dict)
    # No readable trust root means nothing is pinned, so nothing can be AUTHORIZED.
    root_path = os.environ.get("KHIPU_TRUST_ROOT")
    try:
        if root_path == "":
            raise TrustRootError("KHIPU_TRUST_ROOT is set but empty")
        pins = load_trust_root(DEFAULT_TRUST_ROOT if root_path is None else root_path)
        trust_root = {"state": "LOADED", "pinned_nodes": len(pins)}
    except TrustRootError as e:
        pins, trust_root = None, {"state": "UNAVAILABLE", "error": str(e)[:200]}
    out: List[Dict[str, Any]] = []
    for f in files:
        try:
            _, download_fn = _hub()
            p = download_fn(RUNS_REPO, f, repo_type="dataset")
            v = verify_receipt_dict(parse_receipt(Path(p).read_bytes()), pins)
            out.append(_receipt_row(f, v))
        except Exception as e:  # one bad file must not blank the feed
            out.append({"file": f, "node": None, "type": None, "ts": None,
                        "verdict": "OBSERVED", "signature": "UNCHECKED",
                        "key_state": "UNCHECKED", "file_matches_receipt": None,
                        "error": _text(repr(e)[:160])})
    return {"repo": RUNS_REPO, "count": len(out), "trust_root": trust_root, "receipts": out}


def _text(value: Any) -> Optional[str]:
    """A receipt field as text safe to serialize, or None for anything else."""
    if not isinstance(value, str):
        return None
    return value.encode("utf-8", "replace").decode("utf-8")


def _ts(value: Any) -> Any:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) or (isinstance(value, float) and math.isfinite(value)):
        return value
    return _text(value)


def _receipt_row(file: str, v: Dict[str, Any]) -> Dict[str, Any]:
    node, rtype = _text(v.get("node")), _text(v.get("type"))
    # Lanes write mesh/<node>-<type>.json. A valid receipt served under another
    # lane's file name is not shown as AUTHORIZED for that file.
    matches = node is not None and rtype is not None and Path(file).stem == f"{node}-{rtype}"
    row = {"file": file, "node": node, "type": rtype, "ts": _ts(v.get("ts")),
           "verdict": v["verdict"], "signature": v["signature"],
           "key_state": v["key_state"], "file_matches_receipt": matches,
           "error": _text(v.get("error"))}
    if row["verdict"] == "AUTHORIZED" and not matches:
        row["verdict"] = "OBSERVED"
        row["error"] = "file name does not match the receipt's node and type"
    return row


@app.get("/census")
def census() -> Dict[str, Any]:
    from szl_khipu_scholar.qa import CENSUS
    return {"ok": True, "census": CENSUS,
            "sft_repo": SFT_REPO, "corpus_repo": CORPUS_REPO,
            "corpus_docs": 42,
            "monographs_catalogued_not_trained": True,
            "alba_label": "disputed"}


@app.get("/models")
def models() -> Dict[str, Any]:
    return {"ok": True, "status": "TRAINING (receipted; see /receipts)",
            "models": [{"repo": "SZLHOLDINGS/" + k, "base": v} for k, v in MODELS.items()],
            "canonical_record": "signed receipts in " + RUNS_REPO}
