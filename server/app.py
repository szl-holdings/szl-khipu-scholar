"""Khipu Scholar receipts + corpus API (back end).

FastAPI app serving the signed-receipt feed and corpus census.
Fail-closed by design:
- If HF_TOKEN is absent and a repository is private, endpoints return an
  honest error, never fabricated data.
- Receipt verdicts are computed, not asserted: an unsigned or unverified
  receipt is OBSERVED, never AUTHORIZED.

Run: uvicorn server.app:app --host 127.0.0.1 --port 8787
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

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
    from szl_khipu_scholar.receipts import verify_receipt_dict
    out: List[Dict[str, Any]] = []
    for f in files:
        try:
            _, download_fn = _hub()
            p = download_fn(RUNS_REPO, f, repo_type="dataset")
            doc = json.loads(Path(p).read_text(encoding="utf-8"))
            v = verify_receipt_dict(doc)
            out.append({"file": f, "node": v.get("node"), "type": v.get("type"),
                        "verdict": v["verdict"], "ts": v.get("ts")})
        except Exception as e:
            out.append({"file": f, "verdict": "OBSERVED", "error": repr(e)[:120]})
    return {"repo": RUNS_REPO, "count": len(out), "receipts": out}


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
            "canonical_record": "DSSE receipts in " + RUNS_REPO}
