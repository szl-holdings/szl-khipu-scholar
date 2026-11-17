# SZL Khipu Scholar

**Knot the corpus. Sign the run. Fail closed.**

Khipu Scholar is the scholarly-data product of the [SZL Holdings](https://github.com/szl-holdings) governed-AI estate: a provenance-first corpus of open-access khipu research, a QA dataset generated from the MIT-licensed Open Khipu Repository (OKR), and LoRA adapters trained in public under DSSE-signed, tamper-evident receipts.

**Artifact:** Python package + receipts API + explorer front end · **License:** Apache-2.0 · **Doctrine:** v11

## What is here

| Layer | Status | Evidence |
|---|---|---|
| Corpus (42 open-access docs, sha256 hash-pinned) | LIVE | [SZLHOLDINGS/khipu-scholars-corpus-v1](https://huggingface.co/datasets/SZLHOLDINGS/khipu-scholars-corpus-v1) |
| QA dataset (770 rows from OKR khipu_main: 619 khipus / 54,403 cords / 110,677 knots) | LIVE | [SZLHOLDINGS/khipu-scholars-sft-v1](https://huggingface.co/datasets/SZLHOLDINGS/khipu-scholars-sft-v1) |
| LoRA adapters (Qwen3-1.7B / 4B) | TRAINING (receipted) | [salad-khipu-scholar-v1](https://huggingface.co/SZLHOLDINGS/salad-khipu-scholar-v1) · [salad-khipu-scholar-4b-v1](https://huggingface.co/SZLHOLDINGS/salad-khipu-scholar-4b-v1) · [salad-khipu-structure-v1](https://huggingface.co/SZLHOLDINGS/salad-khipu-structure-v1) |
| Signed receipts (boot / crash / state / complete) | LIVE | [SZLHOLDINGS/khipu-scholar-runs](https://huggingface.co/datasets/SZLHOLDINGS/khipu-scholar-runs) |
| Mesh liveness beacons (cross-verified DSSE) | LIVE | [SZLHOLDINGS/mesh-liveness](https://huggingface.co/datasets/SZLHOLDINGS/mesh-liveness) |
| Receipts library (szl-mesh on PyPI) | LIVE | [pypi.org/project/szl-mesh](https://pypi.org/project/szl-mesh/) |

## Before you use it

- **No decipherment claims.** These are structure and scholar auxiliary models over a provenance-first corpus. Khipu decipherment remains open scholarship.
- **Copyrighted monographs are catalogued, never trained on.** Only open-access work under permissive terms enters the corpus; each document is sha256-pinned.
- **The ALBA claim is labeled disputed in the data.** Disputed attributions are carried as labels, not as ground truth.
- **Training losses and wall-hours are receipt-bound.** The canonical record is the signed receipt, not marketing copy.

## Why it matters (for investors)

Every autonomous or model-assisted step in this product line signs its work: training boots, crashes, state transitions, and completions are DSSE-signed records a third party can verify. That is the estate's core thesis - **AI that signs its work** - applied to a real scholarly domain (Andean khipu studies) with licensing discipline as a first-class feature.

Monetization path (staged, owner-gated): metered inference through the estate's x402 pattern ([szl-inference-gateway](https://github.com/szl-holdings/szl-inference-gateway)), a receipts-verification API service, and corpus/QA tooling. Cloudflare deployment wiring is staged under `cloudflare/`.

## For developers

```bash
git clone https://github.com/szl-holdings/szl-khipu-scholar
cd szl-khipu-scholar
pip install -e ".[verify]"
```

```python
from szl_khipu_scholar.receipts import verify_receipt_file   # DSSE-verify any mesh receipt
from szl_khipu_scholar.corpus import load_manifest, verify_manifest  # sha256 corpus pinning
from szl_khipu_scholar.qa import load_qa, validate_row  # OKR-derived QA rows
```

- Back end (receipts + corpus API): `server/app.py` (FastAPI)
- Front end (explorer, static, no build step): `frontend/index.html` (Cloudflare Pages-ready)
- Corpus doctrine (licensing, disputed labels): `docs/CORPUS_DOCTRINE.md`
- Receipts guide: `docs/RECEIPTS.md`

## Estate

Product: [a-11-oy.com](https://a-11-oy.com) · Proof: [a11oy.net](https://a11oy.net) · Sibling kernel product: [szl-khipu](https://github.com/szl-holdings/szl-khipu) · Org: [github.com/szl-holdings](https://github.com/szl-holdings)

© SZL Holdings. Apache-2.0; see NOTICE. Software and artifact rights as declared in repository metadata.
