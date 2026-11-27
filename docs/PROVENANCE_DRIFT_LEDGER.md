# Provenance and drift ledger (step 2)

Status: **local design**, built on the merged tlog from [szl-khipu-scholar#18](https://github.com/szl-holdings/szl-khipu-scholar/pull/18) and the follow-up refusal rules in #23 (current main `573eb48514133183bc892461dffb3da0cf155c13`). This branch has not been pushed.

The tlog commits to opaque entry bytes. It does not parse a receipt, and being in the log does not make a row `AUTHORIZED`, `LIVE`, `MEASURED`, or `publication_eligible`. Signing keys stay with the operator; tests use throwaway keys.

## Purpose

One row binds a **source revision** (GitHub commit, inventory, or receipt path) to a **running or published artifact** (HF model/dataset/Space revision, Cloudflare deployment, PyPI release) and records whether they still match.

| Field | Meaning |
| --- | --- |
| `asset` | Hub or GitHub id, for example `SZLHOLDINGS/chaski-r4` |
| `surface` | `github`, `hf_model`, `hf_dataset`, `hf_space`, `cloudflare`, `pypi`, `other` |
| `source_repo` / `source_rev` | Canonical source and the commit or inventory revision used for the comparison |
| `artifact_rev` | The observed running/published revision (HF sha, Space sha, deploy id, wheel hash) |
| `comparison` | `MATCH` (same as the bound source), `DRIFT` (revision moved), `CONFLICT` (card or claim disagrees with canonical evidence), `HOLD` (evidence incomplete), `UNKNOWN` |
| `label` | `MEASURED`, `REPORTED`, `MODELED`, or `UNKNOWN` |
| `audit_run` | Optional GitHub Actions run that produced the observation |
| `evidence` | Paths or URLs, never secrets |

`DRIFT` is a sha/revision change. `CONFLICT` is a claim-versus-file disagreement at a pinned revision, such as a README that does not disclose a canonical gate `FAIL`.

## How it uses the tlog

```python
from szl_khipu_scholar.drift import DriftLedgerEntry
from szl_khipu_scholar.tlog import DirTileStore, Signer, TileLog, TileReader, open_checkpoint

entry = DriftLedgerEntry(...).bytes()          # canonical JSON
signer = Signer.generate("example.com/drift")  # or an operator-held key; never commit one
log = TileLog(DirTileStore("out"), "example.com/drift", signer, state_path="state")
index = log.append(entry)
checkpoint = log.publish()
```

A later census signs a new checkpoint only if it extends the previous one (the #23 no-fork rule). Readers pin `TileReader` to the verified checkpoint root and call `audit()`.

## Not in this slice

HTTP serving, witnesses, timestamped cosignatures, and a production sequencer are still out of scope, as in `docs/TLOG.md`. Publishing checkpoints, allocating a real origin/key, or appending estate rows to a live log needs Stephen's named yes.

## First rows to log (once a key is approved)

See `tests/fixtures/provenance-drift-20261126.json` for the local, unsigned examples taken from the 2026-11-26 HF evidence audit and the later Hub reads. They are fixtures, not a published log.
