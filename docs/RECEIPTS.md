# Receipts guide

The Khipu Scholar product line publishes a signed receipt for every training
event, on every lane:

| Receipt type | Meaning |
|---|---|
| boot | lane started; carries the public key that boot generated |
| crash | lane crashed; root cause + last state |
| state | periodic state (step, loss, wall time) |
| complete | training finished; final loss + adapter location |
| eval | held-out evaluation result |
| parked | lane waiting on an input (for example an adapter not yet released) |
| beacon | liveness gossip between lanes |

`decommission` files in the same folder are unsigned operator notes, not
receipts.

Live receipt repositories: [khipu-scholar-runs](https://huggingface.co/datasets/SZLHOLDINGS/khipu-scholar-runs) (receipts) and [mesh-liveness](https://huggingface.co/datasets/SZLHOLDINGS/mesh-liveness) (beacons).

## What a receipt is

A receipt is a JSON object with an ed25519 signature, in hex, over
`json.dumps(receipt_without_sig, sort_keys=True)`. It is plain signed JSON,
not a DSSE envelope: there is no `payloadType` and no pre-authentication
encoding. (The liveness beacons are DSSE envelopes.)

## What verification establishes

Two separate questions, reported separately:

| Field | Values | Question it answers |
|---|---|---|
| `signature` | `VALID`, `INVALID`, `MISSING`, `UNCHECKED` | Were these bytes signed by the key they were checked against? |
| `key_state` | `PINNED`, `UNPINNED`, `MISMATCH`, `ABSENT`, `UNCHECKED` | Is that key one this repository trusts for the lane? |

`verdict` is `AUTHORIZED` only for `signature = VALID` with `key_state = PINNED`.
Everything else is `OBSERVED`.

`boot`, `complete` and `eval` receipts carry a public key in `payload.pubkey`.
Whoever writes a receipt chooses the key it carries. A signature that
verifies against that key shows only that the receipt was signed by it:
anyone able to write the file could alter a receipt, re-sign it with a fresh
key, and it would be reported exactly the same way
(`signature = VALID`, `key_state = UNPINNED`, `verdict = OBSERVED`). Without a
pinned key there is no tamper evidence.

A carried key never replaces a pinned one. If a lane has a pinned key and a
receipt carries a different key, the receipt is `MISMATCH` and is not checked
further. A pin that is not exactly 64 hex characters is also `MISMATCH`.

Receipt files with duplicate JSON keys are refused, because JSON parsers
disagree about which value wins.

```python
from szl_khipu_scholar.receipts import load_trust_root, verify_receipt_file

pins = load_trust_root()   # szl_khipu_scholar/trust/lane_keys.json
v = verify_receipt_file("mesh/khipu-scholar-v1-complete.json", pins)
# v["verdict"], v["signature"], v["key_state"]
```

Install with `pip install -e ".[verify]"`.

The `/receipts` endpoint (`server/app.py`) adds one rule: lanes write
`mesh/<node>-<type>.json`, so a receipt served under a file name that does not
match its own node and type is shown as `OBSERVED` with
`file_matches_receipt = false`. One unreadable file is reported in its own row;
it does not hide the rest of the feed.

## The trust root

`szl_khipu_scholar/trust/lane_keys.json` lists the lane keys this repository
trusts:

```json
{
  "schema": "szl.khipu-scholar.lane-keys/v1",
  "keys": [
    {"node": "<lane name>", "pubkey": "<64 hex chars>", "basis": "<how this key came to be trusted>"}
  ]
}
```

A lane may have several keys, one per boot. `basis` is required: it records
what the pin rests on, for example the Hub commit in which the boot receipt
first appeared and who reviewed it. A pin taken from a published boot receipt
is trust on first use. It shows later receipts come from the same key holder.
It does not show the first receipt came from the estate.

A change to this file is a trust decision and goes through review like code.
The server reads it from `KHIPU_TRUST_ROOT` when that is set; a set but empty
or unreadable value authorizes nothing.

**Status, 2026-11-19: no lane key is pinned, so no receipt is AUTHORIZED.**
Verdicts of `AUTHORIZED` recorded before this change, for example in the
`decommission` note for `khipu-structure-v1`, came from a verifier that
accepted any carried key. They do not establish who signed those receipts.

## Known limits of the published receipts

Observed in `khipu-scholar-runs` at the 2026-11-19 revision:

- Each container boot generates a new key. A lane that restarts gets a new
  boot receipt with a new key.
- Receipts are written to one file per lane and type, so a new boot receipt
  replaces the previous one. The earlier version exists only in the dataset's
  commit history.
- `state`, `crash` and `parked` receipts carry no key. They can be checked
  only against a pinned key or the lane's boot receipt.
- For `khipu-scholar-v1` and `khipu-structure-v1`, the `complete` receipt was
  signed before the lane restarted. Its key differs from the key in the
  lane's current boot receipt, so the current files alone do not link
  `complete` back to a boot.
- `complete` receipts record steps, final loss, GPU-hours, the target
  repository and the corpus SHA-256. They do not record hardware, training
  parameters, the base-model revision or the adapter's file hash.
- Nothing outside the receipts endorses any lane key, and an older signed
  receipt can be replayed under the same file name.

These are properties of how the lanes write receipts. The verifier reports
them; it cannot repair them.

## Roadmap

- **ROADMAP:** the dispatcher endorses each boot key with a long-lived estate
  key before training starts, so a verifier needs only the estate public key.
- **ROADMAP:** receipts are written append-only, each naming the digest of
  the one before it, so a lane's history does not depend on dataset commit
  history and old receipts cannot be replayed.
- **ROADMAP:** `complete` receipts bind the adapter's file hash, the base-model
  revision and the dataset revision.
