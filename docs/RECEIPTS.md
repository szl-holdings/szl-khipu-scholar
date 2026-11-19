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
| beacon | liveness gossip between lanes |

Live receipt repositories: [khipu-scholar-runs](https://huggingface.co/datasets/SZLHOLDINGS/khipu-scholar-runs) (receipts) and [mesh-liveness](https://huggingface.co/datasets/SZLHOLDINGS/mesh-liveness) (beacons).

## What a receipt is

A receipt is a JSON object with an ed25519 signature, in hex, over
`json.dumps(receipt_without_sig, sort_keys=True)`. It is plain signed JSON,
not a DSSE envelope: there is no `payloadType` and no pre-authentication
encoding.

## What verification establishes

Two separate questions, reported separately:

| Field | Values | Question it answers |
|---|---|---|
| `signature` | `VALID`, `INVALID`, `MISSING`, `UNCHECKED` | Were these bytes signed by the key they were checked against? |
| `key_state` | `PINNED`, `UNPINNED`, `MISMATCH`, `ABSENT` | Is that key one this repository trusts for the lane? |

`verdict` is `AUTHORIZED` only for `signature = VALID` with `key_state = PINNED`.
Everything else is `OBSERVED`.

`boot`, `complete` and `eval` receipts carry a public key in `payload.pubkey`.
Whoever writes a receipt chooses the key it carries, so a signature that
verifies against that key shows the receipt has not been altered since it was
signed. It does not show who signed it. That case is reported as
`signature = VALID`, `key_state = UNPINNED`, `verdict = OBSERVED`.

A carried key never replaces a pinned one. If a lane has a pinned key and a
receipt carries a different key, the receipt is `MISMATCH` and is not checked
further.

```python
from szl_khipu_scholar.receipts import load_trust_root, verify_receipt_file

pins = load_trust_root()   # szl_khipu_scholar/trust/lane_keys.json
v = verify_receipt_file("mesh/khipu-scholar-v1-complete.json", pins)
# v["verdict"], v["signature"], v["key_state"]
```

Install with `pip install -e ".[verify]"`.

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

**Status, 2026-11-19: no lane key is pinned, so no receipt is AUTHORIZED.**

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
- Nothing outside the receipts endorses any lane key.

These are properties of how the lanes write receipts. The verifier reports
them; it cannot repair them.

## Roadmap

- **ROADMAP:** the dispatcher endorses each boot key with a long-lived estate
  key before training starts, so a verifier needs only the estate public key.
- **ROADMAP:** receipts are written append-only, each naming the digest of
  the one before it, so a lane's history does not depend on dataset commit
  history.
