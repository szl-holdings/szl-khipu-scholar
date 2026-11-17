# Receipts guide

The Khipu Scholar product line publishes cryptographic receipts for every
training event, on every lane:

| Receipt type | Meaning |
|---|---|
| boot | lane started; publishes the node's ed25519 public key |
| crash | lane crashed; root cause + last state |
| state | periodic state (step, loss, wall time) |
| complete | training finished; final loss + adapter location |
| beacon | liveness gossip between lanes (cross-verified) |

Verification (fail-closed):

```python
from szl_khipu_scholar.receipts import verify_receipt_file
verdict = verify_receipt_file("mesh/khipu-scholar-v1-complete.json")
# verdict["verdict"] is "AUTHORIZED" only if the signature verifies;
# anything missing or unverified is "OBSERVED" - never upgraded.
```

The mesh library behind the receipts is [szl-mesh on PyPI](https://pypi.org/project/szl-mesh/).
Live receipt repositories: [khipu-scholar-runs](https://huggingface.co/datasets/SZLHOLDINGS/khipu-scholar-runs) (receipts) and [mesh-liveness](https://huggingface.co/datasets/SZLHOLDINGS/mesh-liveness) (beacons).
