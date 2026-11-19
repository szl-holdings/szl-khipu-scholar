# Receipts transparency log (tiled)

Status: **fresh implementation, added alongside the existing receipts code.**
It does not import, wrap or change `szl_khipu_scholar.receipts`, and it does not
touch how a receipt is canonicalized, signed or verified. The log commits to the
raw bytes of whatever entry it is given; it never parses an entry, so it cannot
change what a receipt means, and being in the log does not make a receipt
`AUTHORIZED`. That still requires a pinned lane key (see `docs/RECEIPTS.md`).

## What is implemented

| Spec | Where |
| --- | --- |
| RFC 6962 hashing, inclusion and consistency proofs (verified with the RFC 9162 algorithms) | `szl_khipu_scholar/tlog/merkle.py` |
| [c2sp.org/signed-note](https://c2sp.org/signed-note), Ed25519 (type `0x01`), vkeys | `.../tlog/note.py` |
| [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint), Ed25519 log signature | `.../tlog/checkpoint.py` |
| [c2sp.org/tlog-tiles](https://c2sp.org/tlog-tiles): height-8 tiles, full and partial tiles, entry bundles, `checkpoint` | `.../tlog/tiles.py`, `.../tlog/log.py` |

Not implemented: timestamped cosignatures (types `0x04`, `0x06`), witnessing
(`c2sp.org/tlog-witness`), pruning / minimum index, HTTP serving. The writer is
single-process and keeps the tree in memory; it is a reference writer, not a
production sequencer.

## Use

```python
from szl_khipu_scholar.tlog import DirTileStore, Signer, TileLog, TileReader, open_checkpoint

signer = Signer.generate("example.com/receipts")      # or Signer(name, seed) with a key you hold
log = TileLog(DirTileStore("out"), "example.com/receipts", signer)
index = log.append(receipt_bytes)                      # exactly the bytes that were signed
checkpoint = log.publish()                             # writes tiles first, then `checkpoint`

cp, _ = open_checkpoint(checkpoint, [signer.verifier], origin="example.com/receipts")
reader = TileReader(DirTileStore("out"), cp.size)
assert reader.root() == cp.root
reader.audit()                                         # every tile agrees with the tile above it
proof = reader.inclusion_proof(index)
```

Keys are supplied by the caller. This code never writes a key anywhere, and the
tests generate throwaway keys at test time.

## Tests

```
pip install -e ".[tlog]" pytest
python -m pytest -q tests/test_tlog_merkle.py tests/test_tlog_note.py tests/test_tlog_tiles.py
python -m pytest -q tests/test_tlog_interop.py        # needs Go; runs tests/interop/go
```

The interop test builds a log of up to 65,793 entries (full and partial tiles at
levels 0 to 2) with throwaway keys, then has independent Go implementations check it:

* `golang.org/x/mod/sumdb/note` opens every checkpoint, rejects tampering and a wrong key.
* `golang.org/x/mod/sumdb/tlog` reads the tiles through `TileHashReader` (which checks
  tiles against the signed root); its own inclusion and consistency proofs equal ours byte for byte.
* `github.com/transparency-dev/merkle` verifies our proofs and rejects mutated, truncated
  and wrong-index ones.
* `github.com/transparency-dev/formats/log` parses the checkpoints and re-marshals them byte for byte.
* `github.com/transparency-dev/tessera/client` (a tlog-tiles client) fetches the checkpoint,
  builds proofs and reads entry bundles, from a directory and over HTTP (local test server).
* Go signs a checkpoint with its own throwaway key; Python accepts it.

`TLOG_REQUIRE_GO=1` turns a missing Go toolchain from a skip into a failure.
