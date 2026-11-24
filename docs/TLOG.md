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
single-process and keeps the tree in memory (after a restart, `TileLog.resume`
rebuilds it from the entry bundles); it is a reference writer, not a production
sequencer. `DirTileStore` needs a POSIX system (directory file descriptors).

## Use

```python
from szl_khipu_scholar.tlog import DirTileStore, Signer, TileLog, TileReader, open_checkpoint

signer = Signer.generate("example.com/receipts")      # or Signer(name, seed) with a key you hold
state = "/var/lib/receipts-log.state"                  # outside the served directory "out"
log = TileLog(DirTileStore("out"), "example.com/receipts", signer, state_path=state)
index = log.append(receipt_bytes)                      # exactly the bytes that were signed
checkpoint = log.publish()                             # tiles, then the state record, then `checkpoint`

# after a restart: rebuild from the entry bundles of the last signed checkpoint
log = TileLog.resume(DirTileStore("out"), "example.com/receipts", signer, state_path=state)

cp, _ = open_checkpoint(checkpoint, [signer.verifier], origin="example.com/receipts")
reader = TileReader(DirTileStore("out"), cp.size, cp.root)   # pinned to the verified root
reader.audit()                                         # every full tile agrees with the tile above it
proof = reader.inclusion_proof(index)
```

`open_checkpoint` always requires a signature from the key named by the
checkpoint's own origin line; other known keys (witnesses, other logs) only
cosign. Pass `origin=` to pin the log as well. Without a pinned root,
`TileReader` still checks every full tile against the tile above it, but the
caller must compare `reader.root()` with the checkpoint before trusting answers.

Keys are supplied by the caller. This code never writes a key anywhere, and the
tests generate throwaway keys at test time.

## What the writer and readers refuse

Each rule below has tests in `tests/test_tlog_*.py`. On 2026-11-24 the rules
were removed one at a time on a scratch copy, and most removals fail a test.
Some do not yet: the fsync of the state record and of its directory, and the
state file's origin and location checks. Their behaviour is unchanged; only
the test that would catch their removal is missing.

* **No fork, no rollback.** `publish` raises `LogStateError` unless the new tree
  extends, by a verified consistency proof, the checkpoint served in the store
  (verified under the log key), the last one this object published, and the one
  recorded in `state_path`. The record is written durably before the signature
  exists. Keep it outside the served directory: whoever can write that directory
  can roll `checkpoint` back, but not the record. Without a state file a writer
  restarted on a rolled-back directory cannot know what it signed.
* **Interrupted publish.** Tiles left beyond the largest signed size by a publish
  that died are replaced on the next publish when a state file exists; without
  one they stay immutable and the writer refuses. Crash ordering is exercised by
  tests that record the order of writes and fsyncs; behaviour under real power
  loss is MODELED, not tested.
* **No writes outside the directory.** `DirTileStore` never opens a symlink below
  its root, writes through an exclusive temp file, and fsyncs file and directory.
* **Readers bound to the root.** See `TileReader` above.
* **Checkpoint parsing** follows c2sp.org/signed-note and tlog-checkpoint: only
  characters below U+0020 are control characters (U+007F is allowed), lines from
  unknown keys are ignored but may not repeat in a checkpoint, a size-0
  checkpoint must carry SHA-256 of the empty string, and sizes must fit in a uint64.
* **Proofs.** `verify_inclusion` and `verify_consistency` are checked against a
  recursive reference written from the RFC 6962 definitions, on honest proofs
  claimed for other indexes and sizes and on truncated, extended, swapped and
  bit-flipped ones.

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
* Go signs notes at the edges of the signed-note spec (U+007F in the text and in the
  key name, a repeated line from a key Python does not know); Python accepts them.

`TLOG_REQUIRE_GO=1` turns a missing Go toolchain from a skip into a failure.
