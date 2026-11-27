"""Local tests for the provenance/drift ledger. Throwaway keys only."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from szl_khipu_scholar.drift import DriftLedgerEntry, canonical_bytes, entry_digest
from szl_khipu_scholar.tlog import DirTileStore, Signer, TileLog, TileReader, open_checkpoint, merkle


FIX = Path(__file__).resolve().parent / "fixtures" / "provenance-drift-20261126.json"


class DriftLedgerTests(unittest.TestCase):
    def test_canonical_bytes_are_stable_and_key_sorted(self):
        row = {"b": 1, "a": "x"}
        self.assertEqual(canonical_bytes(row), b'{"a":"x","b":1}')
        self.assertEqual(entry_digest(row), entry_digest({"a": "x", "b": 1}))

    def test_rejects_unknown_comparison_and_surface(self):
        with self.assertRaises(ValueError):
            DriftLedgerEntry(
                asset="x", surface="hf_model", source_repo="r", source_rev="s",
                artifact_rev="a", observed_at="t", comparison="PASS", label="MEASURED",
            )
        with self.assertRaises(ValueError):
            DriftLedgerEntry(
                asset="x", surface="hub", source_repo="r", source_rev="s",
                artifact_rev="a", observed_at="t", comparison="MATCH", label="MEASURED",
            )

    def test_fixture_rows_round_trip_and_append_to_tlog(self):
        payload = json.loads(FIX.read_text(encoding="utf-8"))
        entries = []
        for raw in payload["rows"]:
            item = DriftLedgerEntry(
                asset=raw["asset"],
                surface=raw["surface"],
                source_repo=raw["source_repo"],
                source_rev=raw["source_rev"],
                artifact_rev=raw["artifact_rev"],
                observed_at=raw["observed_at"],
                comparison=raw["comparison"],
                label=raw["label"],
                artifact_sha256=raw.get("artifact_sha256"),
                audit_run=raw.get("audit_run"),
                notes=raw.get("notes") or "",
                evidence=tuple(raw.get("evidence") or ()),
            )
            entries.append(item.bytes())
            self.assertEqual(json.loads(item.bytes().decode("utf-8"))["schema"], "szl.provenance_drift_ledger.v1")
            self.assertNotIn("PRIVATE", item.bytes().decode("utf-8").upper())

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = DirTileStore(root / "log")
            # Throwaway key, discarded with the tempdir. Never a production origin.
            signer = Signer.generate("example.com/drift-test")
            log = TileLog(store, "example.com/drift-test", signer, state_path=root / "state")
            indexes = [log.append(blob) for blob in entries]
            signed = log.publish()
            checkpoint, _ = open_checkpoint(signed, [signer.verifier], origin="example.com/drift-test")
            reader = TileReader(store, checkpoint.size, checkpoint.root)
            reader.audit()
            self.assertEqual(checkpoint.size, len(entries))
            for index, blob in zip(indexes, entries):
                proof = reader.inclusion_proof(index)
                merkle.verify_inclusion(index, checkpoint.size, merkle.hash_leaf(blob), proof, checkpoint.root)

        # Conflict vs later drift are distinct for the same asset.
        brain = [row for row in payload["rows"] if row["asset"] == "SZLHOLDINGS/brain-navigator-r2"]
        self.assertEqual({row["comparison"] for row in brain}, {"CONFLICT", "DRIFT"})
        self.assertEqual(brain[0]["artifact_rev"], "4f6958469afcbb36124b194441ac398a722d36ef")
        self.assertEqual(brain[1]["artifact_rev"], "a545dce97ad9ec4e9d55e194384d22338f129b80")


if __name__ == "__main__":
    unittest.main()
