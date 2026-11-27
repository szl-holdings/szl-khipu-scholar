"""Canonical bytes for a source-commit-to-running-artifact drift row."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

SCHEMA = "szl.provenance_drift_ledger.v1"
SURFACES = frozenset(
    {"github", "hf_model", "hf_dataset", "hf_space", "cloudflare", "pypi", "other"}
)
COMPARISONS = frozenset({"MATCH", "DRIFT", "CONFLICT", "HOLD", "UNKNOWN"})
LABELS = frozenset({"MEASURED", "REPORTED", "MODELED", "UNKNOWN"})
REQUIRED = (
    "schema",
    "asset",
    "surface",
    "source_repo",
    "source_rev",
    "artifact_rev",
    "observed_at",
    "comparison",
    "label",
)


def canonical_bytes(row: Mapping[str, Any]) -> bytes:
    """Stable UTF-8 JSON. Keys sorted, no extra whitespace, no NaN."""
    return json.dumps(dict(row), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def entry_digest(row: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(row)).hexdigest()


@dataclass(frozen=True)
class DriftLedgerEntry:
    asset: str
    surface: str
    source_repo: str
    source_rev: str
    artifact_rev: str
    observed_at: str
    comparison: str
    label: str
    artifact_sha256: str | None = None
    audit_run: str | None = None
    notes: str = ""
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.surface not in SURFACES:
            raise ValueError(f"unknown surface: {self.surface}")
        if self.comparison not in COMPARISONS:
            raise ValueError(f"unknown comparison: {self.comparison}")
        if self.label not in LABELS:
            raise ValueError(f"unknown label: {self.label}")
        if not self.asset or not self.observed_at:
            raise ValueError("asset and observed_at are required")

    def as_dict(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "schema": SCHEMA,
            "asset": self.asset,
            "surface": self.surface,
            "source_repo": self.source_repo,
            "source_rev": self.source_rev,
            "artifact_rev": self.artifact_rev,
            "observed_at": self.observed_at,
            "comparison": self.comparison,
            "label": self.label,
            "artifact_sha256": self.artifact_sha256,
            "audit_run": self.audit_run,
            "notes": self.notes,
            "evidence": list(self.evidence),
        }
        missing = [key for key in REQUIRED if not row.get(key)]
        if missing:
            raise ValueError(f"missing required fields: {missing}")
        return row

    def bytes(self) -> bytes:
        return canonical_bytes(self.as_dict())

    def digest(self) -> str:
        return entry_digest(self.as_dict())
