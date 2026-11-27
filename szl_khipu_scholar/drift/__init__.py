"""Provenance/drift ledger entries as opaque tlog bytes.

This package does not import or alter szl_khipu_scholar.receipts. Being
logged does not make a row AUTHORIZED, LIVE, or publication_eligible.
"""

from .ledger import (
    COMPARISONS,
    SURFACES,
    DriftLedgerEntry,
    canonical_bytes,
    entry_digest,
)

__all__ = [
    "COMPARISONS",
    "SURFACES",
    "DriftLedgerEntry",
    "canonical_bytes",
    "entry_digest",
]
