"""szl-khipu-scholar: provenance-first khipu corpus tooling and receipt verification.

Part of the SZL Holdings governed-AI estate. Fail closed: a receipt is AUTHORIZED
only against a pinned lane key; unsigned or self-keyed receipts are OBSERVED.
Hash mismatches are failures, never warnings.
"""
__version__ = "0.1.0"

from .corpus import file_sha256, load_manifest, verify_manifest
from .qa import CENSUS, load_qa, validate_dataset, validate_row


def verify_receipt_file(*args, **kwargs):
    from .receipts import verify_receipt_file as _v
    return _v(*args, **kwargs)


__all__ = [
    "__version__",
    "file_sha256", "load_manifest", "verify_manifest",
    "CENSUS", "load_qa", "validate_dataset", "validate_row",
    "verify_receipt_file",
]
