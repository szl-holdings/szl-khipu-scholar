"""QA dataset loading and validation for the OKR-derived khipu QA rows.

Census (measured at generation time from Open Khipu Repository khipu_main,
MIT-licensed): 770 QA rows over 619 khipus / 54,403 cords / 110,677 knots.
validate_dataset is fail-closed on schema drift and row-count mismatch.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Union

CENSUS = {"rows": 770, "khipus": 619, "cords": 54403, "knots": 110677}
REQUIRED_KEYS = ("id", "khipu_id", "question", "answer")


def load_qa(path: Union[str, Path]) -> List[Dict[str, Any]]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def validate_row(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    for k in REQUIRED_KEYS:
        if k not in row:
            return False
    if not isinstance(row["question"], str) or not row["question"].strip():
        return False
    if not isinstance(row["answer"], (str, int, float)):
        return False
    return True


def validate_dataset(path: Union[str, Path], expect_census: bool = True) -> Dict[str, Any]:
    rows = load_qa(path)
    bad = [i for i, r in enumerate(rows) if not validate_row(r)]
    out: Dict[str, Any] = {
        "ok": not bad,
        "rows": len(rows),
        "expected_rows": CENSUS["rows"] if expect_census else None,
        "invalid_indices": bad[:10],
        "census": CENSUS,
    }
    if expect_census and len(rows) != CENSUS["rows"]:
        out["ok"] = False
    return out
