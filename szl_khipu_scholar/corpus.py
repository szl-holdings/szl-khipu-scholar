"""Corpus manifest: sha256 pinning for the open-access khipu corpus.

Doctrine:
- Only open-access, permissively licensed documents are pinned as trained.
- Copyrighted monographs are CATALOGUED (trained=false) and never trained.
- Disputed attributions (e.g. ALBA) carry disputed=true labels, not truth.
- verify_manifest is fail-closed: a missing trained document or a hash
  mismatch sets ok=False. It never upgrades a failure to a warning.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Union


@dataclass
class ManifestEntry:
    doc_id: str
    sha256: str
    license: str
    trained: bool
    disputed: bool = False
    title: str = ""
    source_url: str = ""
    notes: str = ""


def load_manifest(path: Union[str, Path]) -> List[ManifestEntry]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("entries", data.get("documents", []))
    out: List[ManifestEntry] = []
    for d in data:
        out.append(ManifestEntry(
            doc_id=d["doc_id"],
            sha256=d["sha256"],
            license=d.get("license", "unknown"),
            trained=bool(d.get("trained", False)),
            disputed=bool(d.get("disputed", False)),
            title=d.get("title", ""),
            source_url=d.get("source_url", ""),
            notes=d.get("notes", ""),
        ))
    return out


def file_sha256(path: Union[str, Path]) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_manifest(manifest_path: Union[str, Path], docs_dir: Union[str, Path]) -> Dict[str, Any]:
    entries = load_manifest(manifest_path)
    results: Dict[str, Any] = {
        "ok": True,
        "checked": 0,
        "trained": 0,
        "catalogued_not_trained": 0,
        "disputed_labels": 0,
        "mismatches": [],
    }
    for e in entries:
        if e.disputed:
            results["disputed_labels"] += 1
        if not e.trained:
            results["catalogued_not_trained"] += 1
            continue
        p = Path(docs_dir) / e.doc_id
        if not p.exists():
            results["ok"] = False
            results["mismatches"].append({"doc_id": e.doc_id, "error": "missing"})
            continue
        results["checked"] += 1
        results["trained"] += 1
        actual = file_sha256(p)
        if actual != e.sha256:
            results["ok"] = False
            results["mismatches"].append({"doc_id": e.doc_id, "pinned": e.sha256, "actual": actual})
    return results
