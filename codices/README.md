# Codices of the world - corpus lane (v0 seed)

**Knot the corpus. Sign the run. Fail closed.** - extended beyond khipus to the world's mathematical record.

Every agrarian bureaucracy, temple school, and royal library that left us mathematics was chasing the same thing: a **durable, tamper-evidently-recorded receipt of computation**. Khipu knots are literally knotted account books with sum checks. The Rhind papyrus is a scribe's handbook of worked procedures that another scribe could re-verify. Plimpton 322 is a table of numbers that is *still* being argued about. The Bakhshali birch bark captures the zero placeholder. The Dresden codex tabulates eclipses. The Greeks went further and invented the thing that outlives every medium: the proof. This lane is the estate's continuation of that lineage: provenance-first, hash-pinned corpora of the world's open-access mathematical heritage, fed through the same machine pipeline as khipu-scholar (corpus -> QA dataset -> LoRA -> signed eval).

## Doctrine (v11, unchanged)

- **Open-access only.** Copyrighted material is catalogued, never scraped or trained on.
- **Every admitted artifact is sha256 hash-pinned** with a provenance card (source URL, license verification, date).
- **ADMITTED requires verified license status.** `VERIFY` means: do not scrape until the specific scan/edition license is confirmed.
- **No decipherment claims** for any undeciphered script or open scholarly question, anywhere in this lane.
- Receipts live with the run: corpus cards are committed like code, via PR.

## Seed manifest - 2026-11-19

| Source | Civilization | Status | Notes |
|---|---|---|---|
| Rhind Mathematical Papyrus (BM 10057/10058), 1927 facsimile + translation (Peet) | Egypt | **ADMITTED** | Internet Archive, Public Domain Mark 1.0 (verified on item 2026-11-19). OCR text 535,229 bytes, sha256 914ad617e0fac06b. Held machine-side pending HF corpus dataset; card: `codices/seeds/rhind-1927-ocr.json` |
| Bakhshali manuscript (MS Sansk. d.14) | India | CATALOGUED_GATED | Bodleian Libraries copyright on images; earliest zero placeholder (folio 16, 224-383 AD carbon-dated). Catalogue only - contact Bodleian before any reproduction |
| Plimpton 322 + Babylonian math tablets | Babylon | VERIFY | CDLI is open access; confirm per-item license before admission |
| Moscow Mathematical Papyrus | Egypt | VERIFY | 1930 Struve edition out of scope until scan license confirmed |
| Dresden Codex (facsimile scans) | Maya | VERIFY | Facsimiles public domain at source library; confirm scan terms |
| Nine Chapters on the Mathematical Art | China | VERIFY | Public-domain translations exist; confirm each scan |
| Euclid, *Elements* (Heath 1908); Archimedes (Heath 1897) | Greece | VERIFY | Public domain; pin specific scans at admission time |

## Pipeline (planned, mirrors khipu-scholar lane)

1. Admit source (license verified, sha256 pinned, provenance card committed via PR).
2. Extract structure (tables, worked problems, numerals) into a QA dataset.
3. LoRA train under DSSE-signed, tamper-evident receipts (Salad GPU lanes).
4. Held-out eval with signed receipts; honest metrics; no decipherment claims.
