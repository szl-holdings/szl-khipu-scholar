# Codices of the world - corpus lane (v0 seed)

**Knot the corpus. Sign the run. Fail closed.** - extended beyond khipus to the world's mathematical record.

Every agrarian bureaucracy, temple school, and royal library that left us mathematics was chasing the same thing: a **durable, tamper-evidently-recorded receipt of computation**. Khipu knots are literally knotted account books with sum checks. The Rhind papyrus is a scribe's handbook of worked procedures that another scribe could re-verify. Plimpton 322 is a table of numbers that is *still* being argued about. The Bakhshali birch bark captures the zero placeholder. The Dresden codex tabulates eclipses. The Greeks went further and invented the thing that outlives every medium: the proof. This lane is the estate's continuation of that lineage: provenance-first, hash-pinned corpora of the world's open-access mathematical heritage, fed through the same machine pipeline as khipu-scholar (corpus -> QA dataset -> LoRA -> signed eval).

## Doctrine (v11, unchanged)

- **Open-access only.** Copyrighted material is catalogued, never scraped or trained on.
- **Every admitted artifact is sha256 hash-pinned** with a provenance card (source URL, license verification, date).
- **ADMITTED requires verified license status.** `VERIFY` means: do not scrape until the specific scan/edition license is confirmed.
- **No decipherment claims** for any undeciphered script or open scholarly question, anywhere in this lane.
- Receipts live with the run: corpus cards are committed like code, via PR.

## Heritage-transfer eval - 2026-11-19

Adapters trained on khipu data are probed for bounded-arithmetic transfer on adjacent ancient-math formulations. Dataset: [SZLHOLDINGS/khipu-heritage-eval-v1](https://huggingface.co/datasets/SZLHOLDINGS/khipu-heritage-eval-v1) (private), 47 ground-truthed rows: 16 Egyptian repeated-doubling products, 12 two-term unit-fraction decompositions 2/n, 9 sexagesimal conversions (incl. YBC 7289 1;24,51,10 = 30547/21600), 5 Maya calendar-round LCM rows, 5 decimal place-value controls. Every identity backing a gold answer is machine-checked in `codices/lean/heritage-finite` (Lean 4.35 core, lake-verified).

Honesty constraints: TRANSFER PROBE ONLY. Not a decipherment claim, not evidence about ancient scribes, not a heritage benchmark. Metric: exact match on completions. Results (when the eval lane runs) go to SZLHOLDINGS/khipu-scholar-runs with signed receipts.

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
3. LoRA train under signed training receipts (Salad GPU lanes); see `docs/RECEIPTS.md` for what verification establishes.
4. Held-out eval with signed receipts; honest metrics; no decipherment claims.

## Field leaders - upgrade mapping (2026-11-19)

A "zoom out" review of who currently leads each field this lane touches, and how the estate maps against them:

| Field | Current leaders | Estate position (2026-11-19) | Upgrade decision |
|---|---|---|---|
| Model supply chain / provenance | [Sigstore model-signing (CoSAI)](https://github.com/sigstore/model-signing); [CycloneDX 1.7 ML-BOM](https://cyclonedx.org); OWASP AIBOM; SPDX 3.0; CISA AI-in-OT principles | Signed run receipts (plain signed JSON with per-boot lane keys, not yet pinned or endorsed; liveness beacons are DSSE); CycloneDX 1.7 ML-BOMs now live next to both released adapters (`bom/ml-bom.json` in salad-khipu-scholar-v1 and salad-khipu-structure-v1), built from values in the training receipts, which are checked only against the keys they carry | Next provenance gate: a sigstore model-signing pass on released adapters (leaders sign the weights themselves; today we sign the receipts) |
| Fine-tuning throughput | [Unsloth](https://github.com/unslothai/unsloth) over Axolotl/TRL/LLaMA-Factory ([Jul 2026 comparison](https://www.marktechpost.com/2026/07/22/unsloth-vs-axolotl-vs-trl-vs-llama-factory-a-fine-tuning-framework-comparison-on-speed-vram-and-multi-gpu/)) | Current lanes train with TRL LoRA on Salad GPU | Adopt Unsloth for the *next* training lane only; never rewire a lane mid-run |
| Corpus khipu studies | [Metrological Domain Profiling IV](https://works.hcommons.org/records/2d7r8-26m93) (entropy-based classification over the full Open Khipu Repository; three administrative systems) | Our structure-v1 lane targets a different, honest objective: cipher reconstruction on held-out cords (cipher_exact_match 0.9113, n=282, signed receipt 2026-11-19) | Cite as field context in structure-lane docs; no decipherment claims either way |

These citations are published techniques and comparisons, field context only: not partnerships, not endorsements, and no claims about decipherment.
