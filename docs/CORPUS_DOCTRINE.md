# Corpus doctrine

## Licensing discipline
- **Open Khipu Repository (OKR)**: MIT. Structural data (khipu_main: 619 khipus / 54,403 cords / 110,677 knots) derived under its terms; schema published; attribution retained.
- **Text corpus**: open-access scholarship only. Each document is sha256-pinned in the corpus manifest.
- **Copyrighted monographs**: catalogued in metadata with `trained=false`. They are NEVER included as training data. This is a hard doctrine line, not a preference.
- **ALBA attribution**: carried with a `disputed=true` label wherever it appears. Disputed is a label, not a verdict.

## Receipts as the canonical record
Any loss, step count, or wall-hour figure outside a DSSE-signed receipt is non-canonical marketing copy. The signed receipt chain (boot, crash, state, complete) in the runs repository is the only accepted record.

## Claims discipline
- No decipherment claims. The adapters are structure and scholar auxiliary models.
- Models inherit the corpus's license boundaries; downstream users must respect OKR MIT terms and the disputed-label convention.

## Data and validation boundaries

The QA census is a count of records in a particular derived dataset, not a
measure of archaeological completeness or correctness. In
[`qa.py`](../szl_khipu_scholar/qa.py), `validate_row` checks required keys,
nonempty question text and the answer's Python type. `validate_dataset`
also checks the expected row count when requested. These checks do not verify
answers against the upstream database, unique identifiers, source-field
coverage, train/evaluation separation, or the accuracy of the original
recording. Passing validation must not be labeled independent scientific
validation.

A signed receipt can bind a recorded run to an artifact; it does not establish
that the source descriptions are accurate, that the dataset represents all
surviving khipus, or that a model generalizes. Training loss is not held-out
evaluation. Report any independent evaluation separately, with its split,
source pins, exclusions and uncertainty.

### Separate compact arithmetic projection

The sibling `szl-khipu` project has a compact OKR arithmetic corpus. It is not
the same artifact as this project's QA dataset, and its coverage must not be
silently transferred to the QA census.

At the [reviewed source revision](https://github.com/szl-holdings/szl-khipu/blob/5a6a3843008906051e7b3289767078cd04d26ac3/szl_khipu/okr_khipu.py),
`PRIMARY_FIELDS` contains only `id`, `length` and `color`. The compact
cord fields include structure, recorded knot values and a color label, but
do not include fiber/material descriptions or detailed primary-cord
attachments. Its [builder](https://github.com/szl-holdings/szl-khipu/blob/5a6a3843008906051e7b3289767078cd04d26ac3/research/okr_corpus/build_corpus.py)
selects a subset of upstream fields. An omission from this projection is
**not** evidence that the upstream record lacks the information, or that the
physical object lacks the feature.

Arithmetic relations computed from that projection concern recorded numeric
structure, not a complete physical reconstruction or an interpretation of
materials, attachments or narrative meaning. Its
[study limitations](https://github.com/szl-holdings/szl-khipu/blob/5a6a3843008906051e7b3289767078cd04d26ac3/research/okr_corpus/README.md#limitations)
remain part of any presentation of those results.

### Requirements for future enrichment

Before adding new fields or claims, inspect the pinned upstream schema and
record field-level provenance and coverage. Distinguish a field not captured
by an export from a missing upstream value and an unverified observation.
Do not invent materials, replace unknown observations with a default material,
or equate absent documentation with physical absence. Any future enrichment
requires its own documented source and validation; this document does not
claim that such enrichment or an independent evaluation has been completed.
