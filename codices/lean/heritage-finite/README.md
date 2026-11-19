# HeritageFinite (Lean 4.35 / Lake)

Bounded arithmetic identities of the szl-papers ancient-mathematics source ledger
(commit c27a18f, docs/research/ANCIENT_MATH_SOURCE_LEDGER_20261118.md), machine-checked
in **core Lean only** (no mathlib dependency, builds offline in seconds).

Khipu decimal place-value, synthetic R2 top-cord sum check, Egyptian binary doubling,
exact unit-fraction cross-multiplied identities (2/7, 2/9), Euclidean remainder chain +
Bezout certificate, YBC 7289 sexagesimal digits + exact squared residual for sqrt(2),
Dresden calendar-round paired products. Ten theorems, all closed bounded statements.

 binds: szl-mesh PR #99 (Python layer), khipu-yachay release lane (separate), the
canonical lutar-lean proof obligations (untouched by doctrine).

Build: `lake build` (toolchain pinned by lean-toolchain = 4.35.0).
