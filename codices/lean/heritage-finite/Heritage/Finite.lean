/- # Heritage Finite: bounded arithmetic identities for the codices lane

Source of truth: szl-papers c27a18f ANCIENT_MATH_SOURCE_LEDGER_20261118.md (source-only,
draft, non-normative) and the merged Python junction szl-mesh PR #99
(src/szl_mesh/heritage_math.py). This module is the Lean/Lake layer of that ledger:
the same bounded identities, stated and machine-checked in Lean 4 core.

Doctrine constraints carried verbatim from the ledger:
- SYNTHETIC NUMBERS ONLY. No real archaeological data enters this file.
- NO historically-decipherMENT claims: no automatic knot decipherment, no narrative
  decoding of khipus, no reading of Dresden astronomy, no facsimile reproduction.
- Modern algorithms are NOT attributed to ancient scribes (greedy unit-fraction
  search is a modern construction; Euclid VII.2 is cited as mathematical
  equivalence, not verbatim ancient proof; an SZL Lean proof of an ancient theorem
  is not claimed).
- Maya (Dresden) and Inka (khipu) traditions remain separately identified.
- These are elementary bounded identities for multi-source provenance hygiene of
  agentic claims, not archaeological findings, model improvements, or progress on
  the canonical lutar-lean proof obligations.

This package supersedes the private ancient-math bridge snapshot reported lost to
the 2026-11-19 device rotation (reported receipt 03c3889c..., archive 0c5f051c...),
restoring its Lean layer as governed, reviewed code.
-/

namespace HeritageFinite

/-- Synthetic base-10 positional identity (khipu decimal place-value analogy). -/
theorem khipuPlaceValue : 3*100 + 1*10 + 4 = 314 := by decide

/-- Synthetic top-cord ledger sum check (R2 analogy): cords 12, 7, 5 under a top cord 24. -/
theorem khipuR2SyntheticSum : List.foldl (fun acc v => acc + v) 0 [12, 7, 5] = 24 := by rfl

/-- Egyptian-style binary doubling of 27 * 13 (13 = 8 + 4 + 1). -/
theorem egyptDoubling : 27*8 + 27*4 + 27*1 = 27*13 := by decide

/-- Exact unit-fraction decomposition 2/7 = 1/4 + 1/28, cross-multiplied (no division, core-only). -/
theorem rhindTwoSevenths : 2*(4*28) = 7*(28+4) := by decide

/-- Exact unit-fraction decomposition 2/9 = 1/6 + 1/18, cross-multiplied. -/
theorem rhindTwoNinths : 2*(6*18) = 9*(18+6) := by decide

/-- Euclidean mutual-subtraction chain for the pair (232, 72), realized as a remainder chain. -/
theorem euclidChain : ((232:Int) % 72 = 16) ∧ ((72:Int) % 16 = 8) ∧ ((16:Int) % 8 = 0) := by decide

/-- Bezout certificate for the same pair: 232*5 - 72*16 = 8. -/
theorem bezoutCert : (232:Int)*5 - (72:Int)*16 = 8 := by decide

/-- YBC 7289 sexagesimal digits 1;24,51,10 (integer part + fraction, x216000 denominator). -/
theorem ybc7289Digits : 1*216000 + 24*3600 + 51*60 + 10 = 10*30547 := by decide

/-- YBC 7289 squared residual: (30547/21600)^2 misses 2 by 791/466560000 (exact). -/
theorem ybc7289Residual : (30547:Int)*(30547:Int) - 2*(21600*21600) = -791 := by decide

/-- Dresden calendar round: 73 * 260 = 52 * 365 = 18980 (LCM fact as paired products). -/
theorem dresdenCalendarRound : 73*260 = 18980 ∧ 52*365 = 18980 := by decide

end HeritageFinite
