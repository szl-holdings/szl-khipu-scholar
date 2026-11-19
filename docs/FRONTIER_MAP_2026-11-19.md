<!-- SPDX-License-Identifier: Apache-2.0
(c) 2026 Lutar, Stephen P. - SZL Holdings - ORCID 0009-0001-0110-4173 -->

# Frontier map, 2026-11-19: who leads, where we stand, what to adapt

Five fields, each researched from primary sources (cloned repositories, specifications,
PyPI metadata; most web hosts were blocked from the research container, so search
snippets are marked as such in the agents' notes). Items I re-checked myself are marked
**[re-checked]**. Everything else is REPORTED by the research agents. Energy measurement
and governed agent execution were not covered in this round.

Every adaptation below is CPU work. None of it needs Salad or any GPU.

## 1. Signed receipts and transparency logs

**Leaders.** The C2SP tiled-log stack (tlog-tiles v1.0.0; checkpoint, cosignature and
witness specs v1.1.0), run in production by transparency-dev Tessera (v1.0.4), Sigsum
(v1.0.0, two logs, 2-of-3 witness quorum) and Certificate Transparency's static-ct-api.
Sigstore Rekor v2 is GA but opt-in; the public default still points at Rekor v1. IETF COSE
Receipts are RFC 9942 (June 2026). The C2SP witness network has no production tier yet.

**Our position.** The control plane signs every receipt (200 of 200 verified against the
pinned estate key **[re-checked]**). It is a linear SHA-256 chain: checking one receipt
means walking all ~74,000. There are no checkpoints, no inclusion or consistency proofs and
no witness. Training-lane receipts are self-keyed, so they are not tamper-evident to an
outsider **[re-checked; fixed in the verifier, szl-khipu-scholar#14]**.

**Adapt (in order).**
1. **Endorse lane keys** (Fulcio pattern, SPIRE-style one-time join token). The dispatcher
   issues a single-use token; the lane proves possession of its boot key; the control
   plane signs an in-toto "lane-key-endorsement" with an expiry. Then a verifier needs
   only the estate key. M. Label when shipped: MEASURED for the signature chain; execution
   integrity on rented GPUs stays NOT CLAIMED.
2. **Tiled log over the existing chain.** Backfill the 74k receipts as RFC 6962 leaves of
   (sequence, receipt hash, PAE hash, kind), sign checkpoints, serve tiles and offline
   proof files, and sign one migration receipt binding the old chain head. M. Without
   independent witnesses, split views remain possible; do not claim otherwise.
3. **Lane receipts as DSSE, append-only and digest-named**, each naming the previous
   digest. S. Plainly modest: it is what leaders already do.
4. **Witnessing now** by anchoring checkpoint hashes in Sigsum under its vetted policy.
   S. Our twist is modest; Sigsum's witnesses vouch for Sigsum's tree, not ours.

**Do not claim.** Lane receipts AUTHORIZED or verified before endorsement ships; the
control-plane chain as a Merkle or transparency log; witnessing by an estate-run witness;
post-quantum protection; Hub commit history as an audit log.

## 2. Model signing and training attestation

**Leaders.** OpenSSF Model Signing (OMS) v1.0 with a 92-test conformance suite (DSSE plus
an in-toto Statement; per-file SHA-256 manifest); used by NVIDIA NGC and Kaggle and
referenced by CoSAI. The reference library, model-signing 1.1.1, is still marked Alpha,
and important verification fixes are unreleased. The Hugging Face Hub does not verify
model signatures.

**Our position.** Adapter weights are unsigned. Completion receipts do not bind the
adapter's file hash, base-model revision or dataset revision **[re-checked]**. OMS accepts
only P-256/384/521 keys, so the current ed25519 lane keys cannot sign OMS bundles.

**Adapt.** Lanes generate P-256 boot keys (so one endorsed key can also OMS-sign), sign the
adapter directory after training, and record the OMS root digest and Hub commit in the
completion receipt. The release step re-verifies the bundle at that exact revision and
the estate signs a verification-result statement. M. Label: MEASURED for adapter
integrity; training provenance stays SAMPLE (self-attested on untrusted hardware).

**Do not claim.** That a weight signature proves how the model was trained; SLSA Build
L2/L3 for adapters; TEE or hardware-attested training; Sigstore keyless signing for lanes.

## 3. Fine-tuning on interruptible GPUs without crash-loops

**Leaders.** SkyPilot managed jobs and dstack retry infrastructure faults but not user-code
failures, and never retry configuration or auth failures. Salad's own Kelpie caps failures
at 3 per job. Salad keeps the desired replica count, so a deterministic failure becomes an
unbounded paid loop unless something outside the container stops the group. Leaders build
from digest-pinned images and resolve torch, torchvision and torchaudio together into one
hash lock.

**Root causes behind our four crash classes (REPORTED).**
- TRL argument: `SFTConfig(max_seq_length=)` was removed in TRL 0.20.0 (2025-07-29); use
  `max_length`. Live distill launch commands still passed `max_seq_length` on 2026-11-19
  (REPORTED).
- torch/torchvision: TRL 1.17.0 added a hard `torch >= 2.6.0` requirement, so installing it
  over an older image upgrades torch under torchvision. The Salad image base (torch 2.6) has
  no sm_120 kernels, so it cannot run on RTX 5090. torch 2.8.0 is the first PyPI-default
  wheel with sm_120; Salad's recommended RTX 50xx image is
  `pytorch/pytorch:2.11.0-cuda12.8-cudnn9-runtime`.
- Missing split: the worker already falls back; a dispatch-time check would stop it before
  a GPU is billed.
- 401: the worker checks only that a token is present, not that it is valid or scoped.

**Already in szl-gpu-bridge.** Constructor-bound TRL length argument, a pinned-runtime API
contract test, GPU-arch admission with a BF16 smoke test, dataset fallbacks, verified
resume, and a read-only fleet witness.

**Adapt (in order).**
1. **Dispatch preflight on CPU** before any paid GPU: token validity and scope, dataset
   split and schema at a pinned revision via the worker's own serializer, and base-model
   config. M.
2. **Image-bound build preflight**: digest-pinned base, hash-locked overlay that excludes
   torch, `pip check`, and the existing contract test run inside `docker build`. M.
3. **Crash-loop breaker**: give every exit an explicit failure class and stop a group after
   N identical deterministic exits. Read-only detection first; automated stop authority is
   a doctrine change for the owner. S to M.
4. **Hub write budget**: batch heartbeats and receipts per lane per window, with jittered,
   RateLimit-aware backoff. M.

**Do not claim.** That a green CPU preflight proves GPU execution or memory fit; vendor
speed-up numbers (for example Unsloth's) for our lanes; that any untested stack is
validated.

## 4. Certifying computational mathematics

**Leaders and norms.** Exact arithmetic, re-runnable certificates, a second implementation
by someone else or by a different method, and kernel-checked statements where feasible.
The Lean manual's escalating trust ladder ends at `lake comparator`; `native_decide` adds
compiler trust and is rejected by Mathlib. Competition-level formal proving is saturated
(PutnamBench solved by several systems in 2026). Research-level AI is real but uneven, and
disclosure of AI assistance is now expected.

**Our position.** The hjo_loom certificate replays byte-identically (`REPLAY_MATCH`,
~71 s on one core, now with the standard library only) **[re-checked]**. Two algorithms
in one codebase agree on all 396 admitted cylindric inputs **[re-checked]**. Huang's
Theorem 1.2, as formalized by AxiomMath (`RationalDinv.bilinForm_eq_crossDinv`, statement
author-verified), covers the cross terms for all pairs with no containment hypothesis;
its D = E case is Theorem 1.1 **[re-checked: names and statement in the clones]**.

**Adapt (what to answer when asked "where is it going?").**
1. **Quot_m^R(R^n) census over F_q**: the free-module case HJO conjecture about, outside
   their Theorem 1.2. First validate against the Huang-Jiang closed formulas for y^2 = x^m,
   and ask the authors which normalization they want before computing new rows. M, CPU.
2. **Multi-q sweeps** (add GF(4), GF(9), q = 5, 7) to recover polynomials in q rather than
   single values. S to M, CPU.
3. **Make it checkable**: METHOD.md (done, szl-khipu#152), a standalone Zenodo bundle, a
   `computation.yaml` disclosure, and a second implementation by someone else. S.
4. **Optional Lean**: a kernel-checked statement for the smallest census rows. L.

**Do not claim.** That any model was trained or discovered anything here; a new theorem;
"independent replication"; "Lean-verified" counts; any GPU benefit for exact enumeration.

## 5. Computational khipu scholarship

**Leaders.** The Open Khipu Repository (MIT licence; v2.1.0, DOI 10.5281/zenodo.18025748;
an Advisory Board oversees data releases and KH numbers, not outside research), the Khipu
Field Guide as the corrected layer, and published work by Urton, Medrano, Clindaniel,
Hyland and others. For ML on ancient texts, Ithaca and Aeneas set the standard: bounded
tasks with ground truth, historian-in-the-loop evaluation and explicit non-claims.

**Our position (REPORTED).** A careful but unreviewed re-analysis of one transcription,
not a leader. Strengths include byte-pinned inputs and pre-specified tests with permutation
nulls. Gaps: no peer-reviewed output; one transcription layer (a 2026 third-party audit
reports about 3% of aligned pendant values differ from the Field Guide); the null model
choice (the top-cord effect roughly halves under a structure-preserving shift); and
physical completeness. In the pinned `khipu.db` **[re-checked]**, 42% of cords have no fibre
code, 436 of 633 primary cords have thickness 0, attachment position is recorded for 3 of
38,854 level-1 cords, and 221 of 619 records lack provenance.

**Adapt.**
1. Replication-first manuscript for a journal with a data and code policy (Advances in
   Archaeological Practice offers a reproducibility review; Latin American Antiquity
   requires a data availability statement).
2. Cross-check every result against the Field Guide layer, and report a structure-preserving
   null alongside the shuffle null.
3. Put the verified limitations statement on every khipu model and dataset card (drafted
   for the two adapters; blocked on Hugging Face write scope).

**Do not claim.** Decipherment; review or endorsement by the OKR board or anyone who
replied; anything that speaks for Andean communities. Do not re-contact anyone who declined.
