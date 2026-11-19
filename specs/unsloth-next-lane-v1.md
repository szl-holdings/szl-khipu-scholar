# Unsloth next training lane - spec v1

**Status: SPEC, NOT SCHEDULED.** This lane fires only after all of:
1. khipu-scholar-4b completes with a signed complete receipt,
2. the scholar eval lane produces its eval receipts for both adapters,
3. the smoke test below passes with honest measured receipts.

Nothing in this spec disturbs the in-flight 4b lane (TRL). Upgrade for the *next* lane only - doctrine: never rewire mid-run.

## Why Unsloth

The 2026-07 fine-tuning framework comparison ([MarkTechPost](https://www.marktechpost.com/2026/07/22/unsloth-vs-axolotl-vs-trl-vs-llama-factory-a-fine-tuning-framework-comparison-on-speed-vram-and-multi-gpu/)) measures Unsloth ahead of Axolotl/TRL/Llama-Factory on single-GPU throughput and VRAM. Full citation lives in `codices/README.md` (field-leaders table, PR #11). The estate adopts it as the throughput leg of the field-leader upgrade; the provenance leg (ML-BOMs + CoSAI model-signing) is already live.

## Proposed lane: szl-train-khipu-scholar-v2-unsloth

| Item | Value |
|---|---|
| Base | largest Qwen3 base that fits lane VRAM after the smoke test measures headroom |
| Dataset | SZLHOLDINGS/khipu-scholars-sft-v1 (corpus sha256 0a32769c0d56f11510abdf4f7e83dfaacabc99db3284384b6cf690abf42f7e43, pinned) |
| LoRA | r=32, alpha=64, dropout 0.05, same 7 target modules as the TRL lanes (comparability) |
| Train | 2000 steps, bf16, cosine, lr 2e-4, warmup 3% |
| Image | official Unsloth image at build time; fallback: pip install unsloth on the proven pytorch 2.14.1-cuda12.6 image |
| Receipts | identical DSSE machinery, doctrine szl-mesh v11 LOCKED 749/14/163, fail closed |
| Resilience | the v1.3 pattern is now MANDATORY for every training lane: checkpoint sync to the runs repo every 200 steps, resume-from-latest on boot, post-complete cleanup, park watcher armed before fire |

## Smoke test: szl-smoke-unsloth-v1 (gate, ~1.5 GPU-h)

Bound: 20 steps, one small GPU class, then park. All five must pass with signed receipts:
1. Unsloth imports + kernels load on the Salad image.
2. 20 steps, no NaN, loss decreases from a sane baseline.
3. DSSE state receipts seq correctly and verify.
4. Checkpoint sync to hub works and resume round-trips.
5. Honest s/step measurement recorded next to the current 72 s/step TRL baseline. Only a measured win promotes the spec to a lane; a null result is recorded and the lane is not created.

## Honesty constraints

No decipherment claims. No throughput claims without the smoke-test receipt. Capacity waits queue honestly (free tier). Any crash posts a signed crash receipt before the lane dies. Budget is Salad GPU spend, owner-pre-authorized for lane work.
