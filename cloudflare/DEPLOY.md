# Cloudflare onboarding (staged)

Deployment of the Khipu Scholar product on Cloudflare is staged in this repo:

1. **Front end (Cloudflare Pages)**: `frontend/index.html` is a static, no-build page.
   - `npx wrangler pages deploy frontend --project-name khipu-scholar` (owner-gated).
2. **Back end (API)**: `server/app.py` (FastAPI) reads the runs/corpus repositories.
   - Run it on the estate's edge infra with `HF_TOKEN` in the environment.
   - `cloudflare/worker.js` is a GET-only proxy to the API origin.
3. **Owner-gated estate items** (not automatable from this repo, by doctrine):
   - Cloudflare dashboard billing/charging setup.
   - DNS records (szlholdings.si / a-11-oy.com zones).
   - Zero Trust access policies.
   - PyPI trusted-publisher configuration for `szl-khipu-scholar`.

Monetization path (staged): metered inference through the estate's x402
pattern (see [szl-inference-gateway](https://github.com/szl-holdings/szl-inference-gateway));
receipts-verification API tiers; corpus/QA tooling support.
