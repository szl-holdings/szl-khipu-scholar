// Minimal pass-through proxy for the Khipu Scholar API (GET only).
// Owner-gated: set KHIPU_API_ORIGIN in wrangler vars or CF dashboard.
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method !== "GET") return new Response("GET only", { status: 405 });
    const target = env.KHIPU_API_ORIGIN + url.pathname;
    const r = await fetch(target);
    const body = await r.text();
    return new Response(body, { status: r.status, headers: { "content-type": "application/json", "access-control-allow-origin": "*" } });
  },
};
