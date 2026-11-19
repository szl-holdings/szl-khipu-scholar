// SPDX-License-Identifier: Apache-2.0
// (c) 2026 Lutar, Stephen P. - SZL Holdings - ORCID 0009-0001-0110-4173
//
// Decisions the explorer makes about the receipts feed, kept free of the DOM so
// they can be tested with `node --test`. Receipt fields come from files anyone
// with write access to the runs repository can author: everything here returns
// plain text, and the page renders it with textContent only.
(function (root) {
  'use strict';

  const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);

  // The page may name extra API origins in <meta name="khipu-api-origins">.
  function declaredOrigins(content) {
    return String(content || '').split(/\s+/).filter(Boolean).map((s) => {
      try { return new URL(s).origin; } catch (e) { return null; }
    }).filter(Boolean);
  }

  // Resolve ?api= to a feed URL, or refuse. Only http(s) URLs on the page's own
  // origin, a loopback host, or a declared origin are used: a data: URL or a
  // third-party origin could otherwise put forged verdicts under this page.
  function resolveFeed(param, pageHref, declared) {
    if (!param) return { ok: false, reason: 'MISSING' };
    let url;
    try { url = new URL(param, pageHref); } catch (e) { return { ok: false, reason: 'UNPARSEABLE' }; }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { ok: false, reason: 'SCHEME_NOT_ALLOWED', origin: url.protocol };
    }
    let pageOrigin = null;
    try { pageOrigin = new URL(pageHref).origin; } catch (e) { pageOrigin = null; }
    const allowed = url.origin === pageOrigin || LOOPBACK.has(url.hostname) ||
      (declared || []).includes(url.origin);
    if (!allowed) return { ok: false, reason: 'ORIGIN_NOT_ALLOWED', origin: url.origin };
    const base = url.origin + url.pathname.replace(/\/+$/, '');
    return { ok: true, origin: url.origin, feedUrl: base + '/receipts' };
  }

  // AUTHORIZED is shown only when every field the server reports agrees.
  function displayVerdict(row) {
    return row && row.verdict === 'AUTHORIZED' && row.signature === 'VALID' &&
      row.key_state === 'PINNED' && row.file_matches_receipt === true
      ? 'AUTHORIZED' : 'OBSERVED';
  }

  function cellText(value) {
    if (typeof value === 'string') return value;
    if (value === null || value === undefined) return '';
    try {
      const s = JSON.stringify(value);
      return typeof s === 'string' ? s : '';
    } catch (e) {
      return '[unrenderable]';
    }
  }

  function rowCells(row) {
    const r = row && typeof row === 'object' ? row : {};
    return [r.file, r.node, r.type, r.signature, r.key_state].map(cellText)
      .concat([displayVerdict(r)]);
  }

  function feedNote(data, origin) {
    const d = data && typeof data === 'object' ? data : {};
    const count = Array.isArray(d.receipts) ? d.receipts.length : 0;
    const tr = d.trust_root && typeof d.trust_root === 'object' ? d.trust_root : {};
    const head = count + ' receipts from ' + cellText(d.repo) + ' via ' + cellText(origin) + '. ';
    if (tr.state !== 'LOADED') {
      return head + 'Trust root unavailable on the server' +
        (tr.error ? ' (' + cellText(tr.error) + ')' : '') + ': nothing can be AUTHORIZED.';
    }
    const pinned = Number.isInteger(tr.pinned_nodes) ? tr.pinned_nodes : 0;
    return head + 'Verified by that server against ' + pinned + ' pinned lane(s). ' +
      'AUTHORIZED means signed by a pinned lane key; a receipt that only matches the key it carries is OBSERVED.';
  }

  const api = { declaredOrigins, resolveFeed, displayVerdict, cellText, rowCells, feedNote };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.KhipuFeed = api;
})(typeof window !== 'undefined' ? window : globalThis);
