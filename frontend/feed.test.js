// SPDX-License-Identifier: Apache-2.0
// (c) 2026 Lutar, Stephen P. - SZL Holdings - ORCID 0009-0001-0110-4173
// Run with: node --test frontend/feed.test.js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const feed = require('./feed.js');

const PAGE = 'https://explorer.example.org/index.html';

test('data: and other schemes are refused', () => {
  const forged = 'data:application/json,{"receipts":[]}#';
  assert.equal(feed.resolveFeed(forged, PAGE, []).ok, false);
  assert.equal(feed.resolveFeed(forged, PAGE, []).reason, 'SCHEME_NOT_ALLOWED');
  assert.equal(feed.resolveFeed('javascript:alert(1)', PAGE, []).ok, false);
  assert.equal(feed.resolveFeed('file:///etc/passwd', PAGE, []).ok, false);
});

test('third-party origins are refused unless the page declares them', () => {
  const other = 'https://attacker.example.net';
  assert.equal(feed.resolveFeed(other, PAGE, []).reason, 'ORIGIN_NOT_ALLOWED');
  const declared = feed.declaredOrigins('https://attacker.example.net/ https://api.example.org');
  assert.equal(feed.resolveFeed(other, PAGE, declared).ok, true);
});

test('same origin and loopback are allowed; the feed path is fixed', () => {
  assert.equal(feed.resolveFeed('/api/', PAGE, []).feedUrl, 'https://explorer.example.org/api/receipts');
  const local = feed.resolveFeed('http://127.0.0.1:8787?x=1#frag', PAGE, []);
  assert.equal(local.ok, true);
  assert.equal(local.feedUrl, 'http://127.0.0.1:8787/receipts');
  assert.equal(feed.resolveFeed('http://localhost:8787', 'file:///tmp/index.html', []).ok, true);
  assert.equal(feed.resolveFeed(null, PAGE, []).reason, 'MISSING');
});

test('AUTHORIZED only when every field agrees', () => {
  const good = { verdict: 'AUTHORIZED', signature: 'VALID', key_state: 'PINNED', file_matches_receipt: true };
  assert.equal(feed.displayVerdict(good), 'AUTHORIZED');
  for (const [k, v] of [['signature', 'INVALID'], ['key_state', 'UNPINNED'],
    ['file_matches_receipt', false], ['file_matches_receipt', undefined],
    ['verdict', 'AUTHORIZED" onmouseover="x']]) {
    assert.equal(feed.displayVerdict({ ...good, [k]: v }), 'OBSERVED', k);
  }
  assert.equal(feed.displayVerdict(null), 'OBSERVED');
});

test('cells are plain text, whatever the receipt holds', () => {
  const cells = feed.rowCells({ file: 'f', node: { toString: 'x' }, type: '<img src=x onerror=alert(1)>',
    signature: 7, key_state: null });
  assert.deepEqual(cells, ['f', '{"toString":"x"}', '<img src=x onerror=alert(1)>', '7', '', 'OBSERVED']);
  const cyclic = {}; cyclic.self = cyclic;
  assert.equal(feed.cellText(cyclic), '[unrenderable]');
  assert.equal(feed.cellText(() => 1), '');
});

test('an unavailable trust root is said plainly', () => {
  const note = feed.feedNote({ repo: 'r', receipts: [], trust_root: { state: 'UNAVAILABLE', error: 'e' } }, 'o');
  assert.match(note, /Trust root unavailable/);
  assert.match(feed.feedNote({ repo: 'r', receipts: [{}], trust_root: { state: 'LOADED', pinned_nodes: 2 } }, 'o'),
    /against 2 pinned lane/);
});
