'use strict';
// v12.75.0 — URL publique des blocklists.
const assert = require('assert'), path = require('path');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
let pub = { enable: true, token: 'abcdefghij0123456789', sources: ['all'] };
const stub = {
  getPublicSettings: () => pub,
  getPublicIps: name => name === 'all' ? { ok: true, ips: ['192.0.2.1', '198.51.100.0/24'], sources: ['a', 'b'] }
    : name === 'a' ? { ok: true, ips: ['192.0.2.1'], sources: ['a'] } : { ok: false, reason: 'unknown' },
};
const bpath = require.resolve('../features/blocklists');
require.cache[bpath] = { id: bpath, filename: bpath, loaded: true, exports: stub };
const P = require('../features/public-blocklist');
const call = (pathname, { method = 'GET', headers = {}, ip = '203.0.113.5' } = {}) => {
  const out = { code: 0, headers: {}, body: '' };
  const res = { writeHead(c, h) { out.code = c; out.headers = h || {}; }, end(b) { out.body = b || ''; } };
  const handled = P.maybeHandle({ method, headers }, res, pathname, ip);
  return { handled, ...out };
};
console.log('\nURL publique blocklist');
check('hors /public/ : non traite', () => assert.strictEqual(call('/api/x').handled, false));
check('jeton requis : 404 sans/avec mauvais jeton, 200 avec', () => {
  assert.strictEqual(call('/public/blocklist.txt').code, 404);
  assert.strictEqual(call('/public/wrongwrongwrongwrong/blocklist.txt').code, 404);
  const r = call('/public/abcdefghij0123456789/blocklist.txt');
  assert.strictEqual(r.code, 200);
  assert.ok(r.body.includes('192.0.2.1\n198.51.100.0/24\n'));
  assert.ok(/text\/plain/.test(r.headers['Content-Type']));
});
check('une source ; source inconnue 404 ; chemin invalide 404', () => {
  assert.strictEqual(call('/public/abcdefghij0123456789/blocklist/a.txt').code, 200);
  assert.strictEqual(call('/public/abcdefghij0123456789/blocklist/zz.txt').code, 404);
  assert.strictEqual(call('/public/abcdefghij0123456789/../etc/passwd').code, 404);
});
check('ETag -> 304', () => {
  const r = call('/public/abcdefghij0123456789/blocklist.txt');
  assert.strictEqual(call('/public/abcdefghij0123456789/blocklist.txt', { headers: { 'if-none-match': r.headers.ETag } }).code, 304);
});
check('sans jeton configure : /public/blocklist.txt accessible', () => {
  pub = { enable: true, token: '', sources: ['all'] };
  assert.strictEqual(call('/public/blocklist.txt').code, 200);
});
check('desactive : 404 partout ; methode POST : 404', () => {
  assert.strictEqual(call('/public/blocklist.txt', { method: 'POST' }).code, 404);
  pub = { enable: false, token: '', sources: ['all'] };
  assert.strictEqual(call('/public/blocklist.txt').code, 404);
});
check('limite de debit : 429 apres 60 requetes/min/IP', () => {
  pub = { enable: true, token: '', sources: ['all'] }; P._resetRate();
  let last; for (let i = 0; i < 62; i++) last = call('/public/blocklist.txt', { ip: '198.51.100.99' });
  assert.strictEqual(last.code, 429);
});
console.log(`\n${pass} ok, ${fail} ko`); process.exit(fail ? 1 : 0);
