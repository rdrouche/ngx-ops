'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Router, send } = require('../lib/http');
const M = require('../lib/hub-modules');
const { callInternal } = require('../lib/hub-internal');

test('sanitize : secrets retirés, IP retirées/masquées sauf expose_ips, bornes', () => {
  const src = { name: 'x', apiToken: 'T', nested: { password: 'p', ip: '203.0.113.9', note: 'bloqué 198.51.100.7/32 hier', version: '1.24.0' },
    decisions: [{ value: '192.0.2.1', scenario: 'ssh-bf' }, { value: 'asn-123' }], big: Array.from({ length: 900 }, (_, i) => i) };
  const a = M.sanitize(src, false);
  const j = JSON.stringify(a);
  assert.ok(!/"T"|"p"|203\.0\.113|198\.51|192\.0\.2/.test(j), j);
  assert.equal(a.nested.version, '1.24.0'); assert.equal(a.decisions[1].value, 'asn-123'); assert.equal(a.big.length, 500);
  const b = M.sanitize(src, true);
  assert.equal(b.nested.ip, '203.0.113.9'); assert.equal(b.apiToken, undefined);
});

test('parseNginxV : version, TLS, modules', () => {
  const r = M.parseNginxV('nginx version: nginx/1.27.2\nbuilt with OpenSSL 3.0.15 3 Sep 2024\nconfigure arguments: --with-http_v2_module --with-http_ssl_module --add-dynamic-module=/src/vts');
  assert.equal(r.version, '1.27.2'); assert.equal(r.tls, 'OpenSSL 3.0.15 3 Sep 2024');
  assert.deepEqual(r.modules, ['with-http_v2_module', 'with-http_ssl_module', 'add-dynamic-module=/src/vts']);
});

test('callInternal : GET seulement, liste blanche, chemin inconnu', async () => {
  const router = new Router();
  router.get('/api/ok', async ({ res, session }) => send(res, 200, { who: session.username }));
  router.get('/api/boom', async () => { throw new Error('x'); });
  router.post('/api/ok', async ({ res }) => send(res, 200, {}));
  assert.deepEqual((await callInternal(router, '/api/ok')).json, { who: 'ngx-hub' });
  assert.equal((await callInternal(router, '/api/ok', { allow: new Set() })).status, 403);
  assert.equal((await callInternal(router, '/api/none')).status, 404);
  assert.equal((await callInternal(router, '/x')).status, 400);
  assert.equal((await callInternal(router, '/api/boom')).status, 500);
});

test('indicators : une IP vue par plusieurs sources est classée en tête', async () => {
  const router = new Router();
  const j = (p, o) => router.get(p, async ({ res }) => send(res, 200, o));
  j('/api/challenge/offenders', { offenders: [{ ip: '203.0.113.9', attempts: 40 }], bans: [{ ip: '203.0.113.9', until: 1 }] });
  j('/api/crowdsec/decisions', { decisions: [{ value: '203.0.113.9', scenario: 'http-probing' }, { value: '198.51.100.1', scenario: 'ssh' }] });
  j('/api/analyzer/waf/top-ips', { ips: [{ ip: '203.0.113.9', count: 5, blocked: 2 }] });
  const ctx = { router, analyzerApi: async (p) => p.startsWith('/api/alerts') ? { data: { alerts: [{ type: 'scan', severity: 'high', ts: 1, evidence: { ips: ['203.0.113.9'], vhost: 'a.fr' } }] } } : { data: { topIps: [{ ip: '203.0.113.9', hits: 12 }] } },
    instanceId: 'i', version: 'v', fetchVTS: async () => null, execNginx: async () => null, queryEvents: () => ({ events: [], total: 0 }) };
  const settings = { expose: M.MODULE_IDS, exposeIps: true };
  const r = await M.buildModule(ctx, 'indicators', new URLSearchParams('hours=24'), settings);
  assert.equal(r.status, 200);
  const top = r.body.data.indicators[0];
  assert.equal(top.ip, '203.0.113.9'); assert.ok(top.score >= 5, JSON.stringify(top));
  assert.deepEqual(top.kinds, ['alert', 'blocklist_hit', 'challenge_ban', 'challenge_fail', 'crowdsec', 'waf']);
  assert.equal(r.body.data.indicators.length, 2);
  assert.equal((await M.buildModule(ctx, 'indicators', new URLSearchParams(), { ...settings, exposeIps: false })).status, 403);
  assert.equal((await M.buildModule(ctx, 'indicators', new URLSearchParams(), { ...settings, expose: ['inventory'] })).status, 404);
});

test('indicators : les IP d\'une alerte de campagne (paires [ip, nb]) sont remontées avec leur règle (#83)', async () => {
  const router = new Router();
  const ctx = { router, analyzerApi: async (p) => p.startsWith('/api/alerts') ? { data: { alerts: [
    { type: 'forgejo_scraper', severity: 'high', ts: 5, evidence: { campaign: true, vhosts: ['forge.fr'], ips: [['198.51.100.7', 12], ['198.51.100.8', 3], ['pas-une-ip', 1]] } },
    { type: 'scan', severity: 'low', ts: 6, evidence: { ips: ['203.0.113.1'] } }] } } : null,
    instanceId: 'i', version: 'v', fetchVTS: async () => null, execNginx: async () => null, queryEvents: () => ({ events: [], total: 0 }) };
  const r = await M.buildModule(ctx, 'indicators', new URLSearchParams('hours=24'), { expose: M.MODULE_IDS, exposeIps: true });
  const by = Object.fromEntries(r.body.data.indicators.map((x) => [x.ip, x]));
  assert.deepEqual(by['198.51.100.7'].kinds, ['campaign']);
  assert.equal(by['198.51.100.7'].sources[0].type, 'forgejo_scraper');
  assert.equal(by['198.51.100.7'].sources[0].hits, 12);
  assert.ok(by['198.51.100.8'] && !by['pas-une-ip']);
  assert.deepEqual(by['203.0.113.1'].kinds, ['alert'], 'les alertes classiques ne changent pas');
});
