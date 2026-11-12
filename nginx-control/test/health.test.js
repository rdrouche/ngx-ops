'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Router, send } = require('../lib/http');
const H = require('../lib/health');
const feature = require('../features/health');

const ok = (json) => ({ status: 200, json });

test('interpret : réponse absente ou illisible = unknown, jamais ok', () => {
  assert.equal(H.interpret(() => 'ok', null), 'unknown');
  assert.equal(H.interpret(() => 'ok', { status: 500, json: {} }), 'unknown');
  assert.equal(H.interpret(() => 'ok', { status: 200, json: null }), 'unknown');
  assert.equal(H.interpret(() => { throw new Error('x'); }, ok({})), 'unknown');
  assert.equal(H.interpret(() => 'n_importe_quoi', ok({})), 'unknown');
});

test('evaluate : composants désactivés ne dégradent pas ; composant activé en panne = degraded ; nginx down = down', () => {
  const results = {
    '/api/analyzer/status': ok({ enabled: true, reachable: true, container: { running: true } }),
    '/api/waf/status': ok({ enabled: false }),
    '/api/challenge/status': ok({ enabled: true, container: { running: true } }),
    '/api/crowdsec/status': ok({ configured: false }),
    '/api/logstore/status': ok({ read: { enabled: true }, store: { reachable: true }, shipper: { enabled: true, container: { running: false } } }),
    '/api/redis/status': ok({ enabled: false }),
  };
  let r = H.evaluate({ nginxUp: true, results });
  assert.deepEqual(r.components, { dashboard: 'ok', nginx: 'ok', analyzer: 'ok', waf: 'disabled', challenge: 'ok', crowdsec: 'disabled', log_store: 'ok', shipper: 'down', redis: 'disabled' });
  assert.equal(r.status, 'degraded');
  results['/api/logstore/status'] = ok({ read: { enabled: false }, shipper: { enabled: false } });
  assert.equal(H.evaluate({ nginxUp: true, results }).status, 'ok');
  assert.equal(H.evaluate({ nginxUp: false, results }).status, 'down');
  assert.equal(H.evaluate({ nginxUp: true, results: {} }).status, 'ok', 'statuts illisibles = unknown, pas une panne');
});

test('publicView : un seul champ ; 200 ok/degraded, 503 down', () => {
  assert.deepEqual(H.publicView('ok'), { code: 200, body: { status: 'ok' } });
  assert.deepEqual(H.publicView('degraded'), { code: 200, body: { status: 'degraded' } });
  assert.deepEqual(H.publicView('down'), { code: 503, body: { status: 'down' } });
});

function fakeRes() {
  const r = { code: null, headers: {}, body: '' };
  r.writeHead = (c, h) => { r.code = c; r.headers = h || {}; };
  r.end = (b) => { r.body = b || ''; };
  r.setHeader = () => {};
  return r;
}

test('GET /health : public, un seul champ, 404 si HEALTH_PUBLIC=false, 405 hors GET/HEAD, 503 si nginx down', async () => {
  const router = new Router();
  feature.register(router);
  feature.setDeps({ fetchVTS: async () => ({ ok: true }) });
  feature._reset();
  let res = fakeRes();
  assert.equal(await feature.maybeHandle({ method: 'GET' }, res, '/health'), true);
  assert.equal(res.code, 200); assert.deepEqual(JSON.parse(res.body), { status: 'ok' });
  assert.equal(await feature.maybeHandle({ method: 'GET' }, fakeRes(), '/autre'), false);
  res = fakeRes(); await feature.maybeHandle({ method: 'POST' }, res, '/health'); assert.equal(res.code, 405);
  feature.setDeps({ fetchVTS: async () => null }); feature._reset();
  res = fakeRes(); await feature.maybeHandle({ method: 'GET' }, res, '/health');
  assert.equal(res.code, 503); assert.deepEqual(JSON.parse(res.body), { status: 'down' });
  process.env.HEALTH_PUBLIC = 'false';
  try { res = fakeRes(); await feature.maybeHandle({ method: 'GET' }, res, '/health'); assert.equal(res.code, 404); }
  finally { delete process.env.HEALTH_PUBLIC; }
});

test('GET /api/health : permission requise ; états par composant sans détail technique', async () => {
  const router = new Router();
  router.get('/api/analyzer/status', async ({ res }) => send(res, 200, { enabled: true, reachable: true, container: { running: true, image: 'secret/image:1.2.3', id: 'abc' }, agent: { version: '9.9.9', path: '/data/x' } }));
  feature.register(router);
  feature.setDeps({ fetchVTS: async () => ({ ok: true }) }); feature._reset();
  const handler = router.match('GET', '/api/health');
  let res = fakeRes();
  await handler({ res, session: { username: 'v', role: 'none' } });
  assert.equal(res.code, 403);
  res = fakeRes();
  await handler({ res, session: { username: 'a', role: 'admin' } });
  assert.equal(res.code, 200);
  const body = JSON.parse(res.body);
  assert.equal(body.status, 'ok'); assert.equal(body.components.analyzer, 'ok'); assert.equal(body.components.nginx, 'ok');
  assert.ok(!/secret|1\.2\.3|9\.9\.9|\/data/.test(res.body), 'aucun détail technique');
});
