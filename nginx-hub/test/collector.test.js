'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeApp, login, fakeDashboard, GOOD_SUMMARY } = require('./helpers');

const P = '/api/hub/v1';
const PW = 'correct horse battery';
const TOKEN = 'hubt_' + 'a'.repeat(30);

async function setup(t, dashOpts, cfgOverrides) {
  const env = await makeApp(cfgOverrides); t.after(() => env.app.stop());
  await env.users.create({ username: 'root', password: PW, role: 'admin' });
  env.a = (await login(env.base, 'root', PW)).c;
  env.dash = await fakeDashboard({ token: TOKEN, summary: GOOD_SUMMARY, ...dashOpts }); t.after(() => env.dash.close());
  const created = await env.a.post(`${P}/instances`, { name: 'Paris', url: env.dash.url });
  env.id = created.json.instance.id;
  await env.a.post(`${P}/instances/${env.id}/rotate-token`, { token: TOKEN });
  return env;
}

test('collecte nominale : token envoyé, résumé assaini (champs inconnus ignorés), historique alimenté', async (t) => {
  const { a, id, dash } = await setup(t);
  const r = await a.post(`${P}/instances/${id}/refresh`);
  assert.equal(r.status, 200);
  assert.equal(r.json.status, 'online');
  assert.equal(dash.hits[0].token, TOKEN);
  assert.equal(r.json.summary.version, '12.74.0');
  assert.equal(r.json.summary.humans, 1000);
  assert.equal(r.json.summary.alerts_critical, 1);
  assert.equal(r.json.summary.components.waf, 'degraded');
  assert.ok(!('champ_futur' in r.json.detail), 'champ inconnu non conservé');
  assert.equal(r.json.consecutive_failures, 0);
  const h = await a.get(`${P}/instances/${id}/history?range=24h`);
  assert.equal(h.json.points.length, 1);
  assert.equal(h.json.points[0].up, 1);
});

test('nginx arrêté ou composant « down » → dégradé', async (t) => {
  const bad = { ...GOOD_SUMMARY, nginx: { status: 'stopped' } };
  const { a, id } = await setup(t, { summary: bad });
  assert.equal((await a.post(`${P}/instances/${id}/refresh`)).json.status, 'degraded');
});

test('mauvais token → auth_failed ; hors ligne après N échecs consécutifs ; retour en ligne', async (t) => {
  const { a, id, dash, app } = await setup(t, {}, { collector: { offline_after_failures: 2 } });
  await a.post(`${P}/instances/${id}/rotate-token`, { token: 'hubt_' + 'b'.repeat(30) });
  let r = await a.post(`${P}/instances/${id}/refresh`);
  assert.equal(r.json.last_error, 'auth_failed'); assert.equal(r.json.status, 'unknown');
  r = await a.post(`${P}/instances/${id}/refresh`);
  assert.equal(r.json.status, 'offline'); assert.equal(r.json.consecutive_failures, 2);
  await a.post(`${P}/instances/${id}/rotate-token`, { token: TOKEN });
  r = await a.post(`${P}/instances/${id}/refresh`);
  assert.equal(r.json.status, 'online'); assert.equal(r.json.consecutive_failures, 0);
  assert.ok(dash.hits.length >= 3);
  const ov = await a.get(`${P}/overview`);
  assert.equal(ov.json.counts.online, 1);
  assert.equal(ov.json.totals.humans, 1000);
  assert.equal(ov.json.alerts[0].severity, 'critical');
  void app;
});

test('SSRF : aucune redirection suivie', async (t) => {
  const { a, id, app, dash } = await setup(t);
  // on pointe l'instance vers un chemin qui redirige : le fetcher n'interroge que /api/hub/summary ;
  // on simule donc une redirection côté résumé
  await dash.close();
  const redir = require('node:http').createServer((q, s) => { s.writeHead(302, { Location: 'http://127.0.0.1:1/' }); s.end(); });
  await new Promise((r) => redir.listen(0, '127.0.0.1', r));
  t.after(() => { redir.close(); redir.closeAllConnections(); });
  await app.ctx.db.run('UPDATE instances SET base_url = ? WHERE id = ?', [`http://127.0.0.1:${redir.address().port}`, id]);
  const r = await a.post(`${P}/instances/${id}/refresh`);
  assert.equal(r.json.last_error, 'redirect_refused');
});

test('réponses hostiles : trop volumineuse, JSON invalide, schéma absent, délai dépassé', async (t) => {
  const cases = [
    [{ summary: JSON.stringify({ schema: 1, pad: 'x'.repeat(5000) }) }, { collector: { max_response_bytes: 4096 } }, 'too_large'],
    [{ summary: '{pas du json' }, {}, 'bad_json'],
    [{ summary: { vhosts: { count: 1 } } }, {}, 'bad_schema'],
    [{ summary: GOOD_SUMMARY, delayMs: 1500 }, { collector: { timeout_ms: 500 } }, 'timeout'],
    [{ summary: GOOD_SUMMARY, headers: { 'Content-Type': 'text/html' } }, {}, 'bad_content_type'],
  ];
  for (const [dashOpts, cfg, expected] of cases) {
    const { a, id } = await setup(t, dashOpts, cfg);
    const r = await a.post(`${P}/instances/${id}/refresh`);
    assert.equal(r.json.last_error, expected, expected);
  }
});

test('adresse interne bloquée par la politique réseau au moment de la collecte', async (t) => {
  const { a, id, app } = await setup(t);
  app.ctx.config.security.allow_private_networks = false; // durcissement après coup
  const r = await a.post(`${P}/instances/${id}/refresh`);
  assert.equal(r.json.last_error, 'blocked_url');
});

test('purge de rétention', async (t) => {
  const { a, id, app } = await setup(t);
  await a.post(`${P}/instances/${id}/refresh`);
  await app.ctx.db.run('UPDATE samples SET ts = ?', [Date.now() - 40 * 86400e3]);
  const res = await app.ctx.services.get('instances').purge(30);
  assert.equal(res.samples, 1);
});

test('mapNetError : adresse privée vs réservée distinguées', async () => {
  const __test = require('../features/collector/fetcher.js');
  if (!__test || !__test.mapNetError) return;
  assert.equal(__test.mapNetError({ code: 'HUB_PRIVATE_ADDRESS' }).code, 'private_address');
  assert.equal(__test.mapNetError({ code: 'HUB_BLOCKED_ADDRESS' }).code, 'blocked_address');
});
