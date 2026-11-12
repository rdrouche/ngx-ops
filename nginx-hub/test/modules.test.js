'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { makeApp, client } = require('./helpers');
const { clean, normAlert, normEnvelope } = require('../features/modules/sanitize');
const { correlate } = require('../features/modules/correlate');

const P = '/api/hub/v1';
const PW = 'correct horse battery';
const TOKEN = 'T'.repeat(24);

/** Faux dashboard 12.78.0 : alerts (sinceId/order/acked), modules en enveloppe, indicators (403 sans expose_ips), 404 sur ce qui est retiré. */
function fakeDash({ alerts = [], exposeIps = false, absent = [], modules = {}, acked = [] } = {}) {
  const calls = [];
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    calls.push(req.url);
    const json = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
    if (req.headers['x-hub-token'] !== TOKEN) return json(401, {});
    const m = /^\/api\/hub\/v1\/([a-z]+)$/.exec(u.pathname);
    if (!m) return json(404, {});
    const name = m[1];
    if (absent.includes(name)) return json(404, {});
    if (name === 'alerts') {
      const since = Number(u.searchParams.get('sinceId') || 0); const limit = Number(u.searchParams.get('limit') || 100);
      let list = alerts.filter((a) => a.id > since).map((a) => ({ ...a, acked: acked.includes(a.id) }));
      if (u.searchParams.get('acked') === '1') list = list.filter((a) => a.acked);
      if (u.searchParams.get('order') === 'asc') list.sort((a, b) => a.id - b.id); else list.sort((a, b) => b.id - a.id);
      if (!exposeIps) list = list.map(({ ips, ...r }) => r);
      return json(200, { schema: 1, expose_ips: exposeIps, reachable: true, total: alerts.length, count: Math.min(limit, list.length), alerts: list.slice(0, limit) });
    }
    if (name === 'indicators' && !exposeIps) return json(403, { error: 'expose_ips_disabled' });
    return json(200, { schema: 1, module: name, generated_at: new Date().toISOString(), instance: { id: 'srv-1' }, expose_ips: exposeIps, ...(modules[name] || { data: { ok: true } }) });
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ calls, url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => { srv.close(r); srv.closeAllConnections?.(); }) })));
}

async function setup(over = {}) {
  const env = await makeApp({ modules: { alerts_batch: 10 }, ...over });
  await env.users.create({ username: 'root', password: PW, role: 'admin' });
  await env.users.create({ username: 'lecteur', password: PW, role: 'viewer' });
  const admin = client(env.base); await admin.post(`${P}/auth/login`, { username: 'root', password: PW });
  const viewer = client(env.base); await viewer.post(`${P}/auth/login`, { username: 'lecteur', password: PW });
  const add = async (name, url) => (await admin.post(`${P}/instances`, { name, url, token: TOKEN })).json.instance;
  return { ...env, admin, viewer, add, mod: env.app.ctx.services.get('modules') };
}
const mkAlerts = (n, extra = {}) => Array.from({ length: n }, (_, i) => ({ id: i + 1, ts: 1_730_000_000_000 + i, type: 'bruteforce', severity: i % 2 ? 'high' : 'low', summary: `alerte ${i + 1}`, vhost: 'a.fr', country: 'FR', ip_count: 2, evidence: { n: i }, ...extra }));

test('sanitize : secrets retirés, IP retirées/masquées sans expose_ips, bornes, clés inconnues conservées', () => {
  const raw = { a: 1, api_token: 'x', nested: { password: 'p', keep: 'ok', ip: '1.2.3.4', msg: 'vu 203.0.113.9 et 2001:db8::1 à 12:30:45 v12.78.0' }, ips: ['1.1.1.1'], __proto__: { x: 1 }, futur: { x: 1 } };
  const c = clean(raw, false);
  assert.deepEqual(Object.keys(c).sort(), ['a', 'futur', 'nested']);
  assert.equal(c.nested.keep, 'ok'); assert.ok(!('ip' in c.nested)); assert.ok(!('password' in c.nested));
  assert.equal(c.nested.msg, 'vu [ip] et [ip] à 12:30:45 v12.78.0', 'heure et version non masquées');
  assert.equal(clean(raw, true).ips[0], '1.1.1.1');
  assert.equal(clean('x'.repeat(5000), true).length, 600);
  assert.equal(clean(Array.from({ length: 900 }, (_, i) => i), true).length, 500);
  let deep = { v: 1 }; for (let i = 0; i < 20; i++) deep = { d: deep };
  assert.ok(JSON.stringify(clean(deep, true)).length < 100, 'profondeur bornée');
  assert.equal(normAlert({ id: 0 }), null); assert.equal(normAlert({ id: 'x' }), null);
  const a = normAlert({ id: 5, ts: 1, type: 'scan', severity: 'high', summary: 'depuis 8.8.8.8', ips: ['8.8.8.8', 'pas-une-ip'], ip_count: 1, evidence: Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`k${i}`, 'x'.repeat(300)])) }, false);
  assert.equal(a.summary, 'depuis [ip]'); assert.equal(a.ips, null); assert.equal(a.evidence, '{"truncated":true}');
  assert.deepEqual(JSON.parse(normAlert({ id: 6, ips: ['8.8.8.8', 'zzz'] }, true).ips), ['8.8.8.8']);
  assert.equal(normEnvelope([]), null);
  assert.deepEqual(normEnvelope({ expose_ips: 'oui', data: { x: 1 }, errors: { waf_status: 'unavailable', 'Bad Key': 'x' } }), { expose_ips: false, errors: { waf_status: 'unavailable' }, data: { x: 1 } });
});

test('corrélation : campagne = ≥ 2 instances ou ≥ 3 kinds ; données périmées ignorées', () => {
  const mk = (id, ips, at) => ({ instance_id: id, name: `i${id}`, fetched_at: at, payload: JSON.stringify({ data: { indicators: ips } }) });
  const now = Date.now();
  const out = correlate([
    mk(1, [{ ip: '203.0.113.9', score: 2, kinds: ['alert', 'waf'] }, { ip: '198.51.100.1', score: 3, kinds: ['alert', 'waf', 'crowdsec'] }, { ip: 'pas-une-ip', kinds: ['alert'] }], now),
    mk(2, [{ ip: '203.0.113.9', score: 1, kinds: ['crowdsec'] }, { ip: '192.0.2.7', score: 1, kinds: ['alert'] }], now),
    mk(3, [{ ip: '192.0.2.7', score: 1, kinds: ['alert'] }], now - 3600e3),
  ], { maxAgeMs: 900e3, now });
  const by = Object.fromEntries(out.map((x) => [x.ip, x]));
  assert.equal(by['203.0.113.9'].campaign, true); assert.equal(by['203.0.113.9'].instances.length, 2); assert.deepEqual(by['203.0.113.9'].kinds.sort(), ['alert', 'crowdsec', 'waf']);
  assert.equal(by['198.51.100.1'].campaign, true, '3 kinds');
  assert.equal(by['192.0.2.7'].campaign, false, 'la 2e instance est périmée');
  assert.ok(!by['pas-une-ip']);
  assert.equal(out[0].campaign, true);
});

test('alertes : rattrapage par sinceId au-delà de la limite, aucun doublon, acquittements rafraîchis, IP absentes sans expose_ips', async (t) => {
  const e = await setup(); t.after(() => e.app.stop());
  const all = mkAlerts(25, { ips: ['203.0.113.9'] });
  const dash = await fakeDash({ alerts: all, acked: [3] }); t.after(() => dash.close());
  const inst = await e.add('Paris', dash.url);
  await e.mod.pollModule(await e.app.ctx.services.get('instances').get(inst.id), 'alerts');

  const r = (await e.admin.get(`${P}/alerts?limit=500`)).json;
  assert.equal(r.total, 25, '25 alertes malgré un lot de 10');
  assert.equal(new Set(r.items.map((a) => a.remote_id)).size, 25);
  assert.equal(r.items.find((a) => a.remote_id === 3).acked, true);
  assert.ok(r.items.every((a) => a.ip_count === 2));
  assert.ok(r.items.every((a) => !a.ips || a.ips.length === 0), 'pas d\'IP : expose_ips faux');
  assert.ok(!JSON.stringify((await e.viewer.get(`${P}/alerts`)).json).includes('203.0.113.9'));

  // 2e passage : seulement les nouvelles (sinceId)
  all.push(...mkAlerts(3).map((a, i) => ({ ...a, id: 26 + i })));
  dash.calls.length = 0;
  await e.mod.pollModule(await e.app.ctx.services.get('instances').get(inst.id), 'alerts');
  assert.match(dash.calls[0], /sinceId=25/); assert.match(dash.calls[0], /order=asc/);
  assert.equal((await e.admin.get(`${P}/alerts`)).json.total, 28);

  const f = (await e.admin.get(`${P}/alerts?severity=high&acked=0&limit=5`)).json;
  assert.ok(f.items.length <= 5 && f.items.every((a) => a.severity === 'high' && !a.acked));
  assert.equal((await e.admin.get(`${P}/alerts?instance=999`)).json.total, 0);
  assert.equal((await e.admin.get(`${P}/alerts?severity=%27%3Bdrop`)).status, 200, 'filtre invalide ignoré, pas d\'injection');
});

test('modules : enveloppe stockée, partie manquante ≠ zéro, secrets retirés, 404 = absent, erreur conserve la dernière valeur', async (t) => {
  const e = await setup({ modules: { alerts_batch: 10, list: ['alerts', 'inventory', 'security', 'reports'] } }); t.after(() => e.app.stop());
  const dash = await fakeDash({
    absent: ['reports'],
    modules: {
      inventory: { data: { certificates: { certificates: [{ domain: 'a.fr', days: 9 }], summary: { total: 1, expired: 0, warning: 1, ok: 0 } }, nginx: { running: true, connections: 4, api_token: 'zzz' }, futur: [1] }, errors: { agents: 'unavailable' } },
      security: { data: { waf_status: { enabled: true } }, errors: { crowdsec_status: 'unavailable', challenge_stats: 'error_500' } },
    },
  }); t.after(() => dash.close());
  const inst = await e.add('Paris', dash.url);
  await e.mod.tick();

  const list = (await e.admin.get(`${P}/instances/${inst.id}/modules`)).json;
  const st = Object.fromEntries(list.items.map((m) => [m.module, m]));
  assert.equal(st.inventory.status, 'ok'); assert.equal(st.reports.status, 'absent'); assert.equal(st.alerts.status, 'ok');
  assert.deepEqual(st.inventory.parts_errors, { agents: 'unavailable' });
  assert.deepEqual(list.enabled, ['alerts', 'inventory', 'security', 'reports']);

  const inv = (await e.viewer.get(`${P}/instances/${inst.id}/modules/inventory`)).json;
  assert.ok(!('agents' in inv.data), 'partie indisponible absente de data (jamais un zéro inventé)');
  assert.equal(inv.parts_errors.agents, 'unavailable'); assert.equal(inv.data.certificates.summary.warning, 1); assert.deepEqual(inv.data.futur, [1]);
  assert.ok(!JSON.stringify(inv).includes('zzz') && !('api_token' in inv.data.nginx));
  assert.equal((await e.viewer.get(`${P}/instances/${inst.id}/modules/reports`)).status, 200, 'ligne « absent » consultable');
  assert.equal((await e.viewer.get(`${P}/instances/${inst.id}/modules/nimporte`)).status, 404);
  assert.equal((await e.viewer.get(`${P}/instances/${inst.id}/modules/traffic`)).status, 404, 'non collecté');

  // dashboard injoignable → erreur normalisée, dernière charge utile conservée (affichée comme obsolète)
  await dash.close();
  await e.mod.refresh(inst.id);
  const after = (await e.viewer.get(`${P}/instances/${inst.id}/modules/inventory`)).json;
  assert.equal(after.status, 'error'); assert.equal(after.error, 'connection'); assert.equal(after.data.certificates.summary.total, 1, 'dernière valeur conservée');
});

test('indicateurs : désactivés par défaut ; opt-in + expose_ips : corrélation inter-instances, réservée aux admins, sans IP pour les autres', async (t) => {
  const off = await setup(); t.after(() => off.app.stop());
  assert.equal((await off.admin.get(`${P}/indicators`)).status, 404, 'opt-in Hub requis');
  const noIps = await fakeDash({ exposeIps: false }); t.after(() => noIps.close());
  const i0 = await off.add('Sans IP', noIps.url);
  await off.mod.tick();
  assert.ok(!(await off.admin.get(`${P}/instances/${i0.id}/modules`)).json.items.some((m) => m.module === 'indicators'), 'jamais interrogé tant que non activé');

  const e = await setup({ modules: { alerts_batch: 10, list: ['security'], indicators: { enabled: true } } }); t.after(() => e.app.stop());
  const mk = (ips) => ({ indicators: { data: { window_hours: 24, count: ips.length, indicators: ips } }, security: { data: { waf_top_ips: [{ ip: '203.0.113.9', hits: 5 }], waf_status: { enabled: true, note: 'bloqué 203.0.113.9' } } } });
  const d1 = await fakeDash({ exposeIps: true, modules: mk([{ ip: '203.0.113.9', score: 2, kinds: ['alert', 'waf'] }]) }); t.after(() => d1.close());
  const d2 = await fakeDash({ exposeIps: true, modules: mk([{ ip: '203.0.113.9', score: 1, kinds: ['crowdsec'] }, { ip: '192.0.2.7', score: 1, kinds: ['alert'] }]) }); t.after(() => d2.close());
  const d3 = await fakeDash({ exposeIps: false }); t.after(() => d3.close());
  const a = await e.add('A', d1.url); await e.add('B', d2.url); const c = await e.add('C', d3.url);
  await e.mod.tick();

  const r = (await e.admin.get(`${P}/indicators`)).json;
  assert.equal(r.items[0].ip, '203.0.113.9'); assert.equal(r.items[0].campaign, true); assert.equal(r.items[0].instances.length, 2);
  assert.equal(r.items.find((x) => x.ip === '192.0.2.7').campaign, false);
  assert.equal((await e.viewer.get(`${P}/indicators`)).status, 403);
  const stC = (await e.admin.get(`${P}/instances/${c.id}/modules`)).json.items.find((m) => m.module === 'indicators');
  assert.equal(stC.status, 'ips_disabled', '403 expose_ips_disabled normalisé');

  const adminSec = (await e.admin.get(`${P}/instances/${a.id}/modules/security`)).json;
  assert.equal(adminSec.expose_ips, true); assert.equal(adminSec.data.waf_top_ips[0].ip, '203.0.113.9');
  const viewerSec = (await e.viewer.get(`${P}/instances/${a.id}/modules/security`)).json;
  assert.ok(!JSON.stringify(viewerSec).includes('203.0.113.9'), 'viewer : IP retirées et masquées même si exposées');
  assert.equal(viewerSec.data.waf_status.note, 'bloqué [ip]');
  assert.equal((await e.viewer.get(`${P}/instances/${a.id}/modules/indicators`)).status, 403);
  const audit = (await e.admin.get(`${P}/audit`)).json.items;
  assert.ok(audit.some((x) => x.action === 'indicators.view'));
  assert.ok(!JSON.stringify(audit).includes('203.0.113.9'), 'aucune IP de visiteur dans l\'audit');
});

const { extractVhosts } = require('../features/modules/vhosts');
test('vhosts : extraction tolérante (blocs server, listes, maps), certificats (wildcard) et trafic joints', () => {
  const inv = {
    vhosts: { files: [{ file: 'sites/a.conf', servers: [{ server_name: 'www.a.fr a.fr', listen: [443], ssl: true, locations: [{ path: '/', proxy_pass: 'http://app:8080' }] }] },
      { file: 'sites/b.conf', servers: [{ server_names: ['b.fr', '_'], upstream: 'api:9000', enabled: true }] }] },
    certificates: { certificates: [{ domains: ['*.a.fr'], daysLeft: 9 }] },
  };
  const r = extractVhosts(inv, { vhosts: [{ name: 'a.fr', requests: 10, bytes: 2048 }] }, []);
  const by = Object.fromEntries(r.map((v) => [v.name, v]));
  assert.deepEqual(Object.keys(by).sort(), ['a.fr', 'b.fr', 'www.a.fr']);
  assert.equal(by['www.a.fr'].upstream, 'http://app:8080'); assert.equal(by['www.a.fr'].cert_days, 9); assert.equal(by['a.fr'].cert_days, undefined, '*.a.fr ne couvre pas a.fr');
  assert.equal(by['a.fr'].requests, 10); assert.equal(by['b.fr'].state, 'enabled'); assert.equal(by['www.a.fr'].listen, '443');
  assert.deepEqual(extractVhosts({ vhosts: { 'm.fr': { upstream: ['a:1', 'b:2'] }, 'n.fr': {} } }, null, []).map((v) => v.name), ['m.fr', 'n.fr']);
  assert.deepEqual(extractVhosts(null, null, [{ name: 't.fr', requests: 5 }]), [{ name: 't.fr', requests: 5 }]);
  assert.deepEqual(extractVhosts({ vhosts: 'n/a' }, null, []), [], 'forme inattendue : aucun plantage');
});

test('GET /vhosts : un même vhost sur plusieurs instances ; instances sans inventaire signalées ; viewer autorisé', async (t) => {
  const inv = { inventory: { data: { vhosts: [{ name: 'shared.fr', upstream: 'a:1' }, { name: 'only1.fr' }] } } };
  const e = await setup({ modules: { alerts_batch: 10, list: ['inventory', 'traffic'] } }); t.after(() => e.app.stop());
  const d1 = await fakeDash({ modules: inv }); t.after(() => d1.close());
  const d2 = await fakeDash({ modules: { inventory: { data: { vhosts: [{ name: 'shared.fr', upstream: 'b:2' }] } } } }); t.after(() => d2.close());
  const d3 = await fakeDash({ absent: ['inventory'] }); t.after(() => d3.close());
  const a = await e.add('A', d1.url); const b = await e.add('B', d2.url); const c = await e.add('C', d3.url);
  for (const i of [a, b, c]) await e.mod.refresh(i.id);
  const r = (await e.viewer.get(`${P}/vhosts`)).json;
  const shared = r.items.find((v) => v.name === 'shared.fr');
  assert.equal(shared.instance_count, 2); assert.deepEqual(shared.instances.map((i) => i.instance).sort(), ['A', 'B']);
  assert.equal(r.items.find((v) => v.name === 'only1.fr').instance_count, 1);
  assert.deepEqual(r.instances_missing.map((x) => x.name), ['C']);
  const mod = (await e.viewer.get(`${P}/instances/${a.id}/modules/inventory`)).json;
  assert.ok(mod.derived.vhosts.some((v) => v.name === 'shared.fr'), 'liste normalisée jointe à l’onglet Inventaire');
  assert.equal((await request401()).status, 401);
  async function request401() { const { client } = require('./helpers'); return client(e.base).get(`${P}/vhosts`); }
});

test('indicateurs : diagnostic par instance (expose_ips désactivé, module absent)', async (t) => {
  const e = await setup({ modules: { alerts_batch: 10, list: ['security'], indicators: { enabled: true } } }); t.after(() => e.app.stop());
  const ok = await fakeDash({ exposeIps: true, modules: { indicators: { data: { indicators: [{ ip: '203.0.113.9', score: 1, kinds: ['waf'] }] } } } }); t.after(() => ok.close());
  const noips = await fakeDash({ exposeIps: false }); t.after(() => noips.close());
  const a = await e.add('OK', ok.url); const b = await e.add('NOIPS', noips.url);
  await e.mod.refresh(a.id); await e.mod.refresh(b.id);
  const r = (await e.admin.get(`${P}/indicators`)).json;
  const st = Object.fromEntries(r.sources.map((s) => [s.name, s.status]));
  assert.equal(st.OK, 'ok'); assert.equal(st.NOIPS, 'ips_disabled');
});

test('vhosts : les fichiers .conf ne sont pas des vhosts (leur état est reporté sur les blocs), backend détecté par clé évocatrice', () => {
  const inv = { vhosts: {
    files: [{ name: 'conductor.rdr-it.com.conf', path: '/nginx/sites/conductor.rdr-it.com.conf', enabled: true }, { name: '00-default.conf', enabled: true }],
    servers: [{ server_names: ['conductor.rdr-it.com'], file: '/nginx/sites/conductor.rdr-it.com.conf', listen: '443 ssl', ssl: true, locations: [{ path: '/', proxy_pass_target: 'http://app:3000' }] }],
  } };
  const r = extractVhosts(inv, null, []);
  assert.deepEqual(r.map((v) => v.name), ['conductor.rdr-it.com']);
  assert.equal(r[0].state, 'enabled'); assert.equal(r[0].upstream, 'http://app:3000'); assert.equal(r[0].listen, '443 ssl'); assert.equal(r[0].tls, true);
  assert.deepEqual(extractVhosts({ vhosts: [{ name: 'api.rdr-it.com.conf' }, { name: 'x.disable' }] }, null, []), []);
});

test('vhosts : forme réelle du dashboard (serverBlocks, locations[].raw) → backend et état du fichier', () => {
  const inv = { vhosts: { vhosts: [{ file: '/nginx/sites/conductor.rdr-it.com.conf', name: 'conductor.rdr-it.com.conf', enabled: true, serverBlocks: [
    { serverNames: ['conductor.rdr-it.com'], ssl: true, listen: ['443 ssl'], locations: [{ path: '/', kind: 'upstream', targets: [], raw: 'http://conductor_upstream' }] },
    { serverNames: ['_'], ssl: false, listen: ['80'], locations: [] }] }] } };
  const r = extractVhosts(inv, null, []);
  assert.equal(r.length, 1);
  assert.equal(r[0].name, 'conductor.rdr-it.com'); assert.equal(r[0].upstream, 'http://conductor_upstream'); assert.equal(r[0].state, 'enabled');
});

test('vhosts : type de backend et cibles (#68), schéma additif', () => {
  const inv = { vhosts: { vhosts: [{ name: 'a.conf', enabled: true, serverBlocks: [
    { serverNames: ['a.fr'], locations: [{ path: '/', kind: 'docker', raw: 'http://$backend', targets: [{ scheme: 'http', host: 'app', port: 8080 }] }, { path: '/x', kind: 'upstream', raw: 'http://u', targets: [{ host: 'n1', port: 1 }, 'n2:2'] }] },
    { serverNames: ['b.fr'], locations: [{ path: '/', raw: 'http://z' }] }] }] } };
  const r = Object.fromEntries(extractVhosts(inv, null, []).map((v) => [v.name, v]));
  assert.equal(r['a.fr'].backend_kind, 'docker, upstream');
  assert.deepEqual(r['a.fr'].targets, ['app:8080', 'n1:1', 'n2:2']);
  assert.equal(r['b.fr'].backend_kind, undefined); assert.equal(r['b.fr'].targets, undefined);
  assert.equal(r['b.fr'].upstream, 'http://z', 'rendu actuel conservé pour les formes inconnues');
});
