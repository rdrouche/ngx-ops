'use strict';
// #62 : le Hub lit les AGRÉGATS du log store (jeton read, Bearer). Aucune IP/chemin/UA ne doit sortir ; jeton jamais exposé.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { makeApp, client } = require('./helpers');
const { shapeOverview, DIMENSIONS } = require('../features/logstore/model');
const { buildRequests, readToken } = require('../features/logstore/client');
const { shapeIps, merge, union, keyType } = require('../features/logstore/correlation');

const P = '/api/hub/v1';
const PW = 'correct horse battery';
const TOKEN = 'R'.repeat(32);

/** Faux log store : vérifie le Bearer, renvoie des agrégats VOLONTAIREMENT pollués (IP, chemins, UA) pour prouver l'assainissement. */
function fakeStore({ fail = [] } = {}) {
  const calls = [];
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    calls.push({ url: req.url, auth: req.headers.authorization, hubToken: req.headers['x-hub-token'] });
    const json = (code, o) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, { error: 'unauthorized' });
    if (fail.includes(u.pathname)) return json(503, { error: 'database_unavailable' });
    if (u.pathname === '/v1/stats/visits') return json(200, { bucket: u.searchParams.get('bucket'), points: [
      { bucket: '2026-11-10T10:00:00Z', requests: 100, s2xx: 80, s3xx: 5, s4xx: 10, s5xx: 5, bytes: 1000, visitors: 7 },
      { bucket: '2026-11-10T09:00:00Z', requests: 50, s2xx: 50, s3xx: 0, s4xx: 0, s5xx: 0, bytes: 500, visitors: null }] });
    if (u.pathname === '/v1/stats/top') return json(200, { dimension: u.searchParams.get('dimension'), items: [{ key: u.searchParams.get('dimension') === 'site' ? '203.0.113.9' : 'FR', count: 9 }] });
    if (u.pathname === '/v1/stats/security') return json(200, { status_classes: { s2xx: 1, s3xx: 2, s4xx: 3, s5xx: 4 }, blocked: [{ source: 'blocklist', action: 'block', count: 5 }],
      scanners: [{ ip: '198.51.100.7', paths: 99 }, { ip: '198.51.100.8', paths: 40 }], error_user_agents: [{ key: 'curl/8', count: 3 }] });
    if (u.pathname === '/v1/stats/ips') {
      const many = Number(u.searchParams.get('min_instances')) >= 2;
      const items = many
        ? [{ key: '203.0.113.9', events: 30, blocked: 5, errors: 8, instances: ['srv-1', 'srv-2'], instance_count: 2, sources: ['access', 'waf'], sites: 2, first_seen: '2026-11-10T08:00:00Z', last_seen: '2026-11-10T10:00:00Z' },
            { key: '198.51.100.0/24', events: 4, blocked: 0, errors: 0, instances: ['srv-1', 'srv-2'], instance_count: 2, sources: ['access'], sites: 1, first_seen: '2026-11-10T08:00:00Z', last_seen: '2026-11-10T09:00:00Z' },
            { key: 'a'.repeat(32), events: 2, blocked: 0, errors: 0, instances: ['srv-1', 'srv-2'], instance_count: 2, sources: ['access'], sites: 1, first_seen: '2026-11-10T08:00:00Z', last_seen: '2026-11-10T09:00:00Z' },
            { key: '<script>', events: 9, instances: ['srv-1'], instance_count: 1, sources: ['access'] }]
        : [{ key: '192.0.2.77', events: 12, blocked: 6, errors: 0, instances: ['srv-1'], instance_count: 1, sources: ['access', 'waf', 'challenge'], sites: 1, first_seen: '2026-11-10T08:00:00Z', last_seen: '2026-11-10T09:30:00Z' }];
      return json(200, { ip_mode: 'clear', items });
    }
    if (u.pathname === '/v1/health') return json(200, { status: 'ok', version: '0.4.0', detail: { timescale: true, db_size_bytes: 1048576, last_ingest: '2026-11-10T10:00:00Z', retention_days: 30, ip_mode: 'clear' } });
    if (u.pathname === '/v1/instances') return json(200, { instances: [{ id: 'srv-1', name: 'Prod', first_seen: '2026-11-01T00:00:00Z', last_seen: '2026-11-10T10:00:00Z', events_total: 12 }, { id: '../etc', name: 'x' }] });
    return json(404, {});
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ calls, url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => { srv.close(r); srv.closeAllConnections?.(); }) })));
}

async function setup(over = {}, env = { token: TOKEN }) {
  if (env.token) process.env.HUB_LOGSTORE_TOKEN = env.token; else delete process.env.HUB_LOGSTORE_TOKEN;
  const e = await makeApp(over);
  await e.users.create({ username: 'root', password: PW, role: 'admin' });
  await e.users.create({ username: 'lecteur', password: PW, role: 'viewer' });
  const viewer = client(e.base); await viewer.post(`${P}/auth/login`, { username: 'lecteur', password: PW });
  const admin = client(e.base); await admin.post(`${P}/auth/login`, { username: 'root', password: PW });
  return { ...e, viewer, admin, anon: client(e.base) };
}

test('modèle : aucune IP, chemin ni User-Agent ne sort ; valeurs invalides neutralisées', () => {
  const m = shapeOverview({
    visits: { points: [{ bucket: '2026-11-10T10:00:00Z', requests: 5, bytes: -1 }, { bucket: 'pas-une-date', requests: 9 }] },
    security: { status_classes: { s2xx: 'x' }, blocked: [{ source: 'a', action: 'b', count: 2 }, { source: 'a', action: 'b', count: 3 }], scanners: [{ ip: '1.2.3.4' }], error_user_agents: [{ key: 'ua' }] },
    tops: { site: [{ key: '203.0.113.9', count: 4 }, { key: 'a.example', count: 'x' }], path: [{ key: '/secret', count: 1 }], ip: [{ key: '1.1.1.1', count: 1 }] },
    instances: { instances: [{ id: 'ok-1' }, { id: '../x' }] },
  });
  const txt = JSON.stringify(m);
  assert.ok(!/\d+\.\d+\.\d+\.\d+/.test(txt), 'aucune IP : ' + txt);
  assert.ok(!txt.includes('/secret') && !txt.includes('error_user_agents'));
  assert.deepEqual(Object.keys(m.tops), ['site'], 'seules les dimensions de liste blanche');
  assert.equal(m.security.scanners, 1); assert.equal(m.security.blocked[0].count, 5);
  assert.equal(m.visits.points.length, 1); assert.equal(m.visits.points[0].bytes, 0);
  assert.deepEqual(m.instances.map((i) => i.id), ['ok-1']);
  assert.deepEqual(DIMENSIONS.filter((d) => ['path', 'ua', 'ip', 'referer_host'].includes(d)), []);
});

test('requêtes : durée Go (jamais « d »), bucket jour au-delà de 72 h, instance validée, pas de dimension sensible', () => {
  const r = buildRequests({ hours: 168, instance: 'srv-1' });
  assert.equal(r[0].query.since, '168h'); assert.equal(r[0].query.bucket, 'day'); assert.equal(r[0].query.instance, 'srv-1');
  assert.equal(buildRequests({ hours: 24 })[0].query.bucket, 'hour');
  assert.throws(() => buildRequests({ hours: 24, instance: '../x' }));
  assert.ok(!r.some((x) => ['path', 'ua', 'ip', 'referer_host'].includes(x.query.dimension)));
});

test('jeton : variable d’environnement seulement, format contrôlé', () => {
  assert.equal(readToken({ HUB_LOGSTORE_TOKEN: TOKEN }), TOKEN);
  assert.equal(readToken({ HUB_LOGSTORE_TOKEN: 'court' }), '');
  assert.equal(readToken({}), '');
});

test('désactivée par défaut : status « enabled:false », overview vide, aucun appel sortant', async () => {
  const env = await setup({});
  try {
    const s = await env.viewer.get(`${P}/logstore/status`);
    assert.equal(s.status, 200); assert.equal(s.json.enabled, false); assert.equal(s.json.configured, false);
    const o = await env.viewer.get(`${P}/logstore/overview`);
    assert.equal(o.status, 200); assert.equal(o.json.enabled, false);
    assert.equal((await env.anon.get(`${P}/logstore/status`)).status, 401);
  } finally { await env.app.stop(); }
});

test('vue d’ensemble : Bearer envoyé, agrégats assainis, jeton jamais renvoyé, cache', async () => {
  const fs = await fakeStore();
  const env = await setup({ logstore: { enabled: true, url: fs.url, cache_s: 60 } });
  try {
    const st = await env.viewer.get(`${P}/logstore/status`);
    assert.equal(st.json.configured, true); assert.equal(st.json.problem, null);
    const r = await env.viewer.get(`${P}/logstore/overview?hours=24`);
    assert.equal(r.status, 200); assert.equal(r.json.partial, false);
    assert.equal(r.json.totals.requests, 150); assert.equal(r.json.visits.points[0].t < r.json.visits.points[1].t, true);
    assert.equal(r.json.security.scanners, 2); assert.deepEqual(r.json.instances.map((i) => i.id), ['srv-1']);
    assert.equal(r.json.tops.site[0].key, '[ip]');
    assert.ok(!/\d+\.\d+\.\d+\.\d+/.test(r.text), 'aucune IP dans la réponse');
    assert.ok(!r.text.includes(TOKEN) && !st.text.includes(TOKEN));
    assert.ok(fs.calls.every((c) => c.auth === `Bearer ${TOKEN}` && c.hubToken === undefined));
    assert.ok(fs.calls.every((c) => !/dimension=(path|ua|ip|referer_host)/.test(c.url)));
    const n = fs.calls.length;
    await env.viewer.get(`${P}/logstore/overview?hours=24`);
    assert.equal(fs.calls.length, n, 'servi depuis le cache');
    await env.viewer.get(`${P}/logstore/overview?hours=24&instance=srv-1`);
    assert.ok(fs.calls.some((c) => c.url.includes('instance=srv-1')));
    assert.equal((await env.viewer.get(`${P}/logstore/overview?instance=..%2Fx`)).status, 400);
  } finally { await env.app.stop(); await fs.close(); }
});

test('panne partielle : partial + code d’erreur, jamais de message brut ; jeton refusé = erreurs, pas de cache', async () => {
  const fs = await fakeStore({ fail: ['/v1/stats/security'] });
  const env = await setup({ logstore: { enabled: true, url: fs.url } });
  try {
    const r = await env.viewer.get(`${P}/logstore/overview`);
    assert.equal(r.status, 200); assert.equal(r.json.partial, true);
    assert.equal(r.json.errors.security, 'http_503'); assert.equal(r.json.security, null); assert.ok(r.json.visits);
  } finally { await env.app.stop(); await fs.close(); }
  const fs2 = await fakeStore();
  const bad = await setup({ logstore: { enabled: true, url: fs2.url } }, { token: 'W'.repeat(32) });
  try {
    const r = await bad.viewer.get(`${P}/logstore/overview`);
    assert.equal(r.json.partial, true); assert.equal(r.json.errors.visits, 'auth_failed'); assert.equal(r.json.visits, null);
  } finally { await bad.app.stop(); await fs2.close(); }
});

test('configuration incomplète : problème signalé sans appel sortant', async () => {
  const env = await setup({ logstore: { enabled: true, url: 'http://127.0.0.1:9' } }, { token: '' });
  try {
    const s = await env.viewer.get(`${P}/logstore/status`);
    assert.equal(s.json.configured, false); assert.equal(s.json.problem, 'token_missing');
    assert.equal((await env.viewer.get(`${P}/logstore/overview`)).json.enabled, false);
  } finally { await env.app.stop(); }
});

test('corrélation : types de clés, éléments invalides ignorés, instances validées', () => {
  assert.equal(keyType('203.0.113.9'), 'ip'); assert.equal(keyType('2001:db8::1'), 'ip'); assert.equal(keyType('203.0.113.0/24'), 'cidr');
  assert.equal(keyType('a'.repeat(32)), 'pseudonym'); assert.equal(keyType('<script>'), null); assert.equal(keyType('203.0.113.7/24'), null);
  const r = shapeIps({ items: [{ key: '1.2.3.4', instances: ['ok', '../x'], sources: ['waf', 'hack'], events: -5, instance_count: 1 }, { key: 'x' }, null, 'str'] });
  assert.equal(r.length, 1); assert.deepEqual(r[0].instances, ['ok']); assert.deepEqual(r[0].sources, ['waf']); assert.equal(r[0].events, 0);
  assert.deepEqual(shapeIps(null), []); assert.deepEqual(shapeIps({ items: 'x' }), []);
  assert.equal(union([[{ key: 'a' }], [{ key: 'a' }, { key: 'b' }]]).length, 2);
});

test('corrélation : fusion avec les indicateurs des dashboards, campagne et tri', () => {
  const dash = [{ ip: '203.0.113.9', score: 2, kinds: ['alert'], instances: [{ id: 1, name: 'a', kinds: ['alert'], sources: [], seen_at: 1 }], campaign: false },
    { ip: '10.9.9.9', score: 1, kinds: ['alert'], instances: [{ id: 2, name: 'b', kinds: ['alert'], sources: [], seen_at: 1 }], campaign: false }];
  const ls = shapeIps({ items: [
    { key: '203.0.113.9', events: 30, blocked: 5, instances: ['srv-1', 'srv-2'], instance_count: 2, sources: ['access', 'waf'] },
    { key: '192.0.2.77', events: 12, blocked: 6, instances: ['srv-1'], instance_count: 1, sources: ['access', 'waf', 'challenge'] },
    { key: '198.51.100.0/24', events: 3, instances: ['srv-1'], instance_count: 1, sources: ['access'] }] });
  const out = merge(dash, ls);
  const by = Object.fromEntries(out.map((x) => [x.ip, x]));
  assert.equal(by['203.0.113.9'].campaign, true, '2 instances log store');
  assert.deepEqual([...by['203.0.113.9'].kinds].sort(), ['alert', 'waf']);
  assert.equal(by['203.0.113.9'].instances.length, 1, 'instances de dashboard conservées');
  assert.deepEqual([...by['192.0.2.77'].kinds].sort(), ['challenge', 'waf'], 'access n’est pas un type de signal');
  assert.equal(by['192.0.2.77'].campaign, false, '1 instance, 2 types : pas une campagne');
  assert.equal(by['198.51.100.0/24'].scope, 'cidr'); assert.equal(by['198.51.100.0/24'].campaign, false);
  assert.equal(by['10.9.9.9'].logstore, null, 'indicateur de dashboard seul conservé');
  assert.equal(out[0].ip, '203.0.113.9', 'campagnes d’abord');
  assert.deepEqual(merge([], []), []); assert.deepEqual(merge(null, []), []);
});

test('corrélation : désactivée par défaut (404), réservée aux administrateurs, assainie, sans IP dans l’audit', async () => {
  const fs = await fakeStore();
  const off = await setup({ logstore: { enabled: true, url: fs.url } });
  try {
    assert.equal((await off.admin.get(`${P}/logstore/correlation`)).status, 404, 'opt-in : indicators.enabled absent');
    assert.equal((await off.admin.get(`${P}/logstore/status`)).json.indicators, false);
  } finally { await off.app.stop(); }
  const env = await setup({ logstore: { enabled: true, url: fs.url, indicators: { enabled: true } } });
  try {
    assert.equal((await env.viewer.get(`${P}/logstore/correlation`)).status, 403, 'viewer : pas de données personnelles');
    assert.equal((await env.anon.get(`${P}/logstore/correlation`)).status, 401);
    assert.equal((await env.admin.get(`${P}/logstore/status`)).json.indicators, true);
    const r = await env.admin.get(`${P}/logstore/correlation`);
    assert.equal(r.status, 200); assert.equal(r.json.partial, false);
    const by = Object.fromEntries(r.json.items.map((x) => [x.ip, x]));
    assert.ok(by['203.0.113.9'] && by['203.0.113.9'].campaign && by['203.0.113.9'].logstore.blocked === 5);
    assert.ok(by['192.0.2.77'], 'une instance mais ≥ 3 sources');
    assert.equal(by['198.51.100.0/24'].scope, 'cidr'); assert.equal(by['a'.repeat(32)].scope, 'pseudonym');
    assert.ok(!('<script>' in by));
    assert.ok(!r.text.includes(TOKEN));
    const qs = fs.calls.filter((c) => c.url.startsWith('/v1/stats/ips')).map((c) => c.url);
    assert.ok(qs.some((u) => u.includes('min_instances=2')) && qs.some((u) => u.includes('min_sources=3')) && qs.every((u) => u.includes('since=24h') && !u.includes('ip=')));
    assert.ok(fs.calls.filter((c) => c.url.startsWith('/v1/stats/ips')).every((c) => c.auth === `Bearer ${TOKEN}`));
    const rows = await env.app.ctx.db.all('SELECT action, target, detail FROM audit WHERE action = ?', ['logstore.correlation.view']);
    assert.equal(rows.length, 1); assert.ok(!/\d+\.\d+\.\d+\.\d+/.test(JSON.stringify(rows.map((x) => [x.target, x.detail]))), 'aucune adresse dans l’audit');
    const n = fs.calls.length; await env.admin.get(`${P}/logstore/correlation`);
    assert.equal(fs.calls.length, n, 'cache mémoire');
  } finally { await env.app.stop(); await fs.close(); }
});

test('corrélation : règles de campagne d’analyse conservées (#83)', () => {
  const dash = [{ ip: '203.0.113.9', score: 1, kinds: ['campaign'], instances: [{ id: 1, name: 'a', kinds: ['campaign'], sources: [{ kind: 'campaign', type: 'forgejo_scraper' }], seen_at: 1 }], campaign: false, campaign_rules: ['forgejo_scraper'] },
    { ip: '10.9.9.9', score: 1, kinds: ['alert'], instances: [], campaign: false }];
  const ls = shapeIps({ items: [{ key: '203.0.113.9', events: 3, instances: ['srv-1'], instance_count: 1, sources: ['access'] }] });
  const out = Object.fromEntries(merge(dash, ls).map((x) => [x.ip, x]));
  assert.deepEqual(out['203.0.113.9'].campaign_rules, ['forgejo_scraper']);
  assert.deepEqual(out['10.9.9.9'].campaign_rules, []);
  const { correlate } = require('../features/modules/correlate');
  const payload = (kind) => JSON.stringify({ data: { indicators: [{ ip: '198.51.100.7', score: 1, kinds: ['campaign'], sources: [{ kind: 'campaign', type: kind }, { kind: 'campaign', type: 'x'.repeat(200) }] }] } });
  const c = correlate([{ instance_id: 1, name: 'a', fetched_at: Date.now(), payload: payload('forgejo_scraper') }, { instance_id: 2, name: 'b', fetched_at: Date.now(), payload: payload('autre') }], { maxAgeMs: 60000 });
  assert.equal(c.length, 1); assert.equal(c[0].campaign, true, '2 instances');
  assert.ok(c[0].campaign_rules.includes('forgejo_scraper') && c[0].campaign_rules.includes('autre'));
  assert.ok(c[0].campaign_rules.every((r) => r.length <= 80));
});

// #107 : en thème sombre, 3xx et 4xx avaient la même couleur (--c3 et --warn = #e3b341) : les classes doivent rester distinctes.
test('couleurs des classes de statut : 2xx/3xx/4xx/5xx toutes distinctes (histogramme et anneau)', () => {
  const fs = require('node:fs'); const path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '../public/assets/js/views/logstore.js'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, '../public/assets/css/hub.css'), 'utf8') + fs.readFileSync(path.join(__dirname, '../public/assets/css/viz.css'), 'utf8');
  const cls = { s2xx: /label: '2xx'[^}]*cls: '(\w+)'/, s3xx: /label: '3xx'[^}]*cls: '(\w+)'/, s4xx: /label: '4xx'[^}]*cls: '(\w+)'/, s5xx: /label: '5xx'[^}]*cls: '(\w+)'/ };
  const got = Object.fromEntries(Object.entries(cls).map(([k, re]) => [k, (src.match(re) || [])[1]]));
  assert.equal(new Set(Object.values(got)).size, 4, JSON.stringify(got));
  // Teinte réelle (thème sombre) de chaque classe : jamais deux identiques.
  const dark = (css.match(/data-theme="dark"\][^{]*\{([^}]*)\}/g) || []).join(' ');
  const val = (v) => (dark.match(new RegExp(`--${v}:\\s*(#[0-9a-fA-F]{6})`)) || [])[1];
  const colors = Object.values(got).map((c) => val(c)).filter(Boolean);
  assert.equal(new Set(colors).size, colors.length, colors.join(','));
});

test('base de données (#127) : détail assaini, absent pour un jeton limité, requête health dans l’aperçu', () => {
  const ok = shapeOverview({ health: { status: 'ok', version: '0.4.0<script>', detail: { timescale: true, db_size_bytes: 123456, last_ingest: '2026-11-12T10:00:00Z', retention_days: 30, ip_mode: 'hack' } } }).store;
  assert.deepEqual({ ...ok, last_ingest: typeof ok.last_ingest }, { reachable: true, detail: true, version: '0.4.0script', timescale: true, db_size_bytes: 123456, last_ingest: 'number', retention_days: 30, ip_mode: null });
  assert.deepEqual(shapeOverview({ health: { status: 'ok' } }).store, { reachable: true, detail: false });
  assert.equal(shapeOverview({}).store, null);
  assert.ok(buildRequests({ hours: 24 }).some((x) => x.name === 'health' && x.path === '/v1/health'));
});
