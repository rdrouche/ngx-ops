'use strict';
// #107 : explorateur du log store (logs bruts + fiche IP). Opt-in, admin, relais sans stockage, audit sans valeurs.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { makeApp, client } = require('./helpers');
const { buildEventsQuery, buildTopQuery, shapeTop, buildCampaignsQuery, shapeCampaigns, shapeEvent, shapeEvents, shapeIpHistory, shapeExtra } = require('../features/logstore/explorer');
const { loadConfig } = require('../lib/config');

const P = '/api/hub/v1';
const PW = 'correct horse battery';
const TOKEN = 'R'.repeat(32);
const IP = '203.0.113.9';

const EV = (over = {}) => ({ id: 7, ts: '2026-11-10T10:00:00Z', instance_id: 'srv-1', source: 'waf', action: 'logged', site: 'a.example', ip: IP, ip_key: null, method: 'GET', path: '/wp-login.php',
  query_hash: 'deadbeef', status: 403, bytes: 12, rt_ms: 3, ua: 'curl/8', referer_host: null, country: 'FR', bot_class: 'scanner', rule: 'wp-login', extra: { score: 9, rules: ['a', 'b'], nested: { x: 1 } }, ...over });

function fakeStore() {
  const calls = [];
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    calls.push({ path: u.pathname, q: Object.fromEntries(u.searchParams), auth: req.headers.authorization });
    const json = (code, o) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, { error: 'unauthorized' });
    if (u.pathname === '/v1/events') return json(200, { events: [EV(), EV({ id: 8, instance_id: '../x' }), { id: 9, ts: 'pas-une-date' }, EV({ id: 10, source: 'inconnue', secret: 'x' })], next_cursor: 'abc_DEF=' });
    if (u.pathname.startsWith('/v1/ips/')) return json(200, { ip_mode: 'clear', summary: { first_seen: '2026-11-10T08:00:00Z', last_seen: '2026-11-10T10:00:00Z', total: 40, by_source_action: [{ source: 'waf', action: 'logged', count: 3 }] }, events: [EV(), EV({ id: 11, site: 'b.example', instance_id: 'srv-2' })], next_cursor: null });
    return json(404, {});
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ calls, url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => { srv.close(r); srv.closeAllConnections?.(); }) })));
}

async function setup(over = {}) {
  process.env.HUB_LOGSTORE_TOKEN = TOKEN;
  const e = await makeApp(over);
  await e.users.create({ username: 'root', password: PW, role: 'admin' });
  await e.users.create({ username: 'lecteur', password: PW, role: 'viewer' });
  const viewer = client(e.base); await viewer.post(`${P}/auth/login`, { username: 'lecteur', password: PW });
  const admin = client(e.base); await admin.post(`${P}/auth/login`, { username: 'root', password: PW });
  return { ...e, viewer, admin, anon: client(e.base) };
}

test('config : explorateur désactivé par défaut, opt-in strict, page_size borné', () => {
  const c = (ex) => loadConfig({ file: '/nonexistent.yml', overrides: { logstore: { explorer: ex } } }).logstore.explorer;
  assert.equal(loadConfig({ file: '/nonexistent.yml', overrides: {} }).logstore.explorer.enabled, false);
  assert.equal(c('yes').enabled, false); assert.equal(c({ enabled: 1 }).enabled, false); assert.equal(c({ enabled: true }).enabled, true); assert.equal(c(true).enabled, true);
  assert.equal(c({ page_size: 5 }).page_size, 10); assert.equal(c({ page_size: 9999 }).page_size, 500);
});

test('filtres : liste blanche, durée Go, limites ; toute valeur étrangère est refusée', () => {
  const { query, used } = buildEventsQuery({ hours: '168', instance: 'srv-1', site: 'a.example', source: 'waf', action: 'blocked', status: '4xx', ip: IP, path: '/x', ua: 'curl', limit: '9999', cursor: 'abc_DEF=' });
  assert.equal(query.since, '168h'); assert.equal(query.limit, 500); assert.equal(query.status, '4xx');
  assert.deepEqual(used, ['instance', 'site', 'source', 'action', 'status', 'ip', 'path', 'ua', 'cursor']);
  assert.equal(buildEventsQuery({}).query.since, '24h'); assert.equal(buildEventsQuery({}, { defaultLimit: 50 }).query.limit, 50);
  for (const bad of [{ hours: '0' }, { hours: '745' }, { hours: 'x' }, { limit: '0' }, { instance: '../x' }, { site: 'a b' }, { source: 'x' }, { action: 'delete' }, { status: '99' }, { status: '6xx' },
    { ip: 'pas-une-ip' }, { ip: '1.2.3.4; DROP' }, { path: 'a\nb' }, { path: 'x'.repeat(201) }, { ua: 'x'.repeat(201) }, { cursor: 'a b' }, { cursor: '../' }, { site: ['b;', 'a'] }])
    assert.throws(() => buildEventsQuery(bad), (e) => e.code === 'bad_filter', JSON.stringify(bad));
  assert.equal(buildEventsQuery({ ip: '2001:db8::1' }).query.ip, '2001:db8::1'); assert.equal(buildEventsQuery({ ip: '198.51.100.0/24' }).query.ip, '198.51.100.0/24'); assert.equal(buildEventsQuery({ ip: 'a'.repeat(32) }).query.ip, 'a'.repeat(32));
});

test('modèle : champs de liste blanche, types contrôlés, événements invalides écartés', () => {
  const r = shapeEvents({ events: [EV(), { id: 9, ts: 'x' }, EV({ id: 8, instance_id: '../x', source: 'inconnue', secret: 'x', status: 'abc' }), null], next_cursor: 'a b' });
  assert.equal(r.events.length, 2); assert.equal(r.next_cursor, null);
  assert.equal(r.events[1].instance, null); assert.equal(r.events[1].source, null); assert.equal(r.events[1].status, null); assert.ok(!('secret' in r.events[1]));
  assert.equal(r.events[0].ts, Date.parse('2026-11-10T10:00:00Z')); assert.equal(r.events[0].ip, IP);
  assert.deepEqual(r.events[0].extra, { score: 9, rules: ['a', 'b'] }, 'objets imbriqués écartés');
  assert.equal(shapeEvent('x'), null); assert.equal(shapeExtra([1]), null);
  assert.ok(!JSON.stringify(r).includes('query_hash'));
});

test('fiche IP : résumé, répartition par site/instance/règle', () => {
  const h = shapeIpHistory({ ip_mode: 'bidon', summary: { total: 5, by_source_action: [{ source: 'waf', action: 'x', count: 2 }] }, events: [EV(), EV({ id: 2, site: 'b.example' })] });
  assert.equal(h.ip_mode, null); assert.equal(h.summary.total, 5); assert.equal(h.summary.by_source_action[0].action, null);
  assert.deepEqual(h.by_site.map((x) => x.key).sort(), ['a.example', 'b.example']); assert.equal(h.by_instance[0].count, 2); assert.equal(h.by_rule[0].key, 'wp-login');
});

test('désactivé par défaut : 404 même pour un administrateur, aucun appel sortant', async () => {
  const fs = await fakeStore();
  const env = await setup({ logstore: { enabled: true, url: fs.url } });
  try {
    assert.equal((await env.admin.get(`${P}/logstore/explorer/events`)).status, 404);
    assert.equal((await env.admin.get(`${P}/logstore/explorer/ip?ip=${IP}`)).status, 404);
    assert.equal((await env.viewer.get(`${P}/logstore/status`)).json.explorer, false);
    assert.equal(fs.calls.length, 0);
  } finally { await env.app.stop(); await fs.close(); }
});

test('explorateur : admin seulement, filtres relayés, réponse assainie, jeton jamais renvoyé, audit sans valeurs', async () => {
  const fs = await fakeStore();
  const env = await setup({ logstore: { enabled: true, url: fs.url, explorer: { enabled: true, page_size: 50 } } });
  try {
    assert.equal((await env.anon.get(`${P}/logstore/explorer/events`)).status, 401);
    assert.equal((await env.viewer.get(`${P}/logstore/explorer/events`)).status, 403);
    assert.equal((await env.viewer.get(`${P}/logstore/explorer/ip?ip=${IP}`)).status, 403);
    assert.equal((await env.viewer.get(`${P}/logstore/status`)).json.explorer, true);

    const r = await env.admin.get(`${P}/logstore/explorer/events?hours=48&site=a.example&status=4xx&ip=${IP}`);
    assert.equal(r.status, 200); assert.equal(r.json.events.length, 3); assert.equal(r.json.next_cursor, 'abc_DEF='); assert.equal(r.json.limit, 50);
    const c = fs.calls.find((x) => x.path === '/v1/events');
    assert.equal(c.auth, `Bearer ${TOKEN}`); assert.equal(c.q.since, '48h'); assert.equal(c.q.site, 'a.example'); assert.equal(c.q.status, '4xx'); assert.equal(c.q.ip, IP); assert.equal(c.q.limit, '50');
    assert.ok(!r.text.includes(TOKEN) && !r.text.includes('deadbeef'));

    const bad = await env.admin.get(`${P}/logstore/explorer/events?status=${encodeURIComponent('4xx; DROP')}`);
    assert.equal(bad.status, 400); assert.equal(bad.json.error.code, 'bad_filter');
    const before = fs.calls.length; assert.equal((await env.admin.get(`${P}/logstore/explorer/events?hours=9999`)).status, 400); assert.equal(fs.calls.length, before, 'refusé avant tout appel sortant');

    const ip = await env.admin.get(`${P}/logstore/explorer/ip?ip=${IP}&hours=72`);
    assert.equal(ip.status, 200); assert.equal(ip.json.summary.total, 40); assert.equal(ip.json.by_site.length, 2);
    assert.equal(fs.calls.find((x) => x.path.startsWith('/v1/ips/')).path, `/v1/ips/${IP}`);
    for (const badIp of ['', 'x', '198.51.100.0/24', '../etc']) assert.equal((await env.admin.get(`${P}/logstore/explorer/ip?ip=${encodeURIComponent(badIp)}`)).status, 400, badIp);

    const rows = await env.app.ctx.db.all('SELECT action, target, detail FROM audit WHERE action LIKE ?', ['logstore.explorer.%']);
    assert.ok(rows.length >= 2); const txt = JSON.stringify(rows);
    assert.ok(!txt.includes(IP) && !txt.includes('a.example') && !txt.includes('4xx'), 'ni IP ni valeur de filtre dans l’audit : ' + txt);
    assert.ok(txt.includes('filters'));
  } finally { await env.app.stop(); await fs.close(); }
});

test('log store en erreur : 502 normalisé, sans message brut ni jeton', async () => {
  const env = await setup({ logstore: { enabled: true, url: 'http://127.0.0.1:1', timeout_ms: 800, explorer: { enabled: true } } });
  try {
    const r = await env.admin.get(`${P}/logstore/explorer/events`);
    assert.equal(r.status, 502); assert.equal(r.json.error.code, 'logstore_error'); assert.ok(!r.text.includes(TOKEN) && !r.text.includes('127.0.0.1'));
  } finally { await env.app.stop(); }
});

test('vue : teintes de statut distinctes ; export CSV protégé contre l’injection de formule', async () => {
  let m;
  try { m = await import('../public/assets/js/views/explorer.js'); } catch (e) { assert.fail('module de vue non importable hors navigateur : ' + e.message); }
  const tones = [200, 301, 404, 503].map(m.statusTone);
  assert.deepEqual(tones, ['ok', 'info', 'warn', 'err']); assert.equal(m.statusTone(0), '');
  assert.equal(m.csvCell('=cmd|calc'), "'=cmd|calc"); assert.equal(m.csvCell('+1'), "'+1"); assert.equal(m.csvCell('@x'), "'@x"); assert.equal(m.csvCell('-1'), "'-1");
  assert.equal(m.csvCell('a,b'), '"a,b"'); assert.equal(m.csvCell('di"t'), '"di""t"'); assert.equal(m.csvCell(null), ''); assert.equal(m.csvCell({ a: 1 }), '"{""a"":1}"');
  const csv = m.toCsv([{ ts: Date.parse('2026-11-10T10:00:00Z'), instance: 'srv-1', site: 'a.example', path: '=HYPERLINK("x")', status: 200, extra: { score: 9 } }]);
  const [head, row] = csv.split('\n');
  assert.ok(head.startsWith('ts,instance,site')); assert.ok(row.includes('2026-11-10T10:00:00.000Z') && row.includes(`"'=HYPERLINK(""x"")"`), row);
});

test('top : dimension en liste blanche, filtres validés, réponse assainie', () => {
  const b = buildTopQuery({ dimension: 'rule', hours: '6', source: 'waf', rule: 'wp-login', limit: '999' });
  assert.deepEqual(b.query, { since: '6h', limit: 50, source: 'waf', rule: 'wp-login', dimension: 'rule' });
  assert.ok(b.used.includes('dimension') && !JSON.stringify(b.used).includes('wp-login'));
  assert.throws(() => buildTopQuery({ dimension: 'password' }), { code: 'bad_filter' });
  assert.throws(() => buildTopQuery({}), { code: 'bad_filter' });
  assert.throws(() => buildTopQuery({ dimension: 'rule', rule: 'a\nb' }), { code: 'bad_filter' });
  const s = shapeTop({ items: [{ key: 'r1', count: 5, x: 1 }, { key: 7, count: 2 }, { key: 'r2', count: -3 }, 'bad'] }, 'rule');
  assert.deepEqual(s.items, [{ key: 'r1', count: 5 }, { key: 'r2', count: 0 }]);
});

test('buildEventsQuery : filtre rule', () => {
  assert.equal(buildEventsQuery({ rule: 'bad-bots' }).query.rule, 'bad-bots');
  assert.throws(() => buildEventsQuery({ rule: 'a\nb' }), { code: 'bad_filter' });
});

test('campagnes : fenêtre ≤ 7 j, min_ips borné, sortie sans IP', () => {
  const b = buildCampaignsQuery({ hours: '24', min_ips: '5', source: 'waf' });
  assert.deepEqual(b.query, { since: '24h', source: 'waf', min_ips: 5, limit: 30 });
  assert.throws(() => buildCampaignsQuery({ hours: '200' }), { code: 'bad_filter' });
  assert.throws(() => buildCampaignsQuery({ min_ips: '1' }), { code: 'bad_filter' });
  const s = shapeCampaigns({ items: [{ rule: 'wp-login', path: '/wp-login.php', events: 9, blocked: 9, ip_count: 3, site_count: 1, instance_count: 1, sources: ['waf', 'x'], first_seen: '2026-11-10T10:00:00Z', last_seen: '2026-11-10T11:00:00Z', ip: '203.0.113.1' }, { rule: null }] });
  assert.equal(s.items.length, 1);
  assert.deepEqual(s.items[0].sources, ['waf']);
  assert.ok(!JSON.stringify(s).includes('203.0.113'));
});

test('source analysis (#110) acceptée par le filtre et conservée dans les événements', () => {
  assert.equal(buildEventsQuery({ source: 'analysis' }).query.source, 'analysis');
  assert.equal(buildTopQuery({ dimension: 'rule', source: 'analysis' }).query.source, 'analysis');
  assert.equal(shapeEvent(EV({ source: 'analysis', action: 'logged', rule: 'bruteforce' })).source, 'analysis');
});
