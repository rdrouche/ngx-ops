'use strict';
const assert = require('assert');
const S = require('../lib/intel-settings');
const C = require('../lib/intel-client');
let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const ENV = {};
const norm = (t, env = ENV) => S.normalizeIntelSettings(t, env);
const instance = { id: '3df7919e-94f5-4635-91c6-8189f6475ebf', version: '12.69.0' };

(async () => {
  console.log('\nreglages');
  await check('defaut : desactive, anonyme, volumetrique exclue, https obligatoire', () => {
    const { settings } = norm('');
    assert.strictEqual(settings.enable, false); assert.strictEqual(settings.mode, 'anonymous');
    assert.deepStrictEqual(settings.excludeRules, ['volumetric', 'country_traffic']);
    assert.strictEqual(norm('api_url: http://x.tld/a').settings.apiUrl, '');
    assert.ok(norm('api_url: http://x.tld/a').errors.length);
    assert.ok(norm('api_url: "https://u:p@x.tld/a"').errors.length, 'identifiants dans l URL refuses');
  });
  await check('URL : le yml surcharge INTEL_API_URL ; jeton : ENV prioritaire', () => {
    assert.strictEqual(norm('', { apiUrl: 'https://env.tld/a' }).settings.apiUrl, 'https://env.tld/a');
    assert.strictEqual(norm('api_url: https://yml.tld/a', { apiUrl: 'https://env.tld/a' }).settings.apiUrl, 'https://yml.tld/a');
    assert.strictEqual(norm('token: yml', { token: 'env' }).settings.token, 'env');
  });
  await check('mode identified : user + token requis pour etre pret', () => {
    const base = 'enable: true\napi_url: https://x.tld/a\nmode: identified\n';
    assert.strictEqual(norm(base).settings.ready, false);
    assert.ok(norm(base).errors.length);
    assert.strictEqual(norm(base + 'user: a@b.fr\ntoken: t\n').settings.ready, true);
    assert.strictEqual(norm('enable: true\napi_url: https://x.tld/a\n').settings.ready, true);
  });
  await check('v12.70.5 : `enabled` accepte comme alias, cle inconnue signalee', () => {
    const yml = 'enabled: true\nmode: identified\napi_url: https://ti.ngx-ops.net/api/v1/events\nuser: a@b.fr\ntoken: "t"\n';
    const r = norm(yml);
    assert.strictEqual(r.settings.enable, true); assert.strictEqual(r.settings.ready, true); assert.deepStrictEqual(r.errors, []);
    const bad = norm('enable: true\napi_url: https://x.tld/a\nenabeld: true\n');
    assert.ok(bad.errors.some(e => /enabeld/.test(e)));
    assert.strictEqual(norm('enable: false\nenabled: true\n').settings.enable, false, 'enable prioritaire');
  });
  await check('v12.71.0 : ping — URL derivee, intervalle borne 3-60, meme hote impose', () => {
    const base = 'enable: true\napi_url: https://ti.ngx-ops.net/api/v1/events\n';
    const d = norm(base).settings;
    assert.strictEqual(d.pingUrl, 'https://ti.ngx-ops.net/api/v1/ping'); assert.strictEqual(d.pingIntervalMinutes, 5); assert.strictEqual(d.pingEnable, true);
    assert.strictEqual(norm(base + 'ping_interval_minutes: 1\n').settings.pingIntervalMinutes, 3);
    assert.strictEqual(norm(base + 'ping_interval_minutes: 999\n').settings.pingIntervalMinutes, 60);
    assert.strictEqual(norm('api_url: https://x.tld/custom/path\n').settings.pingUrl, 'https://x.tld/api/v1/ping');
    assert.strictEqual(norm(base + 'url_ping: https://ti.ngx-ops.net/p\n').settings.pingUrl, 'https://ti.ngx-ops.net/p');
    const other = norm(base + 'ping_url: https://evil.tld/p\n');
    assert.strictEqual(other.settings.pingUrl, 'https://ti.ngx-ops.net/api/v1/ping'); assert.ok(other.errors.length);
    assert.strictEqual(norm(base + 'ping_enable: false\n').settings.pingEnable, false);
  });
  await check('v12.71.0 : buildPingRequest — en-tetes, pas d Idempotency-Key, jeton seulement en identified', () => {
    const s = norm('enable: true\nmode: identified\napi_url: https://x.tld/api/v1/events\nuser: a@b.fr\ntoken: tk\n').settings;
    const r = C.buildPingRequest({ settings: s, instance, userAgent: 'NGXOps' });
    assert.strictEqual(r.url, 'https://x.tld/api/v1/ping');
    assert.strictEqual(r.headers.Authorization, 'Bearer tk'); assert.strictEqual(r.headers['X-NC-User'], 'a@b.fr');
    assert.strictEqual(r.headers['Idempotency-Key'], undefined); assert.strictEqual(r.headers['X-NC-Schema'], '1');
    assert.strictEqual(r.body.user, 'a@b.fr'); assert.ok(!JSON.stringify(r.body).includes('tk'));
    const a = C.buildPingRequest({ settings: norm('api_url: https://x.tld/api/v1/events\n').settings, instance });
    assert.strictEqual(a.headers.Authorization, undefined);
  });
  await check('v12.71.0 : classifyPing — 200 / 401 / 429 / reseau', () => {
    const ok = C.classifyPing({ status: 200, body: { status: 'ok', server: { name: 'NGX Ops Intelligence', version: '0.4.0' }, authenticated: true,
      instance: { new: false, trust_level: 'identified', pings: 12 }, limits: { max_alerts_per_batch: 500, batches_per_minute: 60 }, warnings: ['w1'] } });
    assert.ok(ok.ok); assert.strictEqual(ok.limits.maxAlertsPerBatch, 500); assert.deepStrictEqual(ok.warnings, ['w1']); assert.strictEqual(ok.instance.trustLevel, 'identified');
    const a = C.classifyPing({ status: 401, body: { code: 'token_unknown', detail: 'x' } });
    assert.strictEqual(a.kind, 'auth'); assert.strictEqual(a.code, 'token_unknown');
    const r = C.classifyPing({ status: 429, headers: { 'retry-after': '30' }, body: null }, 1000);
    assert.strictEqual(r.kind, 'rateLimited'); assert.strictEqual(r.retryAfterMs, 30000); assert.strictEqual(r.code, 'rate_limited');
    assert.strictEqual(C.classifyPing({ error: 'ECONNREFUSED' }).code, 'network');
    assert.strictEqual(C.classifyPing({ status: 503, body: { code: 'unavailable' } }).kind, 'retry');
  });
  await check('v12.71.0 : pingDue — demarrage, config changee, intervalle, lot recent, 401, backoff', () => {
    const s = norm('enable: true\napi_url: https://x.tld/api/v1/events\n').settings;
    const now = 10_000_000_000;
    assert.strictEqual(C.pingDue({ settings: s, state: {}, now }), 'config', 'jamais pingue');
    const done = (over = {}) => ({ ping: C.nextPingState(null, { ok: true, kind: 'ok', at: now }, s, now), lastSuccessAt: 0, ...over });
    assert.strictEqual(C.pingDue({ settings: s, state: done(), now: now + 4 * 60_000 }), null, 'avant 5 min');
    assert.strictEqual(C.pingDue({ settings: s, state: done(), now: now + 5 * 60_000 }), 'interval');
    assert.strictEqual(C.pingDue({ settings: s, state: done({ lastSuccessAt: now + 4 * 60_000 }), now: now + 5 * 60_000 }), null, 'un lot recent vaut preuve de connexion');
    const s2 = { ...s, token: 'zz' };
    assert.strictEqual(C.pingDue({ settings: s2, state: done(), now: now + 1000 }), 'config', 'config modifiee = ping immediat');
    const fail = C.nextPingState(null, { ok: false, kind: 'auth', code: 'token_unknown', at: now }, s, now);
    assert.strictEqual(C.pingDue({ settings: s, state: { ping: fail }, now: now + 3600_000 }), null, '401 : plus de ping periodique');
    const err = C.nextPingState(null, { ok: false, kind: 'retry', code: 'network', at: now }, s, now);
    assert.ok(err.nextAt >= now + 5 * 60_000);
    assert.strictEqual(C.pingDue({ settings: s, state: { ping: err }, now: now + 60_000 }), null, 'backoff');
    const rl = C.nextPingState(null, { ok: false, kind: 'rateLimited', retryAfterMs: 20 * 60_000, at: now }, s, now);
    assert.ok(rl.nextAt >= now + 20 * 60_000);
    assert.strictEqual(C.pingDue({ settings: { ...s, pingEnable: false }, state: {}, now }), null);
    assert.strictEqual(C.pingDue({ settings: { ...s, enable: false }, state: {}, now }), null);
  });
  await check('listes (bloc et [a, b]), bornes, valeurs invalides', () => {
    const s = norm('include_rules:\n  - ua_attack_tools\n  - "probe_sensitive_files"\nexclude_rules: [volumetric]\ninterval_seconds: 5\nbatch_size: 9999\nmin_severity: nope\n');
    assert.deepStrictEqual(s.settings.includeRules, ['ua_attack_tools', 'probe_sensitive_files']);
    assert.deepStrictEqual(s.settings.excludeRules, ['volumetric']);
    assert.strictEqual(s.settings.intervalSeconds, 60); assert.strictEqual(s.settings.batchSize, 500);
    assert.ok(s.errors.some(e => /min_severity/.test(e)));
  });

  console.log('\nformat des alertes');
  const sc = { id: 12, ts: Date.parse('2026-10-02T09:53:13Z'), type: 'scan', severity: 'medium', ip: '51.195.200.136', vhost: 'docs.example.com',
    evidence: { ip: '51.195.200.136', requests: 56, distinctPaths: 37, notFound: 37, firstSeen: 1000, lastSeen: 2000, statuses: { 404: 37, 200: 19 },
      userAgents: ['curl/8'], samples: [{ path: '/.env' }, { path: '/.env' }, { path: '/wp-login.php' }] } };
  const custom = { id: 13, ts: 5000, type: 'custom_7', severity: 'high', ip: '203.0.113.5',
    evidence: { ip: '203.0.113.5', ruleId: 7, ruleName: 'ua_attack_tools', matches: 4, userAgents: ['sqlmap/1.7'], samples: [{ path: '/?id=1%27' }] } };
  const vol = { id: 14, ts: 5000, type: 'volumetric', severity: 'high', evidence: {} };
  const s0 = norm('').settings;
  await check('alerte par IP : champs du schema 1, vhost non partage par defaut', () => {
    const a = C.shapeAlert(sc, s0);
    assert.strictEqual(a.id, '12'); assert.strictEqual(a.ts, '2026-10-02T09:53:13.000Z');
    assert.deepStrictEqual(a.rule, { key: 'scan', kind: 'builtin', id: null, name: 'scan' });
    assert.strictEqual(a.scope, 'ip'); assert.strictEqual(a.ip, '51.195.200.136');
    assert.strictEqual(a.requests, 56); assert.strictEqual(a.distinct_paths, 37); assert.strictEqual(a.not_found, 37);
    assert.deepStrictEqual(a.paths, ['/.env', '/wp-login.php']); assert.deepStrictEqual(a.user_agents, ['curl/8']);
    assert.strictEqual(a.vhost, undefined);
  });
  await check('partage coupe : plus de chemins/UA ; vhost sur demande', () => {
    const a = C.shapeAlert(sc, { ...s0, sharePaths: false, shareUserAgents: false, shareVhost: true });
    assert.strictEqual(a.paths, undefined); assert.strictEqual(a.user_agents, undefined); assert.strictEqual(a.vhost, 'docs.example.com');
  });
  await check('regle personnalisee : kind custom, id et nom', () => {
    assert.deepStrictEqual(C.shapeAlert(custom, s0).rule, { key: 'custom', kind: 'custom', id: 7, name: 'ua_attack_tools' });
  });
  await check('filtres : volumetrique exclue, include_rules, severite minimale', () => {
    assert.strictEqual(C.shouldSend(vol, s0), false);
    assert.strictEqual(C.shouldSend(custom, s0), true);
    assert.strictEqual(C.shouldSend(sc, { ...s0, includeRules: ['ua_attack_tools'] }), false);
    assert.strictEqual(C.shouldSend(custom, { ...s0, includeRules: ['ua_attack_tools'] }), true);
    assert.strictEqual(C.shouldSend(sc, { ...s0, minSeverity: 'high' }), false);
  });
  await check('lot : enveloppe, jeton uniquement en mode identified', () => {
    const anon = C.buildBatch({ settings: s0, instance, alerts: [sc], now: 0, batchId: 'b1' });
    assert.deepStrictEqual(Object.keys(anon), ['schema', 'batch_id', 'sent_at', 'mode', 'instance', 'alerts']);
    const h = C.buildHeaders({ settings: s0, instance, body: anon, userAgent: 'NGXOps' });
    assert.strictEqual(h['X-NC-Instance-Id'], instance.id); assert.strictEqual(h.Authorization, undefined);
    assert.strictEqual(h['Idempotency-Key'], 'b1');
    const si = { ...s0, mode: 'identified', user: 'a@b.fr', token: 'tok' };
    const idb = C.buildBatch({ settings: si, instance, alerts: [sc], now: 0 });
    assert.strictEqual(idb.user, 'a@b.fr');
    const hi = C.buildHeaders({ settings: si, instance, body: idb });
    assert.strictEqual(hi.Authorization, 'Bearer tok'); assert.strictEqual(hi['X-NC-User'], 'a@b.fr');
  });

  console.log('\nreponses');
  await check('classification des codes HTTP', () => {
    const k = (st, h) => C.classifyResponse({ status: st, headers: h || {} }, 0).kind;
    assert.strictEqual(k(200), 'ok'); assert.strictEqual(k(202), 'ok');
    assert.strictEqual(k(429), 'rateLimited'); assert.strictEqual(k(401), 'auth'); assert.strictEqual(k(403), 'auth');
    assert.strictEqual(k(413), 'tooLarge'); assert.strictEqual(k(422), 'drop'); assert.strictEqual(k(400), 'drop');
    assert.strictEqual(k(500), 'retry'); assert.strictEqual(k(503), 'retry'); assert.strictEqual(k(302), 'retry');
    assert.strictEqual(C.classifyResponse({ error: 'ECONNRESET' }).kind, 'retry');
  });
  await check('Retry-After : secondes, date HTTP, borne a 24 h', () => {
    assert.strictEqual(C.parseRetryAfter('120', 0), 120000);
    assert.strictEqual(C.parseRetryAfter(new Date(60000).toUTCString(), 0), 60000);
    assert.strictEqual(C.parseRetryAfter('999999999', 0), 86400000);
    assert.strictEqual(C.parseRetryAfter('x', 0), null);
  });
  await check('backoff exponentiel plafonne a 1 h, jitter +-20 %', () => {
    assert.strictEqual(C.backoffMs(1, () => 0.5), 30000);
    assert.strictEqual(C.backoffMs(3, () => 0.5), 120000);
    assert.strictEqual(C.backoffMs(30, () => 0.5), 3600000);
    assert.ok(C.backoffMs(1, () => 0) >= 24000 && C.backoffMs(1, () => 1) <= 36000);
  });

  console.log('\ncycle d envoi');
  const settings = norm('enable: true\napi_url: https://x.tld/api/alerts/send\nbatch_size: 2\n').settings;
  const mk = (alerts, latestId) => ({ fetchAlerts: async (q) => {
    let a = alerts.filter(x => !q.sinceId || x.id > q.sinceId);
    if (q.order === 'desc') a = [...a].reverse();
    return { alerts: a.slice(0, q.limit), latestId: latestId != null ? latestId : (alerts.length ? alerts[alerts.length - 1].id : 0) };
  } });
  const al = (id, extra = {}) => ({ id, ts: 1000 * id, type: 'scan', severity: 'medium', ip: '198.51.100.' + id, evidence: { ip: '198.51.100.' + id }, ...extra });
  await check('premier cycle : initialise le curseur sans envoyer l historique', async () => {
    let posted = 0;
    const r = await C.runCycle({ settings, state: null, instance, deps: { ...mk([al(1), al(2)]), post: async () => { posted++; return { status: 200 }; } } });
    assert.strictEqual(r.outcome, 'initialized'); assert.strictEqual(r.state.cursor, 2); assert.strictEqual(posted, 0);
  });
  await check('envoi : le curseur avance, pending si le lot est plein', async () => {
    const reqs = [];
    const deps = { ...mk([al(1), al(2), al(3), al(4)]), post: async (r) => { reqs.push(r); return { status: 200, body: { accepted: 2 } }; } };
    const r = await C.runCycle({ settings, state: { cursor: 0 }, instance, deps, now: 10 });
    assert.strictEqual(r.outcome, 'sent'); assert.strictEqual(r.state.cursor, 2); assert.strictEqual(r.state.pending, true);
    assert.strictEqual(reqs[0].body.alerts.length, 2); assert.strictEqual(r.state.counters.accepted, 2);
  });
  await check('429 : meme lot rejoue apres Retry-After, curseur inchange', async () => {
    const deps = { ...mk([al(1)]), post: async () => ({ status: 429, headers: { 'retry-after': '600' } }) };
    const r = await C.runCycle({ settings, state: { cursor: 0 }, instance, deps, now: 1000 });
    assert.strictEqual(r.outcome, 'rate_limited'); assert.strictEqual(r.state.cursor, 0);
    assert.ok(r.state.nextAttemptAt >= 1000 + 600000); assert.strictEqual(r.state.counters.http429, 1);
    const early = await C.runCycle({ settings, state: r.state, instance, deps, now: 2000 });
    assert.strictEqual(early.outcome, 'backoff');
    const ok = await C.runCycle({ settings, state: r.state, instance, now: r.state.nextAttemptAt + 1, deps: { ...mk([al(1)]), post: async () => ({ status: 200 }) } });
    assert.strictEqual(ok.outcome, 'sent'); assert.strictEqual(ok.state.cursor, 1); assert.strictEqual(ok.state.failures, 0);
  });
  await check('401 : suspendu jusqu au changement de configuration', async () => {
    const deps = { ...mk([al(1)]), post: async () => ({ status: 401 }) };
    const r = await C.runCycle({ settings, state: { cursor: 0 }, instance, deps, now: 1 });
    assert.strictEqual(r.outcome, 'auth_error'); assert.strictEqual(r.state.authError, true);
    const again = await C.runCycle({ settings, state: r.state, instance, deps, now: 99999999 });
    assert.strictEqual(again.outcome, 'auth_error');
    const changed = { ...settings, token: 'autre', mode: 'identified', user: 'a@b.fr' };
    const retry = await C.runCycle({ settings: changed, state: r.state, instance, deps: { ...mk([al(1)]), post: async () => ({ status: 200 }) }, now: 5 });
    assert.strictEqual(retry.outcome, 'sent');
  });
  await check('413 : lot reduit ; 422 : lot abandonne ; 503 : backoff', async () => {
    const a = await C.runCycle({ settings, state: { cursor: 0 }, instance, deps: { ...mk([al(1), al(2)]), post: async () => ({ status: 413 }) } });
    assert.strictEqual(a.state.batchLimit, 1); assert.strictEqual(a.state.cursor, 0);
    const d = await C.runCycle({ settings, state: { cursor: 0 }, instance, deps: { ...mk([al(1), al(2)]), post: async () => ({ status: 422 }) } });
    assert.strictEqual(d.outcome, 'dropped'); assert.strictEqual(d.state.cursor, 2); assert.strictEqual(d.state.counters.dropped, 2);
    const r = await C.runCycle({ settings, state: { cursor: 0 }, instance, deps: { ...mk([al(1)]), post: async () => ({ status: 503 }) }, now: 0 });
    assert.strictEqual(r.outcome, 'retry_later'); assert.ok(r.state.nextAttemptAt > 0);
  });
  await check('alertes filtrees : curseur avance sans requete', async () => {
    let posted = 0;
    const r = await C.runCycle({ settings, state: { cursor: 0 }, instance, deps: { ...mk([al(1, { type: 'volumetric' })]), post: async () => { posted++; return { status: 200 }; } } });
    assert.strictEqual(r.outcome, 'filtered'); assert.strictEqual(r.state.cursor, 1); assert.strictEqual(posted, 0);
  });
  await check('base de l analyseur remise a zero : le curseur est ramene', async () => {
    const r = await C.runCycle({ settings, state: { cursor: 500 }, instance, deps: { ...mk([al(1)], 1), post: async () => ({ status: 200 }) } });
    assert.strictEqual(r.outcome, 'empty'); assert.strictEqual(r.state.cursor, 1);
  });
  await check('analyseur injoignable : pas de plantage, nouvelle tentative dans 1 min', async () => {
    const r = await C.runCycle({ settings, state: { cursor: 0 }, instance, now: 0, deps: { fetchAlerts: async () => null, post: async () => ({ status: 200 }) } });
    assert.strictEqual(r.outcome, 'analyzer_unreachable'); assert.strictEqual(r.state.nextAttemptAt, 60000);
  });
  await check('apercu : derniers alertes, jeton masque, curseur intact', async () => {
    const si = { ...settings, mode: 'identified', user: 'a@b.fr', token: 'secret' };
    const r = await C.runCycle({ settings: si, state: null, instance, dryRun: true, deps: { ...mk([al(1), al(2)]), post: async () => { throw new Error('ne doit pas envoyer'); } } });
    assert.strictEqual(r.outcome, 'preview'); assert.strictEqual(r.request.headers.Authorization, 'Bearer ***');
    assert.deepStrictEqual(r.request.body.alerts.map(a => a.id), ['1', '2']); assert.strictEqual(r.state.cursor, null);
  });
  await check('desactive ou incomplet : aucun appel', async () => {
    const off = await C.runCycle({ settings: { ...settings, enable: false }, state: null, instance, deps: {} });
    assert.strictEqual(off.outcome, 'disabled');
    const nr = await C.runCycle({ settings: { ...settings, ready: false }, state: null, instance, deps: {} });
    assert.strictEqual(nr.outcome, 'not_ready');
  });

  console.log('\nalertes WAF emule (v12.70.0)');
  const wafAlert = { id: 7, ts: 1791043525385, type: 'waf', severity: 'high', ip: '203.0.113.9', vhost: 'blog.example.com',
    evidence: { score: 30, requests: 6, windowMinutes: 60, mode: 'remediate',
      rules: [{ id: 942100, msg: 'SQLi', count: 3, severity: 'CRITICAL' }], tags: ['attack-sqli'], categories: ['sqli'],
      paths: ['/a', '/b'], userAgents: ['sqlmap/1.7'], statuses: { 404: 6 }, firstSeen: 1791043500000, lastSeen: 1791043525000 } };
  await check('une alerte waf est mise en forme (kind waf, score, regles, chemins selon partage)', () => {
    const o = C.shapeAlert(wafAlert, settings);
    assert.strictEqual(o.rule.kind, 'waf');
    assert.strictEqual(o.waf.score, 30);
    assert.deepStrictEqual(o.waf.rules, [{ id: 942100, count: 3, severity: 'CRITICAL' }]);
    assert.ok(Array.isArray(o.paths) && o.ip === '203.0.113.9');
    const priv = C.shapeAlert(wafAlert, { ...settings, sharePaths: false, shareUserAgents: false });
    assert.ok(!priv.paths && !priv.user_agents);
  });
  await check('exclude_rules: [waf] retire les alertes waf', () => {
    assert.strictEqual(C.shouldSend(wafAlert, { ...settings, excludeRules: ['waf'] }), false);
    assert.strictEqual(C.shouldSend(wafAlert, { ...settings, excludeRules: ['volumetric'], includeRules: [] }), true);
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
