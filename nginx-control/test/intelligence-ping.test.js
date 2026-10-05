'use strict';
/**
 * v12.71.0 — ping NGX Ops Intelligence de bout en bout (module features/intelligence.js, serveur HTTPS local).
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'intel-ping-'));
process.env.USERS_FILE = path.join(tmp, 'users.yml'); // CONFIG_DIR en derive
process.env.INSTANCE_ID = '3f2b8c1e-9d4a-4e6b-8a57-1c2d3e4f5a6b';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // certificat autosigne du serveur de test uniquement
execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout ${tmp}/k.pem -out ${tmp}/c.pem -subj /CN=127.0.0.1 -days 1 2>/dev/null`);

let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const calls = [];
let mode = 'ok';
const srv = https.createServer({ key: fs.readFileSync(tmp + '/k.pem'), cert: fs.readFileSync(tmp + '/c.pem') }, (req, res) => {
  let b = ''; req.on('data', d => b += d);
  req.on('end', () => {
    calls.push({ method: req.method, url: req.url, headers: req.headers, body: b });
    const send = (s, o, h = {}) => { res.writeHead(s, { 'Content-Type': 'application/json', ...h }); res.end(JSON.stringify(o)); };
    if (req.url !== '/api/v1/ping') return send(404, { error: 'nf' });
    if (mode === 'auth') return send(401, { error: 'x', code: 'token_unknown', detail: 'unknown token' });
    return send(200, { status: 'ok', server: { name: 'NGX Ops Intelligence', version: '0.4.0' }, authenticated: true,
      instance: { new: false, trust_level: 'identified', pings: 3 }, limits: { max_alerts_per_batch: 50 }, warnings: ['demo warning'] });
  });
});

(async () => {
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  fs.mkdirSync(tmp, { recursive: true });
  fs.writeFileSync(path.join(tmp, 'intelligence.yml'),
    `enabled: true\nmode: identified\napi_url: https://127.0.0.1:${port}/api/v1/events\nuser: a@b.fr\ntoken: secret-token\n`);
  const I = require('../features/intelligence');
  const events = require('../lib/events');

  console.log('\nping manuel (bouton « Tester la connexion »)');
  const st0 = I.publicStatus();
  await check('statut : ping configure, URL derivee, 5 min, test possible', () => {
    assert.strictEqual(st0.ping.url, `127.0.0.1:${port}/api/v1/ping`); assert.strictEqual(st0.ping.intervalMinutes, 5);
    assert.strictEqual(st0.ping.canTest, true); assert.strictEqual(st0.ping.last, null);
  });
  const calls0 = calls.length;
  const handlers = {};
  const router = { get: (p, h) => { handlers['GET ' + p] = h; }, post: (p, h) => { handlers['POST ' + p] = h; }, put() {}, delete() {} };
  I.register(router);
  const run = async (key) => {
    let out; const res = { writeHead(s) { this.s = s; }, end(b) { out = { status: this.s, body: b ? JSON.parse(b) : null }; } };
    await handlers[key]({ res, req: {}, session: { username: 'admin', role: 'admin', permissions: ['*'] }, url: new URL('http://x/') });
    return out;
  };
  const r = await run('POST /api/intelligence/ping').catch(e => ({ err: e.message }));
  await check('POST /api/intelligence/ping : 1 requete POST, en-tetes complets, resultat sans jeton', () => {
    assert.ok(!r.err, r.err);
    assert.strictEqual(calls.length, calls0 + 1);
    const c = calls[calls.length - 1];
    assert.strictEqual(c.method, 'POST'); assert.strictEqual(c.headers.authorization, 'Bearer secret-token');
    assert.strictEqual(c.headers['x-nc-user'], 'a@b.fr'); assert.strictEqual(c.headers['x-nc-instance-id'], '3f2b8c1e-9d4a-4e6b-8a57-1c2d3e4f5a6b');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.ping.ok, true); assert.deepStrictEqual(r.body.ping.warnings, ['demo warning']);
    assert.ok(!JSON.stringify(r.body).includes('secret-token'));
  });
  await check('etat persiste : limite serveur retenue, evenement ping_ok journalise', () => {
    const st = I.loadState();
    assert.strictEqual(st.serverBatchLimit, 50); assert.strictEqual(st.ping.ok, true);
    const ev = events.recentEvents(50).map(e => e.type);
    assert.ok(ev.includes('intelligence.ping_ok'), ev.join(','));
    assert.ok(ev.includes('intelligence.ping_warning'), ev.join(','));
  });

  console.log('\nechec d authentification');
  mode = 'auth';
  const r2 = await run('POST /api/intelligence/ping');
  await check('401 : code et detail exposes, evenement ping_error, plus de ping automatique', () => {
    assert.strictEqual(r2.body.ping.ok, false); assert.strictEqual(r2.body.ping.code, 'token_unknown'); assert.strictEqual(r2.body.ping.kind, 'auth');
    assert.ok(events.recentEvents(50).some(e => e.type === 'intelligence.ping_error'));
    const C = require('../lib/intel-client');
    const { settings } = I.loadSettings();
    assert.strictEqual(C.pingDue({ settings, state: I.loadState(), now: Date.now() + 3600_000 }), null);
  });

  srv.close(); fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
