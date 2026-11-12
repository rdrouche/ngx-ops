'use strict';
/** MFA (v12.75.0) : TOTP, codes de secours, clé WebAuthn simulée, contre un vrai serveur. */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto');
const { spawn } = require('child_process');
const http = require('http');
const totp = require('../lib/totp');
const wa = require('../lib/webauthn');

let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mfa-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mfa-data-'));
for (const d of ['lib', 'features', 'public']) fs.cpSync(path.join(root, d), path.join(appDir, d), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));
for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n  - username: bob\n    password: bob12345\n    role: viewer\n    name: B\n    enabled: true\n');

const PORT = 3917;
const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'), DIR_SNIPPETS: path.join(tmp, 'snippets'),
  DIR_STREAMS: path.join(tmp, 'streams'), DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'), DIR_SSL: path.join(tmp, 'ssl'),
  DIR_CERTS: path.join(tmp, 'certs'), DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

function raw(method, p, { cookie, body, json, headers } = {}) {
  return new Promise(resolve => {
    const data = json !== undefined ? JSON.stringify(json) : body;
    const h = { ...(cookie ? { Cookie: cookie } : {}), ...(headers || {}) };
    if (data !== undefined) { h['Content-Length'] = Buffer.byteLength(data); h['Content-Type'] = json !== undefined ? 'application/json' : 'application/x-www-form-urlencoded'; }
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method, headers: h, timeout: 5000 }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { let j; try { j = JSON.parse(b); } catch { j = null; }
        resolve({ status: res.statusCode, text: b, json: j, location: res.headers.location,
          cookies: (res.headers['set-cookie'] || []).map(c => c.split(';')[0]) }); });
    });
    r.on('error', e => resolve({ status: 0, text: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 0, text: 'timeout' }); });
    if (data !== undefined) r.write(data);
    r.end();
  });
}
const sess = (r) => (r.cookies.find(c => c.startsWith('ngx_session=')) || '');
const mfaCk = (r) => (r.cookies.find(c => c.startsWith('ngx_mfa=') && c.length > 9) || '');
const loginPw = (u, p) => raw('POST', '/auth/login', { body: `username=${u}&password=${p}` });

// Authentificateur logiciel ES256 (comme une YubiKey)
const authn = (() => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = crypto.randomBytes(32);
  let counter = 0;
  const cbor = (o) => { // encodeur minimal pour le test
    if (Buffer.isBuffer(o)) { const h = o.length < 24 ? Buffer.from([0x40 | o.length]) : o.length < 256 ? Buffer.from([0x58, o.length]) : Buffer.from([0x59, o.length >> 8, o.length & 255]); return Buffer.concat([h, o]); }
    if (typeof o === 'string') { const b = Buffer.from(o); return Buffer.concat([Buffer.from([0x60 | b.length]), b]); }
    if (typeof o === 'number') return o >= 0 ? Buffer.from([o]) : Buffer.from([0x20 | (-1 - o)]);
    if (o instanceof Map) return Buffer.concat([Buffer.from([0xa0 | o.size]), ...[...o].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  };
  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
  const sha = (b) => crypto.createHash('sha256').update(b).digest();
  const ctr = () => { const b = Buffer.alloc(4); b.writeUInt32BE(counter); return b; };
  return {
    credId,
    create(challenge, rpId, origin) {
      const cd = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin }));
      const len = Buffer.alloc(2); len.writeUInt16BE(credId.length);
      const ad = Buffer.concat([sha(rpId), Buffer.from([0x41]), ctr(), Buffer.alloc(16), len, credId, cose]);
      const att = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', ad]]));
      return { clientDataJSON: cd.toString('base64url'), attestationObject: att.toString('base64url') };
    },
    get(challenge, rpId, origin) {
      counter++;
      const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
      const ad = Buffer.concat([sha(rpId), Buffer.from([0x01]), ctr()]);
      const sig = crypto.sign('sha256', Buffer.concat([ad, sha(cd)]), privateKey);
      return { id: credId.toString('base64url'), clientDataJSON: cd.toString('base64url'), authenticatorData: ad.toString('base64url'), signature: sig.toString('base64url') };
    },
  };
})();

(async () => {
  await check('totp RFC 6238 / base32 / anti-rejeu', () => {
    assert.strictEqual(totp.hotp(totp.base32Encode(Buffer.from('12345678901234567890')), 1), '287082');
    const s = totp.generateSecret(); const c = totp.hotp(s, totp.counterAt());
    const ctr = totp.verify(s, c); assert.ok(ctr !== null);
    assert.strictEqual(totp.verify(s, c, { lastCounter: ctr }), null);
    assert.strictEqual(totp.verify(s, '12345'), null);
    assert.ok(totp.otpauthUri({ secret: s, account: 'a b' }).startsWith('otpauth://totp/NGX%20Ops:a%20b?secret='));
  });
  await check('cbor/webauthn : refuse un mauvais challenge', () => {
    const rp = 'localhost', o = 'http://localhost';
    const reg = wa.verifyRegistration(authn.create('abc', rp, o), { challenge: 'abc', origins: [o], rpId: rp });
    assert.strictEqual(reg.alg, -7);
    assert.throws(() => wa.verifyRegistration(authn.create('abc', rp, o), { challenge: 'zzz', origins: [o], rpId: rp }));
    assert.throws(() => wa.verifyRegistration(authn.create('abc', rp, o), { challenge: 'abc', origins: ['http://evil'], rpId: rp }));
  });

  const srv = spawn('node', [path.join(appDir, 'server.js')], { env, stdio: 'ignore' });
  for (let i = 0; i < 50; i++) { const r = await raw('GET', '/auth/login'); if (r.status === 200) break; await new Promise(r => setTimeout(r, 200)); }
  let adminCk = '', secret = '', recov = [];
  try {
    await check('compte sans MFA : connexion directe (pas de régression)', async () => {
      const r = await loginPw('admin', 'admin123'); assert.strictEqual(r.status, 302); assert.strictEqual(r.location, '/');
      adminCk = sess(r); assert.ok(adminCk);
    });
    await check('status MFA : désactivé au départ', async () => {
      const r = await raw('GET', '/api/mfa/status', { cookie: adminCk }); assert.strictEqual(r.json.enabled, false);
    });
    await check('activation TOTP : mauvais code refusé, bon code accepté + codes de secours', async () => {
      const s = await raw('POST', '/api/mfa/totp/setup', { cookie: adminCk, json: {} });
      secret = s.json.secret; assert.ok(/^otpauth:\/\/totp\//.test(s.json.uri));
      const bad = await raw('POST', '/api/mfa/totp/confirm', { cookie: adminCk, json: { code: '000000' } }); assert.strictEqual(bad.status, 400);
      const ok = await raw('POST', '/api/mfa/totp/confirm', { cookie: adminCk, json: { code: totp.hotp(secret, totp.counterAt()) } });
      assert.strictEqual(ok.status, 200); recov = ok.json.recoveryCodes; assert.strictEqual(recov.length, 10);
      assert.ok(fs.existsSync(path.join(tmp, 'config', 'mfa.json')));
      assert.strictEqual((fs.statSync(path.join(tmp, 'config', 'mfa.json')).mode & 0o777), 0o600);
    });
    await check('login avec MFA : pas de session avant le 2e facteur', async () => {
      const r = await loginPw('admin', 'admin123');
      assert.strictEqual(r.location, '/auth/mfa'); assert.ok(!sess(r)); assert.ok(mfaCk(r));
      const api = await raw('GET', '/api/mfa/status', { cookie: mfaCk(r) }); assert.strictEqual(api.status, 401);
    });
    await check('login : mauvais code TOTP refusé', async () => {
      const r = await loginPw('admin', 'admin123'); const ck = mfaCk(r);
      const b = await raw('POST', '/auth/mfa', { cookie: ck, body: 'mode=totp&code=111111' });
      assert.strictEqual(b.status, 200); assert.ok(!sess(b));
    });
    await check('login : bon code TOTP → session ; rejeu du même code refusé', async () => {
      // le code de l'activation (même fenêtre) est déjà consommé → il faut un pas suivant
      const code = totp.hotp(secret, totp.counterAt() + 1);
      const r = await loginPw('admin', 'admin123');
      const b = await raw('POST', '/auth/mfa', { cookie: mfaCk(r), body: `mode=totp&code=${code}` });
      assert.strictEqual(b.status, 302); assert.ok(sess(b));
      const r2 = await loginPw('admin', 'admin123');
      const b2 = await raw('POST', '/auth/mfa', { cookie: mfaCk(r2), body: `mode=totp&code=${code}` });
      assert.ok(!sess(b2), 'rejeu accepté');
    });
    await check('login : code de secours à usage unique', async () => {
      const r = await loginPw('admin', 'admin123');
      const b = await raw('POST', '/auth/mfa', { cookie: mfaCk(r), body: `mode=recovery&code=${recov[0]}` });
      assert.ok(sess(b)); adminCk = sess(b);
      const r2 = await loginPw('admin', 'admin123');
      const b2 = await raw('POST', '/auth/mfa', { cookie: mfaCk(r2), body: `mode=recovery&code=${recov[0]}` });
      assert.ok(!sess(b2));
    });
    await check('5 échecs → jeton en attente détruit', async () => {
      const r = await loginPw('admin', 'admin123'); const ck = mfaCk(r); let last;
      for (let i = 0; i < 5; i++) last = await raw('POST', '/auth/mfa', { cookie: ck, body: 'mode=totp&code=222222' });
      const after = await raw('POST', '/auth/mfa', { cookie: ck, body: `mode=totp&code=${totp.hotp(secret, totp.counterAt() + 1)}` });
      assert.ok(!sess(after));
    });
    await check('POST /auth/mfa depuis une autre origine refusé', async () => {
      const r = await loginPw('admin', 'admin123');
      const b = await raw('POST', '/auth/mfa', { cookie: mfaCk(r), body: 'mode=totp&code=1', headers: { Origin: 'http://evil.example' } });
      assert.strictEqual(b.status, 403);
    });
    await check('clé WebAuthn : enregistrement puis connexion', async () => {
      const o = await raw('POST', '/api/mfa/webauthn/options', { cookie: adminCk, json: {} });
      const pk = o.json.publicKey; assert.strictEqual(pk.rp.id, '127.0.0.1');
      const origin = `http://127.0.0.1:${PORT}`;
      const reg = await raw('POST', '/api/mfa/webauthn/register', { cookie: adminCk, json: { ...authn.create(pk.challenge, pk.rp.id, origin), name: 'YubiKey 5' } });
      assert.strictEqual(reg.status, 200, reg.text);
      const st = await raw('GET', '/api/mfa/status', { cookie: adminCk }); assert.strictEqual(st.json.keys.length, 1);
      const r = await loginPw('admin', 'admin123'); const ck = mfaCk(r);
      const page = await raw('GET', '/auth/mfa', { cookie: ck }); assert.ok(page.text.includes('mfa-login.js'));
      const op = await raw('POST', '/auth/mfa/webauthn/options', { cookie: ck, json: {} });
      assert.ok(op.json.publicKey.challenge);
      const v = await raw('POST', '/auth/mfa/webauthn/verify', { cookie: ck, json: authn.get(op.json.publicKey.challenge, op.json.publicKey.rpId, origin) });
      assert.strictEqual(v.json.ok, true, v.text); assert.ok(sess(v));
      // signature rejouée avec l'ancien challenge → refus
      const r2 = await loginPw('admin', 'admin123'); const ck2 = mfaCk(r2);
      const op2 = await raw('POST', '/auth/mfa/webauthn/options', { cookie: ck2, json: {} });
      const v2 = await raw('POST', '/auth/mfa/webauthn/verify', { cookie: ck2, json: authn.get(op.json.publicKey.challenge, op2.json.publicKey.rpId, origin) });
      assert.strictEqual(v2.json.ok, false);
    });
    await check('désactivation TOTP exige le mot de passe', async () => {
      const bad = await raw('POST', '/api/mfa/totp/disable', { cookie: adminCk, json: { password: 'nope' } }); assert.strictEqual(bad.status, 403);
      const ok = await raw('POST', '/api/mfa/totp/disable', { cookie: adminCk, json: { password: 'admin123' } }); assert.strictEqual(ok.status, 200);
    });
    await check('reset admin : réservé aux admins', async () => {
      const b = await loginPw('bob', 'bob12345'); const bc = sess(b);
      assert.strictEqual((await raw('POST', '/api/mfa/admin/reset', { cookie: bc, json: { username: 'admin' } })).status, 403);
      const ok = await raw('POST', '/api/mfa/admin/reset', { cookie: adminCk, json: { username: 'admin' } }); assert.strictEqual(ok.status, 200, ok.text);
      assert.strictEqual((await raw('GET', '/api/mfa/status', { cookie: adminCk })).json.enabled, false);
      const r = await loginPw('admin', 'admin123'); assert.strictEqual(r.location, '/');
    });
  } finally { srv.kill(); }
  console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})();
