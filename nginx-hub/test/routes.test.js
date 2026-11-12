'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeApp, client, login, fakeDashboard, GOOD_SUMMARY, generateSecret, totpAt } = require('./helpers');

const P = '/api/hub/v1';
const PW = 'correct horse battery';

test('santé publique minimale + en-têtes de sécurité', async (t) => {
  const { app, base } = await makeApp(); t.after(() => app.stop());
  const r = await fetch(base + '/healthz');
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), { status: 'ok' });
  assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('cache-control'), 'no-store');
});

test('API protégée : 401 sans session, 404 route inconnue, 405 mauvaise méthode', async (t) => {
  const { app, base } = await makeApp(); t.after(() => app.stop());
  assert.equal((await client(base).get(`${P}/instances`)).status, 401);
  assert.equal((await client(base).get(`${P}/nope`)).status, 404);
  assert.equal((await client(base).call('PUT', '/healthz', {})).status, 405);
});

test('connexion : erreur générique, verrouillage, session, CSRF requis', async (t) => {
  const { app, base, users } = await makeApp(); t.after(() => app.stop());
  await users.create({ username: 'root', password: PW, role: 'admin' });
  const bad = await client(base).post(`${P}/auth/login`, { username: 'root', password: 'x' });
  const unknown = await client(base).post(`${P}/auth/login`, { username: 'ghost', password: 'x' });
  assert.equal(bad.status, 401); assert.equal(unknown.status, 401);
  assert.equal(bad.json.error.message, unknown.json.error.message);

  const { c, r } = await login(base, 'root', PW);
  assert.equal(r.status, 200); assert.equal(r.json.state, 'active');
  assert.match(r.headers.get('set-cookie'), /HttpOnly/); assert.match(r.headers.get('set-cookie'), /SameSite=Strict/);
  // sans CSRF → refusé
  const noCsrf = await c.call('POST', `${P}/instances`, { name: 'x', url: 'http://127.0.0.1:9' }, { 'X-CSRF-Token': 'faux' });
  assert.equal(noCsrf.status, 403); assert.equal(noCsrf.json.error.code, 'bad_csrf');
  // origine étrangère → refusée
  const evil = await c.call('POST', `${P}/instances`, { name: 'x', url: 'http://127.0.0.1:9' }, { Origin: 'https://evil.example' });
  assert.equal(evil.status, 403); assert.equal(evil.json.error.code, 'bad_origin');
});

test('verrouillage après N échecs', async (t) => {
  const { app, base, users } = await makeApp({ security: { login_max_failures: 3 } }); t.after(() => app.stop());
  await users.create({ username: 'root', password: PW, role: 'admin' });
  for (let i = 0; i < 3; i++) await client(base).post(`${P}/auth/login`, { username: 'root', password: 'mauvais' });
  const r = await client(base).post(`${P}/auth/login`, { username: 'root', password: PW });
  assert.equal(r.status, 401, 'compte verrouillé même avec le bon mot de passe');
});

test('MFA obligatoire : enrôlement, confirmation, puis connexion en 2 étapes avec anti-rejeu', async (t) => {
  const { app, base, users } = await makeApp({ security: { mfa_policy: 'required' } }); t.after(() => app.stop());
  await users.create({ username: 'root', password: PW, role: 'admin' });
  const { c, r } = await login(base, 'root', PW);
  assert.equal(r.json.state, 'enroll');
  assert.equal((await c.get(`${P}/instances`)).json.error.code, 'mfa_enrollment_required');
  const enr = await c.post(`${P}/auth/mfa/enroll`);
  assert.equal(enr.status, 200); assert.match(enr.json.otpauth_uri, /^otpauth:\/\/totp\//);
  assert.equal((await c.post(`${P}/auth/mfa/confirm`, { code: '000000' })).status, 401);
  const ok = await c.post(`${P}/auth/mfa/confirm`, { code: totpAt(enr.json.secret) });
  assert.equal(ok.json.state, 'active');
  assert.equal((await c.get(`${P}/instances`)).status, 200);

  // nouvelle connexion : mot de passe → état mfa → code
  const c2 = client(base);
  const l2 = await c2.post(`${P}/auth/login`, { username: 'root', password: PW });
  assert.equal(l2.json.state, 'mfa');
  assert.equal((await c2.get(`${P}/instances`)).json.error.code, 'mfa_required');
  // le code du pas courant a déjà été consommé à la confirmation → rejeu refusé
  const replay = await c2.post(`${P}/auth/mfa/verify`, { code: totpAt(enr.json.secret) });
  assert.equal(replay.status, 401);
  const future = await c2.post(`${P}/auth/mfa/verify`, { code: totpAt(enr.json.secret, Date.now() + 30_000) });
  assert.equal(future.json.state, 'active');
});

test('rôles : viewer lecture seule, admin écriture', async (t) => {
  const { app, base, users } = await makeApp(); t.after(() => app.stop());
  await users.create({ username: 'root', password: PW, role: 'admin' });
  await users.create({ username: 'lecteur', password: PW, role: 'viewer' });
  const admin = (await login(base, 'root', PW)).c;
  const viewer = (await login(base, 'lecteur', PW)).c;
  const body = { name: 'Paris', url: 'http://127.0.0.1:9' };
  assert.equal((await viewer.post(`${P}/instances`, body)).status, 403);
  assert.equal((await viewer.get(`${P}/instances`)).status, 200);
  assert.equal((await viewer.get(`${P}/audit`)).status, 403);
  assert.equal((await admin.post(`${P}/instances`, body)).status, 201);
  assert.equal((await admin.get(`${P}/audit`)).status, 200);
});

test('instances : CRUD, token jamais renvoyé en clair après création, rotation, hash fourni', async (t) => {
  const { app, base, users } = await makeApp(); t.after(() => app.stop());
  await users.create({ username: 'root', password: PW, role: 'admin' });
  const a = (await login(base, 'root', PW)).c;
  const created = await a.post(`${P}/instances`, { name: 'Paris', url: 'http://127.0.0.1:9/', tags: ['prod'] });
  assert.equal(created.status, 201);
  assert.match(created.json.token_once, /^hubt_/);
  assert.equal(created.json.token_sha256.length, 64);
  assert.equal(created.json.instance.url, 'http://127.0.0.1:9');
  const id = created.json.instance.id;

  const list = await a.get(`${P}/instances`);
  assert.ok(!JSON.stringify(list.json).includes(created.json.token_once), 'le token ne fuit pas');
  assert.ok(!('token_enc' in list.json.items[0]));
  assert.equal((await a.get(`${P}/instances/abc`)).status, 404);

  const upd = await a.patch(`${P}/instances/${id}`, { name: 'Paris 2', enabled: false });
  assert.equal(upd.json.name, 'Paris 2'); assert.equal(upd.json.status, 'disabled');
  assert.equal((await a.patch(`${P}/instances/${id}`, { token: 'hubt_aaaaaaaaaaaaaaaaaaaa' })).status, 400);

  const rot = await a.post(`${P}/instances/${id}/rotate-token`, {});
  assert.notEqual(rot.json.token_once, created.json.token_once);
  assert.equal((await a.post(`${P}/instances/${id}/rotate-token`, { token: 'court' })).status, 400);

  assert.equal((await a.del(`${P}/instances/${id}`)).status, 200);
  assert.equal((await a.get(`${P}/instances/${id}`)).status, 404);
});

test('instances : validation SSRF des URLs', async (t) => {
  const { app, base, users } = await makeApp({ security: { allow_insecure_http: false, allow_private_networks: false } }); t.after(() => app.stop());
  await users.create({ username: 'root', password: PW, role: 'admin' });
  const a = (await login(base, 'root', PW)).c;
  for (const url of ['http://example.org', 'https://169.254.169.254', 'https://127.0.0.1', 'https://10.0.0.5', 'https://user:pw@example.org',
    'https://[::1]', 'https://[::ffff:7f00:1]', 'ftp://example.org', 'https://example.org/?a=1', 'pas une url', 'https://nas.internal']) {
    const r = await a.post(`${P}/instances`, { name: 'x', url });
    assert.equal(r.status, 400, url + ' devrait être refusée');
  }
  assert.equal((await a.post(`${P}/instances`, { name: 'ok', url: 'https://dashboard.example.org/ngx/' })).status, 201);
});

