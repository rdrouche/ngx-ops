'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeApp, client, totpAt } = require('./helpers');
const { createUsers } = require('../features/auth/users');
const { ensureBootstrapAdmin } = require('../features/auth/bootstrap');
const { openStore } = require('../lib/store');
const { loadConfig } = require('../lib/config');
const { KEY } = require('./helpers');

const P = '/api/hub/v1';
const silent = { warn() {} };

test('premier démarrage : admin créé, mot de passe affiché une seule fois, changement obligatoire puis MFA', async (t) => {
  let printed = '';
  const { app, base } = await makeApp({ security: { bootstrap_admin: true, mfa_policy: 'required' } }, { banner: (s) => { printed += s; } });
  t.after(() => app.stop());
  const m = printed.match(/Identifiant\s+: (\S+)\n\s+Mot de passe\s+: (\S+)/);
  assert.ok(m, 'la bannière contient identifiant et mot de passe');
  const [, user, initial] = m;
  assert.equal(user, 'admin'); assert.ok(initial.length >= 20);

  const c = client(base);
  const login = await c.post(`${P}/auth/login`, { username: 'admin', password: initial });
  assert.equal(login.json.state, 'pwchange');
  assert.equal((await c.get(`${P}/instances`)).json.error.code, 'password_change_required');
  assert.equal((await c.get(`${P}/overview`)).status, 403);
  assert.equal((await c.get(`${P}/auth/me`)).json.state, 'pwchange');
  assert.equal((await c.post(`${P}/auth/mfa/enroll`)).status, 403, 'pas d\'enrôlement MFA avant le changement de mot de passe');

  assert.equal((await c.post(`${P}/auth/password`, { current: 'faux', next: 'nouveau mot de passe 1' })).status, 401);
  assert.equal((await c.post(`${P}/auth/password`, { current: initial, next: initial })).status, 400);
  assert.equal((await c.post(`${P}/auth/password`, { current: initial, next: 'court' })).status, 400);
  const changed = await c.post(`${P}/auth/password`, { current: initial, next: 'nouveau mot de passe 1' });
  assert.equal(changed.json.state, 'enroll', 'étape suivante : MFA obligatoire');

  const enr = await c.post(`${P}/auth/mfa/enroll`);
  const done = await c.post(`${P}/auth/mfa/confirm`, { code: totpAt(enr.json.secret) });
  assert.equal(done.json.state, 'active');
  assert.equal((await c.get(`${P}/instances`)).status, 200);

  // l'ancien mot de passe initial ne fonctionne plus
  assert.equal((await client(base).post(`${P}/auth/login`, { username: 'admin', password: initial })).status, 401);
});

test('pas de recréation si des comptes existent ; désactivable ; mot de passe imposé jamais affiché', async () => {
  const cfg0 = loadConfig({ file: '/none' });
  const db = await openStore(cfg0, { file: ':memory:' });
  const users = createUsers(db, KEY);
  const cfg = loadConfig({ file: '/none' });
  let out = '';
  const banner = (s) => { out += s; };
  assert.ok(await ensureBootstrapAdmin({ users, config: cfg, banner, log: silent, env: { HUB_BOOTSTRAP_ADMIN_PASSWORD: 'mot de passe imposé 42' } }));
  assert.ok(!out.includes('mot de passe imposé 42'), 'le mot de passe imposé n\'est pas écrit dans les logs');
  assert.equal((await users.getByName('admin')).must_change_password, 1);
  assert.equal(await ensureBootstrapAdmin({ users, config: cfg, banner, log: silent, env: {} }), null, 'second démarrage : rien');
  assert.equal(await users.count(), 1);

  const db2 = await openStore(cfg, { file: ':memory:' });
  const off = loadConfig({ file: '/none', overrides: { security: { bootstrap_admin: false } } });
  assert.equal(await ensureBootstrapAdmin({ users: createUsers(db2, KEY), config: off, banner, log: silent, env: {} }), null);
});

test('mot de passe imposé trop court : ignoré, mot de passe aléatoire utilisé', async () => {
  const users = createUsers(await openStore(loadConfig({ file: '/none' }), { file: ':memory:' }), KEY);
  let out = '';
  await ensureBootstrapAdmin({ users, config: loadConfig({ file: '/none' }), banner: (s) => { out += s; }, log: silent, env: { HUB_BOOTSTRAP_ADMIN_PASSWORD: 'court' } });
  assert.match(out, /Mot de passe\s+: \S{20,}/);
});
