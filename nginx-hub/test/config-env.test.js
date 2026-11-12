'use strict';
// #122 : déploiement rapide par variables d'environnement (sans hub.yml) ; le mot de passe PostgreSQL ne vient jamais du YAML.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadConfig } = require('../lib/config');
const { pgPassword } = require('../lib/store');

const load = (env, file) => loadConfig({ env: { HUB_DATA_DIR: os.tmpdir(), ...env }, file: file || '/nonexistent/hub.yml' });

test('sans fichier : valeurs par défaut (log store désactivé)', () => {
  const c = load({});
  assert.equal(c.logstore.enabled, false); assert.equal(c.logstore.url, ''); assert.equal(c.server.public_base_url, '');
});

test('HUB_PUBLIC_BASE_URL, HUB_LOGSTORE_ENABLED et HUB_LOGSTORE_URL suffisent', () => {
  const c = load({ HUB_PUBLIC_BASE_URL: 'https://hub.exemple.fr', HUB_LOGSTORE_ENABLED: 'true', HUB_LOGSTORE_URL: 'https://logs.exemple.fr' });
  assert.equal(c.server.public_base_url, 'https://hub.exemple.fr');
  assert.equal(c.logstore.enabled, true); assert.equal(c.logstore.url, 'https://logs.exemple.fr');
});

test('HUB_LOGSTORE_ENABLED : 1/yes/on actifs, false/0 inactifs, vide ou absent = valeur du YAML', () => {
  for (const v of ['1', 'true', 'YES', 'on']) assert.equal(load({ HUB_LOGSTORE_ENABLED: v }).logstore.enabled, true, v);
  for (const v of ['false', '0', 'off', 'n’importe quoi']) assert.equal(load({ HUB_LOGSTORE_ENABLED: v }).logstore.enabled, false, v);
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hubcfg-')), 'hub.yml');
  fs.writeFileSync(f, 'logstore:\n  enabled: true\n  url: https://yaml.exemple.fr\n');
  assert.equal(load({}, f).logstore.enabled, true);
  assert.equal(load({ HUB_LOGSTORE_ENABLED: '' }, f).logstore.enabled, true);
  assert.equal(load({ HUB_LOGSTORE_ENABLED: 'false' }, f).logstore.enabled, false, 'la variable l’emporte sur le YAML');
  assert.equal(load({ HUB_LOGSTORE_URL: 'https://env.exemple.fr' }, f).logstore.url, 'https://env.exemple.fr');
});

test('mot de passe PostgreSQL : variable, fichier prioritaire, jamais le YAML', () => {
  assert.equal(pgPassword({}), undefined);
  assert.equal(pgPassword({ HUB_DB_PASSWORD: 'secret' }), 'secret');
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hubpw-')), 'pw');
  fs.writeFileSync(f, 'depuis-fichier\n');
  assert.equal(pgPassword({ HUB_DB_PASSWORD: 'secret', HUB_DB_PASSWORD_FILE: f }), 'depuis-fichier');
  const y = path.join(path.dirname(f), 'hub.yml');
  fs.writeFileSync(y, 'storage:\n  driver: postgres\n  postgres:\n    password: dans-le-yaml\n');
  assert.equal(pgPassword({}), undefined, 'un mot de passe écrit dans le YAML n’est jamais utilisé');
});

test('clé maîtresse : hexadécimal (64 car.) ou base64 (32 octets), même clé ; formes invalides refusées', () => {
  const { loadMasterKey, generateKey } = require('../lib/crypto');
  const raw = require('node:crypto').randomBytes(32);
  assert.deepEqual(loadMasterKey({ HUB_SECRET_KEY: raw.toString('hex') }), raw);
  assert.deepEqual(loadMasterKey({ HUB_SECRET_KEY: raw.toString('hex').toUpperCase() + '\n' }), raw);
  assert.deepEqual(loadMasterKey({ HUB_SECRET_KEY: raw.toString('base64') }), raw);
  assert.equal(generateKey('hex').length, 64); assert.equal(generateKey().length, 44);
  assert.deepEqual(loadMasterKey({ HUB_SECRET_KEY: generateKey('hex') }).length, 32);
  assert.throws(() => loadMasterKey({ HUB_SECRET_KEY: raw.toString('hex').slice(2) }), /32 octets/);
  assert.throws(() => loadMasterKey({ HUB_SECRET_KEY: 'zz'.repeat(32) }), /32 octets/);
  assert.throws(() => loadMasterKey({}), /absente/);
});
