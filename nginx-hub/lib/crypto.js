'use strict';
/**
 * Primitives cryptographiques (node:crypto uniquement).
 *  - seal/open : AES-256-GCM pour chiffrer les secrets stockés (tokens d'instances, secrets TOTP)
 *  - hashPassword/verifyPassword : scrypt + sel aléatoire
 *  - randomToken / sha256 / safeEqual
 */
const crypto = require('node:crypto');
const fs = require('node:fs');

function loadMasterKey(env = process.env) {
  let raw = env.HUB_SECRET_KEY;
  if (!raw && env.HUB_SECRET_KEY_FILE) raw = fs.readFileSync(env.HUB_SECRET_KEY_FILE, 'utf8');
  if (!raw) {
    throw new Error('Clé maîtresse absente : définir HUB_SECRET_KEY (32 octets : 64 caractères hexadécimaux ou base64) ou HUB_SECRET_KEY_FILE. '
      + 'Générer avec : node bin/hub-admin.js generate-key');
  }
  // 64 caractères hexadécimaux (ex. `openssl rand -hex 32`) ou base64 (44 caractères) : sans ambiguïté, les longueurs diffèrent
  const t = raw.trim();
  const key = /^[0-9a-fA-F]{64}$/.test(t) ? Buffer.from(t, 'hex') : Buffer.from(t, 'base64');
  if (key.length !== 32) throw new Error('HUB_SECRET_KEY invalide : 32 octets attendus (64 caractères hexadécimaux ou base64).');
  return key;
}

function generateKey(encoding = 'base64') { return crypto.randomBytes(32).toString(encoding === 'hex' ? 'hex' : 'base64'); }

/** Format : v1.<iv>.<tag>.<ciphertext> (base64url). `aad` lie le secret à son contexte (ex. "instance:12"). */
function seal(plain, key, aad = '') {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return ['v1', iv.toString('base64url'), c.getAuthTag().toString('base64url'), ct.toString('base64url')].join('.');
}

function open(sealed, key, aad = '') {
  const [v, iv, tag, ct] = String(sealed).split('.');
  if (v !== 'v1' || !iv || !tag || ct === undefined) throw new Error('secret scellé invalide');
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8');
}

const SCRYPT = { N: 32768, r: 8, p: 1, keylen: 32, maxmem: 96 * 1024 * 1024 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(String(password), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64url')}$${h.toString('base64url')}`;
}

function verifyPassword(password, stored) {
  try {
    const [alg, N, r, p, salt, hash] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hash, 'base64url');
    const got = crypto.scryptSync(String(password), Buffer.from(salt, 'base64url'), expected.length,
      { N: +N, r: +r, p: +p, maxmem: SCRYPT.maxmem });
    return crypto.timingSafeEqual(got, expected);
  } catch { return false; }
}

/** Hash factice pour égaliser le temps de réponse quand l'utilisateur n'existe pas. */
const DUMMY_HASH = hashPassword(crypto.randomBytes(8).toString('hex'));

function randomToken(bytes = 32) { return crypto.randomBytes(bytes).toString('base64url'); }
function sha256(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }

/** Comparaison à temps constant, indépendante des longueurs. */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

module.exports = { loadMasterKey, generateKey, seal, open, hashPassword, verifyPassword, DUMMY_HASH, randomToken, sha256, safeEqual };
