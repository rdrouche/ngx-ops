'use strict';
/**
 * Stockage MFA — config/mfa.json (0600), séparé de users.yml (qui reste la
 * source de vérité des comptes, versionnable). Rien de secret n'entre dans
 * git : ce fichier est généré à l'exécution.
 *
 *  { users: { <username>: { totp: {secret, enabled, lastCounter, createdAt},
 *                           webauthn: [{id, name, publicKeyPem, alg, counter, createdAt}],
 *                           recovery: [sha256hex, ...] } } }
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cfg = require('./config');

const FILE = process.env.MFA_FILE || path.join(cfg.CONFIG_DIR, 'mfa.json');
const MAX_KEYS = 8;

function load() {
  try {
    const j = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    if (j && typeof j === 'object' && j.users && typeof j.users === 'object') return j;
  } catch { /* absent ou illisible → vide */ }
  return { users: {} };
}

function save(db) {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, FILE);
  try { fs.chmodSync(FILE, 0o600); } catch { /* best effort */ }
}

function getUser(username) {
  const u = load().users[username];
  return u || { totp: null, webauthn: [], recovery: [] };
}

function update(username, fn) {
  const db = load();
  const cur = db.users[username] || { totp: null, webauthn: [], recovery: [] };
  const next = fn(cur) || cur;
  const empty = !(next.totp && next.totp.enabled) && !(next.webauthn || []).length;
  if (empty) delete db.users[username]; else db.users[username] = next;
  save(db);
  return next;
}

function isEnabled(username) {
  const u = getUser(username);
  return !!((u.totp && u.totp.enabled) || (u.webauthn && u.webauthn.length));
}

function status(username) {
  const u = getUser(username);
  return {
    enabled: isEnabled(username),
    totp: !!(u.totp && u.totp.enabled),
    keys: (u.webauthn || []).map(k => ({ id: k.id, name: k.name, createdAt: k.createdAt })),
    recoveryLeft: (u.recovery || []).length,
  };
}

const hashCode = (c) => crypto.createHash('sha256').update(String(c).toUpperCase().replace(/[^A-Z0-9]/g, '')).digest('hex');

/** 10 codes de secours, lisibles (XXXXX-XXXXX), stockés hachés. */
function newRecoveryCodes(n = 10) {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const codes = [];
  for (let i = 0; i < n; i++) {
    const b = crypto.randomBytes(10);
    let s = ''; for (const x of b) s += A[x % A.length];
    codes.push(s.slice(0, 5) + '-' + s.slice(5));
  }
  return { codes, hashes: codes.map(hashCode) };
}

/** Consomme un code de secours (usage unique). */
function useRecovery(username, code) {
  const h = hashCode(code);
  let ok = false;
  update(username, (u) => {
    const i = (u.recovery || []).findIndex(x => {
      const a = Buffer.from(x), b = Buffer.from(h);
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    });
    if (i >= 0) { u.recovery.splice(i, 1); ok = true; }
    return u;
  });
  return ok;
}

module.exports = { FILE, MAX_KEYS, load, save, getUser, update, isEnabled, status, newRecoveryCodes, useRecovery, hashCode };
