'use strict';
/** Accès aux comptes du Hub (utilisé par les routes et par bin/hub-admin.js). */
const { hashPassword, seal, open } = require('../../lib/crypto');

const USERNAME_RE = /^[a-zA-Z0-9._-]{3,32}$/;
const ROLE_LIST = ['viewer', 'admin'];

function checkPassword(pw) {
  if (typeof pw !== 'string' || pw.length < 12) return 'mot de passe : 12 caractères minimum';
  if (pw.length > 256) return 'mot de passe trop long';
  if (/^(.)\1+$/.test(pw)) return 'mot de passe trop faible';
  return null;
}

function createUsers(db, key) {
  const q = {
    byName: 'SELECT * FROM users WHERE lower(username) = lower(?)',
    byId: 'SELECT * FROM users WHERE id = ?',
    insert: 'INSERT INTO users(username,pass_hash,role,created_at,must_change_password) VALUES (?,?,?,?,?)',
    setPw: 'UPDATE users SET pass_hash = ?, must_change_password = ?, failed_count = 0, locked_until = 0 WHERE id = ?',
    count: 'SELECT COUNT(*) AS n FROM users',
    fail: 'UPDATE users SET failed_count = ?, locked_until = ? WHERE id = ?',
    ok: 'UPDATE users SET failed_count = 0, locked_until = 0 WHERE id = ?',
    setSecret: 'UPDATE users SET mfa_secret_enc = ?, mfa_enabled = 0, mfa_last_step = 0 WHERE id = ?',
    enable: 'UPDATE users SET mfa_enabled = 1, mfa_last_step = ? WHERE id = ?',
    step: 'UPDATE users SET mfa_last_step = ? WHERE id = ?',
    resetMfa: 'UPDATE users SET mfa_secret_enc = NULL, mfa_enabled = 0, mfa_last_step = 0 WHERE id = ?',
    list: 'SELECT id, username, role, mfa_enabled, disabled, created_at FROM users ORDER BY lower(username)',
    disable: 'UPDATE users SET disabled = ? WHERE id = ?',
    setRole: 'UPDATE users SET role = ? WHERE id = ?',
  };
  const mfaAad = (id) => `user:${id}:mfa`;

  const one = (sql, p) => db.get(sql, p);
  return {
    getByName: (n) => one(q.byName, [String(n)]),
    getById: (id) => one(q.byId, [id]),
    count: async () => Number((await one(q.count)).n),
    async create({ username, password, role = 'viewer', mustChange = false }) {
      if (!USERNAME_RE.test(username || '')) throw new Error('identifiant : 3–32 caractères [a-zA-Z0-9._-]');
      if (!ROLE_LIST.includes(role)) throw new Error('rôle invalide (viewer|admin)');
      const bad = checkPassword(password);
      if (bad) throw new Error(bad);
      if (await one(q.byName, [username])) throw new Error('identifiant déjà utilisé');
      return db.insert(q.insert, [username, hashPassword(password), role, Date.now(), mustChange ? 1 : 0]);
    },
    async setPassword(id, password, { mustChange = false } = {}) {
      const bad = checkPassword(password);
      if (bad) throw new Error(bad);
      await db.run(q.setPw, [hashPassword(password), mustChange ? 1 : 0, id]);
    },
    /** @returns {Promise<boolean>} true si le compte vient d'être verrouillé */
    async recordFailure(user, maxFailures, lockMinutes) {
      const n = user.failed_count + 1;
      if (n >= maxFailures) { await db.run(q.fail, [0, Date.now() + lockMinutes * 60_000, user.id]); return true; }
      await db.run(q.fail, [n, user.locked_until, user.id]);
      return false;
    },
    recordSuccess: (id) => db.run(q.ok, [id]),
    isLocked: (user) => user.locked_until > Date.now(),
    beginMfaEnrollment: (id, secret) => db.run(q.setSecret, [seal(secret, key, mfaAad(id)), id]),
    getMfaSecret(user) { return user.mfa_secret_enc ? open(user.mfa_secret_enc, key, mfaAad(user.id)) : null; },
    enableMfa: (id, step) => db.run(q.enable, [step, id]),
    updateMfaStep: (id, step) => db.run(q.step, [step, id]),
    resetMfa: (id) => db.run(q.resetMfa, [id]),
    setDisabled: (id, v) => db.run(q.disable, [v ? 1 : 0, id]),
    async setRole(id, role) { if (!ROLE_LIST.includes(role)) throw new Error('rôle invalide'); await db.run(q.setRole, [role, id]); },
    list: () => db.all(q.list),
  };
}

module.exports = { createUsers, checkPassword, USERNAME_RE, ROLE_LIST };
