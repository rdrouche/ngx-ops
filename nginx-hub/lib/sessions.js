'use strict';
/**
 * Sessions serveur. L'identifiant brut n'existe que dans le cookie : la base ne stocke que son SHA-256.
 * États : 'mfa' (mot de passe validé, code TOTP attendu), 'enroll' (MFA obligatoire mais pas encore activé), 'active'.
 */
const { randomToken, sha256 } = require('./crypto');
const { parseCookies } = require('./http');

const COOKIE = 'hub_sid';
const PENDING_TTL_MS = 5 * 60 * 1000;
const TOUCH_EVERY_MS = 60 * 1000;

function createSessionStore(db, { ttlMs }) {
  const q = {
    insert: 'INSERT INTO sessions(id_hash,user_id,state,csrf,created_at,expires_at,last_seen,ip) VALUES (?,?,?,?,?,?,?,?)',
    get: `SELECT s.id_hash, s.user_id, s.state, s.csrf, s.expires_at, s.last_seen, u.username, u.role, u.mfa_enabled, u.disabled
                     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?`,
    touch: 'UPDATE sessions SET last_seen = ?, expires_at = ? WHERE id_hash = ?',
    del: 'DELETE FROM sessions WHERE id_hash = ?',
    delUser: 'DELETE FROM sessions WHERE user_id = ?',
    purge: 'DELETE FROM sessions WHERE expires_at < ?',
  };

  return {
    COOKIE,
    ttlMs,
    async create({ userId, state, ip }) {
      const sid = randomToken(32);
      const csrf = randomToken(24);
      const now = Date.now();
      const life = state === 'active' ? ttlMs : PENDING_TTL_MS;
      await db.run(q.insert, [sha256(sid), userId, state, csrf, now, now + life, now, ip || null]);
      return { sid, csrf, maxAgeSec: Math.floor(life / 1000) };
    },
    /** @returns {object|null} session (jamais l'identifiant brut) */
    async fromRequest(req) {
      const sid = parseCookies(req.headers.cookie)[COOKIE];
      if (!sid || sid.length > 128) return null;
      const idHash = sha256(sid);
      const row = await db.get(q.get, [idHash]);
      const now = Date.now();
      if (!row || row.expires_at < now || row.disabled) { if (row) await db.run(q.del, [idHash]); return null; }
      if (row.state === 'active' && now - row.last_seen > TOUCH_EVERY_MS) await db.run(q.touch, [now, now + ttlMs, idHash]);
      return { idHash, userId: row.user_id, username: row.username, role: row.role, state: row.state, csrf: row.csrf, mfaEnabled: !!row.mfa_enabled };
    },
    async destroy(idHash) { await db.run(q.del, [idHash]); },
    async destroyAllForUser(userId) { await db.run(q.delUser, [userId]); },
    async purgeExpired() { return (await db.run(q.purge, [Date.now()])).changes; },
  };
}

module.exports = { createSessionStore, COOKIE };
