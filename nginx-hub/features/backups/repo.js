'use strict';
/** Accès données des sauvegardes (tables `backups` + colonnes backup_* de `instances`). Aucune logique HTTP. */
const { randomBytes } = require('node:crypto');

const COLS = 'id, instance_id, source, received_at, expires_at, sha256, size_bytes, encrypted, files, dashboard_version, remote_instance_id, retention_days';

function createBackupsRepo(db) {
  return {
    newId: () => 'bk_' + randomBytes(10).toString('hex'),

    findInstanceByPushSha: (sha) => db.get('SELECT id, slug, name, enabled, base_url FROM instances WHERE push_token_sha256 = ?', [sha]),
    getInstance: (id) => db.get('SELECT * FROM instances WHERE id = ?', [id]),

    findBySha: (instanceId, sha) => db.get(`SELECT ${COLS} FROM backups WHERE instance_id = ? AND sha256 = ?`, [instanceId, sha]),
    get: (id) => db.get(`SELECT ${COLS}, manifest FROM backups WHERE id = ?`, [id]),
    list: (instanceId, limit = 200) => db.all(`SELECT ${COLS}, manifest FROM backups WHERE instance_id = ? ORDER BY received_at DESC LIMIT ?`, [instanceId, limit]),

    async insert(b) {
      await db.run(`INSERT INTO backups(id,instance_id,source,received_at,expires_at,sha256,size_bytes,encrypted,files,dashboard_version,remote_instance_id,retention_days,manifest)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [b.id, b.instance_id, b.source, b.received_at, b.expires_at, b.sha256, b.size_bytes, b.encrypted ? 1 : 0, b.files ?? null,
        b.dashboard_version ?? null, b.remote_instance_id ?? null, b.retention_days ?? null, b.manifest ?? null]);
    },
    /** Doublon : on prolonge la rétention (jamais on ne la raccourcit). */
    extend: (id, expiresAt) => db.run('UPDATE backups SET expires_at = ? WHERE id = ? AND expires_at < ?', [expiresAt, id, expiresAt]),
    remove: async (id) => (await db.run('DELETE FROM backups WHERE id = ?', [id])).changes > 0,

    /** Supprime les lignes expirées ; renvoie les sha256 concernés (les blobs orphelins sont nettoyés par gc). */
    async deleteExpired(now) {
      const r = await db.run('DELETE FROM backups WHERE expires_at < ?', [now]);
      return r.changes;
    },
    /** Garde-fou disque : ne conserve que les N plus récentes d'une instance. */
    async trim(instanceId, keep) {
      const rows = await db.all('SELECT id FROM backups WHERE instance_id = ? ORDER BY received_at DESC', [instanceId]);
      let n = 0;
      for (const r of rows.slice(keep)) { await db.run('DELETE FROM backups WHERE id = ?', [r.id]); n++; }
      return n;
    },
    async referencedShas() { return new Set((await db.all('SELECT DISTINCT sha256 FROM backups')).map((r) => r.sha256)); },
    countRefs: async (sha) => Number((await db.get('SELECT COUNT(*) AS n FROM backups WHERE sha256 = ?', [sha])).n),

    setPushToken: (id, sha, hint, now) => db.run('UPDATE instances SET push_token_sha256 = ?, push_token_hint = ?, backup_expected_since = COALESCE(backup_expected_since, ?) WHERE id = ?', [sha, hint, now, id]),
    clearPushToken: (id) => db.run('UPDATE instances SET push_token_sha256 = NULL, push_token_hint = NULL WHERE id = ?', [id]),
    setBackupToken: (id, enc, hint, now) => db.run('UPDATE instances SET backup_token_enc = ?, backup_token_hint = ?, backup_expected_since = COALESCE(backup_expected_since, ?) WHERE id = ?', [enc, hint, now, id]),
    clearBackupToken: (id) => db.run('UPDATE instances SET backup_token_enc = NULL, backup_token_hint = NULL WHERE id = ?', [id]),

    markOk: (id, ts) => db.run('UPDATE instances SET last_backup_at = ?, last_backup_try_at = ?, last_backup_error = NULL WHERE id = ?', [ts, ts, id]),
    markFail: (id, ts, code) => db.run('UPDATE instances SET last_backup_try_at = ?, last_backup_error = ? WHERE id = ?', [ts, String(code).slice(0, 40), id]),

    /** Une ligne par instance : état de configuration + dernière sauvegarde. */
    overviewRows: () => db.all(`SELECT i.id, i.slug, i.name, i.enabled, i.created_at, i.push_token_hint, i.backup_token_hint,
        (i.push_token_sha256 IS NOT NULL) AS push_on, (i.backup_token_enc IS NOT NULL) AS pull_on,
        i.backup_expected_since, i.last_backup_at, i.last_backup_try_at, i.last_backup_error,
        (SELECT COUNT(*) FROM backups b WHERE b.instance_id = i.id) AS count,
        (SELECT COALESCE(SUM(size_bytes), 0) FROM backups b WHERE b.instance_id = i.id) AS bytes
        FROM instances i ORDER BY lower(i.name)`),
    /** Instances éligibles au pull (jeton de pull présent, activées). */
    pullCandidates: () => db.all('SELECT * FROM instances WHERE enabled = 1 AND backup_token_enc IS NOT NULL'),
  };
}

module.exports = { createBackupsRepo };
