'use strict';
/** Accès données des modules (instance_modules) et des alertes détaillées (hub_alerts). */

function createModulesRepo(db) {
  return {
    rows: (instanceId) => db.all('SELECT instance_id, module, status, fetched_at, last_ok_at, error, expose_ips, parts_errors FROM instance_modules WHERE instance_id = ? ORDER BY module', [instanceId]),
    row: (instanceId, module) => db.get('SELECT * FROM instance_modules WHERE instance_id = ? AND module = ?', [instanceId, module]),
    /** Toutes les instances actives avec la dernière charge utile (même obsolète) d'un module. */
    payloadsOf: (module) => db.all(
      `SELECT m.instance_id, i.name, m.status, m.fetched_at, m.payload FROM instance_modules m JOIN instances i ON i.id = m.instance_id
       WHERE m.module = ? AND i.enabled = 1 AND m.payload IS NOT NULL`, [module]),
    summaries: () => db.all('SELECT id, name, last_summary FROM instances WHERE enabled = 1'),
    moduleStatuses: (module) => db.all(
      `SELECT i.id, i.name, m.status, m.error, m.expose_ips FROM instances i LEFT JOIN instance_modules m ON m.instance_id = i.id AND m.module = ?
       WHERE i.enabled = 1 ORDER BY i.name`, [module]),
    fetchTimes: () => db.all('SELECT instance_id, module, fetched_at FROM instance_modules'),

    /** Succès : remplace la charge utile. Échec/absence : conserve la dernière charge utile valide (affichée « obsolète »). */
    saveOk: (id, module, now, { expose, errors, payload }) => db.run(
      `INSERT INTO instance_modules(instance_id,module,status,fetched_at,last_ok_at,error,expose_ips,parts_errors,payload)
       VALUES (?,?,?,?,?,?,?,?,?)
       ON CONFLICT(instance_id,module) DO UPDATE SET status = excluded.status, fetched_at = excluded.fetched_at, last_ok_at = excluded.last_ok_at,
         error = NULL, expose_ips = excluded.expose_ips, parts_errors = excluded.parts_errors, payload = excluded.payload`,
      [id, module, 'ok', now, now, null, expose ? 1 : 0, Object.keys(errors).length ? JSON.stringify(errors) : null, payload]),
    saveFail: (id, module, now, status, error) => db.run(
      `INSERT INTO instance_modules(instance_id,module,status,fetched_at,error) VALUES (?,?,?,?,?)
       ON CONFLICT(instance_id,module) DO UPDATE SET status = excluded.status, fetched_at = excluded.fetched_at, error = excluded.error`,
      [id, module, status, now, error]),

    // ---- alertes détaillées
    upsertAlert: (id, a) => db.run(
      `INSERT INTO hub_alerts(instance_id,remote_id,ts,type,severity,summary,vhost,country,acked,ip_count,evidence,ips) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(instance_id,remote_id) DO UPDATE SET ts = excluded.ts, type = excluded.type, severity = excluded.severity, summary = excluded.summary,
         vhost = excluded.vhost, country = excluded.country, acked = excluded.acked, ip_count = excluded.ip_count, evidence = excluded.evidence, ips = excluded.ips`,
      [id, a.remote_id, a.ts, a.type, a.severity, a.summary, a.vhost, a.country, a.acked, a.ip_count, a.evidence, a.ips]),
    markAcked: (id, remoteId) => db.run('UPDATE hub_alerts SET acked = 1 WHERE instance_id = ? AND remote_id = ?', [id, remoteId]),
    lastId: async (id) => Number((await db.get('SELECT alerts_last_id AS v FROM instances WHERE id = ?', [id]))?.v) || 0,
    setLastId: (id, v) => db.run('UPDATE instances SET alerts_last_id = ? WHERE id = ?', [v, id]),
    purgeAlerts: async (before) => (await db.run('DELETE FROM hub_alerts WHERE ts < ?', [before])).changes,

    async listAlerts({ instance, severity, type, acked, limit, offset }) {
      const where = []; const p = [];
      if (instance) { where.push('a.instance_id = ?'); p.push(instance); }
      if (severity) { where.push('a.severity = ?'); p.push(severity); }
      if (type) { where.push('a.type = ?'); p.push(type); }
      if (acked === 0 || acked === 1) { where.push('a.acked = ?'); p.push(acked); }
      const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
      const total = Number((await db.get(`SELECT COUNT(*) AS n FROM hub_alerts a ${w}`, p)).n);
      const items = await db.all(
        `SELECT a.instance_id, i.name AS instance, a.remote_id, a.ts, a.type, a.severity, a.summary, a.vhost, a.country, a.acked, a.ip_count, a.evidence, a.ips
         FROM hub_alerts a JOIN instances i ON i.id = a.instance_id ${w} ORDER BY a.ts DESC, a.remote_id DESC LIMIT ? OFFSET ?`, [...p, limit, offset]);
      return { total, items };
    },
    alertFacets: () => db.all('SELECT severity, type, acked, COUNT(*) AS n FROM hub_alerts GROUP BY severity, type, acked'),

    indicatorRows: () => db.all(
      `SELECT m.instance_id, i.name, m.fetched_at, m.payload FROM instance_modules m JOIN instances i ON i.id = m.instance_id
       WHERE m.module = 'indicators' AND m.status = 'ok' AND i.enabled = 1`),
  };
}

module.exports = { createModulesRepo };
