'use strict';
/** Accès données : inventaire des instances + série temporelle légère. Aucune logique HTTP ici. */
const { seal, open, randomToken, sha256 } = require('../../lib/crypto');

const RANGES = {
  '24h': { ms: 24 * 3600e3, bucketMs: 300e3 },
  '7d': { ms: 7 * 24 * 3600e3, bucketMs: 1800e3 },
  '30d': { ms: 30 * 24 * 3600e3, bucketMs: 7200e3 },
};

const aad = (slug) => `instance:${slug}`;

function slugify(name) {
  return String(name).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'instance';
}

function generateToken() { return 'hubt_' + randomToken(32); }

function createInstancesRepo(db, key) {
  const q = {
    all: 'SELECT * FROM instances ORDER BY lower(name)',
    byId: 'SELECT * FROM instances WHERE id = ?',
    bySlug: 'SELECT id FROM instances WHERE slug = ?',
    insert: `INSERT INTO instances(slug,name,base_url,token_enc,token_hint,tags,enabled,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?)`,
    del: 'DELETE FROM instances WHERE id = ?',
    setToken: 'UPDATE instances SET token_enc = ?, token_hint = ?, updated_at = ?, consecutive_failures = 0 WHERE id = ?',
    poll: `UPDATE instances SET status = ?, last_contact_at = ?, last_ok_at = COALESCE(?, last_ok_at), last_latency_ms = ?,
                      consecutive_failures = ?, last_error = ?, last_summary = COALESCE(?, last_summary) WHERE id = ?`,
    sample: `INSERT INTO samples(instance_id,ts,ok,latency_ms,req_humans,req_robots,alerts_active,vhosts,req_total,req_errors,bytes_out) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    purge: 'DELETE FROM samples WHERE ts < ?',
    purgeAudit: 'DELETE FROM audit WHERE ts < ?',
    history: `SELECT CAST(ts / ? AS BIGINT) * ? AS t, AVG(ok) AS up, AVG(latency_ms) AS latency, MAX(alerts_active) AS alerts,
                         AVG(req_humans) AS humans, AVG(req_robots) AS robots, MAX(vhosts) AS vhosts,
                         MAX(req_total) AS requests, MAX(req_errors) AS errors, MAX(bytes_out) AS bytes
                         FROM samples WHERE instance_id = ? AND ts >= ? GROUP BY t ORDER BY t`,
  };

  const hint = (token) => '…' + token.slice(-4);

  return {
    RANGES,
    list: () => db.all(q.all),
    get: (id) => db.get(q.byId, [id]),

    async create({ name, url, token, tags = [], enabled = true }) {
      let slug = slugify(name); let n = 2;
      while (await db.get(q.bySlug, [slug])) slug = `${slugify(name)}-${n++}`;
      const plain = token || generateToken();
      const now = Date.now();
      const id = await db.insert(q.insert, [slug, name, url, seal(plain, key, aad(slug)), hint(plain), JSON.stringify(tags), enabled ? 1 : 0, now, now]);
      return { id, token: plain, generated: !token };
    },

    async update(id, patch) {
      const cur = await db.get(q.byId, [id]);
      if (!cur) return false;
      const next = {
        name: patch.name ?? cur.name,
        base_url: patch.url ?? cur.base_url,
        tags: patch.tags ? JSON.stringify(patch.tags) : cur.tags,
        enabled: patch.enabled === undefined ? cur.enabled : (patch.enabled ? 1 : 0),
      };
      await db.run('UPDATE instances SET name=?, base_url=?, tags=?, enabled=?, updated_at=? WHERE id=?',
        [next.name, next.base_url, next.tags, next.enabled, Date.now(), id]);
      return true;
    },

    remove: async (id) => (await db.run(q.del, [id])).changes > 0,

    async rotateToken(id, token) {
      const cur = await db.get(q.byId, [id]);
      if (!cur) return null;
      const plain = token || generateToken();
      await db.run(q.setToken, [seal(plain, key, aad(cur.slug)), hint(plain), Date.now(), id]);
      return { token: plain, generated: !token };
    },

    /** Déchiffre le token — à n'utiliser que pour construire la requête sortante. */
    getToken(row) { return open(row.token_enc, key, aad(row.slug)); },
    tokenSha256: (token) => sha256(token),

    async recordPoll(id, { status, ok, latencyMs, failures, error, summary, ts = Date.now() }) {
      await db.run(q.poll, [status, ts, ok ? ts : null, latencyMs ?? null, failures, error || null, summary ? JSON.stringify(summary) : null, id]);
      const t24 = summary && summary.traffic_24h.available ? summary.traffic_24h : null;
      await db.run(q.sample, [id, ts, ok ? 1 : 0, latencyMs ?? null,
        t24 ? t24.humans : null, t24 ? t24.robots : null,
        summary ? summary.alerts.active : null, summary ? summary.vhosts.count : null,
        t24 ? t24.requests : null, t24 ? t24.errors : null, t24 ? t24.bytes : null]);
    },

    async history(id, rangeKey) {
      const r = RANGES[rangeKey] || RANGES['24h'];
      return (await db.all(q.history, [r.bucketMs, r.bucketMs, id, Date.now() - r.ms])).map((p) => ({
        t: Number(p.t), up: p.up, latency_ms: p.latency, alerts: p.alerts, humans: p.humans, robots: p.robots, vhosts: p.vhosts, requests: p.requests, errors: p.errors, bytes: p.bytes,
      }));
    },

    async purge(retentionDays, now = Date.now()) {
      const s = (await db.run(q.purge, [now - retentionDays * 86400e3])).changes;
      const a = (await db.run(q.purgeAudit, [now - 365 * 86400e3])).changes;
      return { samples: s, audit: a };
    },
  };
}

module.exports = { createInstancesRepo, generateToken, slugify, RANGES };
