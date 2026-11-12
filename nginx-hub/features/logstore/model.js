'use strict';
/**
 * Vue Hub du log store (#62) : assainissement STRICT des agrégats reçus. Fonctions pures.
 * Aucune donnée de visiteur n'en sort : pas d'IP, de chemin, de User-Agent ni de referer. Seules des dimensions
 * agrégées de liste blanche sont conservées ; toute valeur qui ressemble à une IP est masquée (« [ip] »).
 */
const { maskIps } = require('../modules/sanitize');

const DIMENSIONS = ['site', 'country', 'rule', 'bot_class', 'source', 'action', 'status']; // tops demandés (jamais path, ua, referer_host, ip)
const INSTANCE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.round(v) : 0);
const label = (v) => maskIps(String(v == null ? '' : v)).slice(0, 120);
const isoMs = (v) => { const t = Date.parse(v); return Number.isFinite(t) ? t : null; };

function visits(raw) {
  const pts = isObj(raw) && Array.isArray(raw.points) ? raw.points : [];
  return {
    bucket: isObj(raw) && raw.bucket === 'day' ? 'day' : 'hour',
    points: pts.filter(isObj).slice(0, 800).map((p) => ({ t: isoMs(p.bucket), requests: num(p.requests), s2xx: num(p.s2xx), s3xx: num(p.s3xx), s4xx: num(p.s4xx), s5xx: num(p.s5xx), bytes: num(p.bytes) }))
      .filter((p) => p.t !== null).sort((a, b) => a.t - b.t),
  };
}

function top(raw) {
  const items = isObj(raw) && Array.isArray(raw.items) ? raw.items : [];
  return items.filter(isObj).slice(0, 50).map((x) => ({ key: label(x.key), count: num(x.count) })).filter((x) => x.key !== '');
}

function security(raw) {
  const r = isObj(raw) ? raw : {};
  const sc = isObj(r.status_classes) ? r.status_classes : {};
  const merged = new Map();
  for (const b of (Array.isArray(r.blocked) ? r.blocked : []).filter(isObj).slice(0, 100)) {
    const k = `${label(b.source)}|${label(b.action)}`;
    merged.set(k, (merged.get(k) || 0) + num(b.count));
  }
  return {
    status_classes: { s2xx: num(sc.s2xx), s3xx: num(sc.s3xx), s4xx: num(sc.s4xx), s5xx: num(sc.s5xx) },
    blocked: [...merged].map(([k, count]) => { const [source, action] = k.split('|'); return { source, action, count }; }).sort((a, b) => b.count - a.count),
    scanners: Array.isArray(r.scanners) ? Math.min(r.scanners.length, 100000) : 0, // nombre seulement : les IP des scanners ne sortent pas
  };
}

function instances(raw) {
  const list = isObj(raw) && Array.isArray(raw.instances) ? raw.instances : [];
  return list.filter(isObj).filter((i) => INSTANCE_RE.test(String(i.id || ''))).slice(0, 200)
    .map((i) => ({ id: String(i.id), name: label(i.name), first_seen: isoMs(i.first_seen), last_seen: isoMs(i.last_seen), events_total: num(i.events_total) }));
}

/** #127 : informations de la base (GET /v1/health). `detail` n'est présent que pour un jeton read global : sinon `null`. */
function store(raw) {
  const d = isObj(raw) && isObj(raw.detail) ? raw.detail : null;
  if (!d) return { reachable: isObj(raw) && raw.status === 'ok', detail: false };
  const ipMode = ['clear', 'pseudonymized', 'truncated'].includes(d.ip_mode) ? d.ip_mode : null;
  const ver = isObj(raw) && typeof raw.version === 'string' ? raw.version.replace(/[^A-Za-z0-9._+-]/g, '').slice(0, 32) : null;
  return { reachable: true, detail: true, version: ver || null, timescale: d.timescale === true, db_size_bytes: num(d.db_size_bytes),
    last_ingest: isoMs(d.last_ingest), retention_days: num(d.retention_days) || null, ip_mode: ipMode };
}

/** @param {{visits?:any, security?:any, instances?:any, health?:any, tops?:Object<string,any>}} parts réponses brutes (une partie absente = null) */
function shapeOverview(parts = {}) {
  const tops = {};
  for (const d of DIMENSIONS) if (parts.tops && parts.tops[d] != null) tops[d] = top(parts.tops[d]);
  const v = parts.visits != null ? visits(parts.visits) : null;
  return {
    visits: v,
    totals: v ? v.points.reduce((a, p) => ({ requests: a.requests + p.requests, s4xx: a.s4xx + p.s4xx, s5xx: a.s5xx + p.s5xx, bytes: a.bytes + p.bytes }), { requests: 0, s4xx: 0, s5xx: 0, bytes: 0 }) : null,
    security: parts.security != null ? security(parts.security) : null,
    tops,
    instances: parts.instances != null ? instances(parts.instances) : null,
    store: parts.health != null ? store(parts.health) : null,
  };
}

module.exports = { DIMENSIONS, INSTANCE_RE, shapeOverview, visits, top, security, instances, store };
