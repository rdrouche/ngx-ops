'use strict';
/**
 * Données détaillées exposées au Hub (v12.78.0) : alertes et vue sécurité.
 * Fonctions pures. Les adresses IP de visiteurs ne sortent QUE si `expose_ips: true`
 * (config/hub.yml) — sinon elles sont retirées de chaque alerte (champs ip / ips, y compris
 * imbriqués), ce qui rend la corrélation entre instances impossible mais préserve la vie privée.
 */
const IP_KEYS = new Set(['ip', 'ips', 'clientip', 'client_ip', 'sourceip', 'topips', 'addresses']);
const MAX_EVIDENCE_CHARS = 4000;
const MAX_IPS = 200;

function isIp(s) { return typeof s === 'string' && /^[0-9a-f:.]{3,45}$/i.test(s) && (s.includes('.') || s.includes(':')); }

/** Copie de l'evidence sans IP (profondeur bornée) ; renvoie { evidence, ips }. */
function scrub(ev, exposeIps, depth = 0, ips = new Set()) {
  if (ev == null || depth > 4) return { evidence: ev, ips };
  if (Array.isArray(ev)) {
    const out = ev.slice(0, 50).map(v => (isIp(v) ? (ips.add(v), exposeIps ? v : null) : scrub(v, exposeIps, depth + 1, ips).evidence)).filter(v => v !== null);
    return { evidence: out, ips };
  }
  if (typeof ev === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(ev)) {
      if (IP_KEYS.has(k.toLowerCase())) {
        for (const x of (Array.isArray(v) ? v : [v])) {
          const val = x && typeof x === 'object' ? x.ip : x;
          if (isIp(val)) ips.add(val);
        }
        if (exposeIps) out[k] = v;
        continue;
      }
      out[k] = scrub(v, exposeIps, depth + 1, ips).evidence;
    }
    return { evidence: out, ips };
  }
  return { evidence: typeof ev === 'string' ? ev.slice(0, 300) : ev, ips };
}

function shapeAlert(a, exposeIps) {
  const { evidence, ips } = scrub(a.evidence, exposeIps);
  let ev = evidence;
  if (ev && JSON.stringify(ev).length > MAX_EVIDENCE_CHARS) ev = { truncated: true };
  const o = {
    id: a.id, ts: a.ts, type: String(a.type || '').slice(0, 60), severity: String(a.severity || 'low').slice(0, 20),
    summary: String(a.summary || '').slice(0, 300), vhost: ev && ev.vhost ? String(ev.vhost).slice(0, 253) : (a.vhost || null),
    country: ev && ev.country ? String(ev.country).slice(0, 8) : null, acked: !!a.acked, ip_count: ips.size, evidence: ev,
  };
  if (exposeIps) o.ips = [...ips].slice(0, MAX_IPS);
  return o;
}

function shapeAlerts(list, exposeIps) { return (Array.isArray(list) ? list : []).map(a => shapeAlert(a, exposeIps)); }

/** Comptage par type / gravité. */
function tally(alerts) {
  const byType = {}, bySeverity = {};
  for (const a of alerts) { byType[a.type] = (byType[a.type] || 0) + 1; bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1; }
  return { by_type: byType, by_severity: bySeverity };
}

/** IP les plus actives (toutes alertes confondues) — uniquement si exposeIps. */
function topIps(alerts, n = 50) {
  const m = new Map();
  for (const a of alerts) for (const ip of a.ips || []) m.set(ip, (m.get(ip) || 0) + 1);
  return [...m.entries()].sort((x, y) => y[1] - x[1]).slice(0, n).map(([ip, alerts]) => ({ ip, alerts }));
}

module.exports = { shapeAlert, shapeAlerts, tally, topIps, scrub, isIp };
