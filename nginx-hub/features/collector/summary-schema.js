'use strict';
/**
 * Contrat « summary » (schéma 1, API v1) renvoyé par GET /api/hub/v1/summary d'un dashboard NGX Ops (≥ 12.76.0).
 * Le Hub NE FAIT JAMAIS CONFIANCE au contenu distant : tout est re-typé, borné et tronqué ici.
 * Évolution : champs additifs uniquement — un champ inconnu est ignoré, un champ absent reçoit une valeur neutre.
 * Le contrat ne contient jamais d'IP de visiteur, de secret ni de chemin disque : si un tel champ arrivait quand même,
 * il serait ignoré (liste blanche stricte ci-dessous).
 */
const { SUMMARY_SCHEMA_MAX } = require('../../lib/config');

const NGINX_STATES = ['running', 'stopped', 'unknown'];
const COMPONENT_STATES = ['ok', 'degraded', 'down', 'disabled', 'unknown'];
const SEVERITIES = ['info', 'warning', 'critical'];
/** Synonymes tolérés pour l'état d'un composant (le contrat ne fige pas le vocabulaire). */
const STATE_ALIASES = {
  running: 'ok', active: 'ok', up: 'ok', healthy: 'ok', enabled: 'ok', on: 'ok',
  warn: 'degraded', warning: 'degraded', partial: 'degraded',
  error: 'down', failed: 'down', stopped: 'down', inactive: 'down', dead: 'down',
  off: 'disabled', none: 'disabled', not_configured: 'disabled', unconfigured: 'disabled',
  // #126 : vocabulaire émis par les dashboards 12.78 à 12.8x (« configured » = composant configuré et joignable).
  configured: 'ok', unreachable: 'down', unavailable: 'down',
};

function str(v, max = 200) {
  if (typeof v !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  return v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max) || null;
}
function num(v) {
  const n = typeof v === 'number' ? v : Number.NaN;
  return Number.isFinite(n) && n >= 0 ? Math.min(Math.floor(n), 1e15) : 0;
}
/** Entier signé borné (jours restants d'un certificat : négatif = expiré). */
function int(v, lim = 36500) {
  const n = typeof v === 'number' ? v : Number.NaN;
  return Number.isFinite(n) ? Math.max(-lim, Math.min(lim, Math.trunc(n))) : null;
}
function oneOf(v, list, d) { return list.includes(v) ? v : d; }
function iso(v) { const t = typeof v === 'string' ? Date.parse(v) : Number.NaN; return Number.isFinite(t) ? new Date(t).toISOString() : null; }
function obj(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }
function arr(v, max) { return (Array.isArray(v) ? v : []).slice(0, max); }
function present(v) { return v && typeof v === 'object' && !Array.isArray(v); }
function componentState(v) {
  const s = typeof v === 'string' ? v.toLowerCase() : '';
  return COMPONENT_STATES.includes(s) ? s : (STATE_ALIASES[s] || 'unknown');
}

function sanitizeSummary(raw) {
  const r = obj(raw);
  if (!Number.isInteger(r.schema) || r.schema < 1) {
    const e = new Error('schéma de résumé absent ou invalide'); e.code = 'bad_schema'; throw e;
  }
  const inst = obj(r.instance); const nginx = obj(r.nginx); const alerts = obj(r.alerts); const sec = obj(r.security);
  const hasTraffic = present(r.traffic_24h); const traffic = obj(r.traffic_24h);

  const components = {};
  for (const [k, v] of Object.entries(obj(r.components)).slice(0, 12)) {
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(k)) continue;
    components[k] = { state: componentState(obj(v).state), detail: str(obj(v).detail, 160) };
  }
  const items = arr(alerts.items, 10).map((a) => ({
    id: str(obj(a).id, 64), severity: oneOf(obj(a).severity, SEVERITIES, 'warning'), title: str(obj(a).title, 160) || '(sans titre)', since: iso(obj(a).since),
  }));
  const top = arr(r.top_vhosts, 10).map((v) => ({
    name: str(obj(v).name, 120) || '?', requests: num(obj(v).requests), bytes: num(obj(v).bytes), errors: num(obj(v).errors),
    humans: num(obj(v).humans), robots: num(obj(v).robots),
  }));
  const countries = arr(r.top_countries, 10).map((c) => {
    const code = str(obj(c).country, 8);
    return { country: code && /^[A-Za-z]{2}$/.test(code) ? code.toUpperCase() : (code || '??').slice(0, 8), requests: num(obj(c).requests) };
  });
  const certs = arr(r.certs_expiring, 20).map((c) => ({
    name: str(obj(c).name, 120) || '?', days_left: int(obj(c).daysLeft ?? obj(c).days_left), not_after: iso(obj(c).notAfter ?? obj(c).not_after),
  }));
  const active = num(alerts.active);

  return {
    schema: r.schema,
    schema_newer: r.schema > SUMMARY_SCHEMA_MAX,
    generated_at: iso(r.generated_at),
    instance: { id: str(inst.id, 64), name: str(inst.name, 80), version: str(inst.version, 32), hostname: str(inst.hostname, 120) },
    nginx: {
      status: oneOf(nginx.status, NGINX_STATES, 'unknown'), version: str(nginx.version, 32), uptime_s: num(nginx.uptime_s),
      config_ok: typeof nginx.config_ok === 'boolean' ? nginx.config_ok : null, connections: num(nginx.connections),
    },
    vhosts: { count: num(obj(r.vhosts).count) },
    // traffic_24h peut valoir null côté dashboard (analyse indisponible) : `available` le distingue d'un vrai zéro.
    traffic_24h: {
      available: hasTraffic,
      requests: num(traffic.requests), errors: num(traffic.errors), bytes: num(traffic.bytes),
      humans: num(traffic.humans), robots: num(traffic.robots), blocked: num(traffic.blocked),
    },
    alerts: { active, critical: Math.min(num(alerts.critical), active || num(alerts.critical)), items },
    top_vhosts: top,
    top_countries: countries,
    security: {
      crowdsec: present(sec.crowdsec) ? { active: typeof sec.crowdsec.active === 'boolean' ? sec.crowdsec.active : num(sec.crowdsec.active) } : null,
      waf: present(sec.waf) ? { blocked_24h: num(sec.waf.blocked_24h) } : null,
      blocklists: present(sec.blocklists) ? { ips: num(sec.blocklists.ips), hits_24h: num(sec.blocklists.hits_24h) } : null,
    },
    certs_expiring: certs,
    components,
    mfa: { accounts: r.mfa === undefined ? null : num(obj(r.mfa).accounts) },
  };
}

/** Santé dérivée d'une réponse valide : online | degraded. */
function deriveHealth(s) {
  if (s.nginx.status === 'stopped' || s.nginx.config_ok === false) return 'degraded';
  if (Object.values(s.components).some((c) => c.state === 'down')) return 'degraded';
  return 'online';
}

module.exports = { sanitizeSummary, deriveHealth };
