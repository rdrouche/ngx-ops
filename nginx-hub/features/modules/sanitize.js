'use strict';
/**
 * Assainissement des modules du contrat 12.78.0. Le Hub NE FAIT JAMAIS CONFIANCE au contenu distant, même si le dashboard
 * promet d'avoir déjà retiré secrets et IP : défense en profondeur.
 *  - profondeur ≤ 9, 500 éléments par tableau, 200 clés par objet, chaînes ≤ 600 ;
 *  - toute clé évoquant secret/token/mot de passe/clé/cookie/licence/empreinte/hash est retirée ;
 *  - sans expose_ips : clés `ip`/`ips`… retirées et adresses masquées dans les textes (`[ip]`) ;
 *  - on ne s'appuie que sur les noms de PARTIES et l'enveloppe ; le reste est traité comme extensible.
 */
const net = require('node:net');

const SECRET_KEY = /token|passw|passphrase|secret|private|api[_-]?key|cookie|licen[cs]e|credential|fingerprint|hash/i;
const IP_KEYS = new Set(['ip', 'ips', 'client_ip', 'remote_addr', 'remote_ip', 'src_ip', 'source_ip', 'addr', 'address']);
const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX = { depth: 9, array: 500, keys: 200, str: 600 };
const IP_CANDIDATE = /[0-9A-Fa-f:.]{3,45}/g;

function maskIps(s) {
  return s.replace(IP_CANDIDATE, (m) => (net.isIP(m) ? '[ip]' : m));
}

// eslint-disable-next-line no-control-regex
const CTRL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

function clean(v, exposeIps, depth = 0) {
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string') { const t = v.replace(CTRL, ' ').slice(0, MAX.str); return exposeIps ? t : maskIps(t); }
  if (depth >= MAX.depth) return undefined;
  if (Array.isArray(v)) return v.slice(0, MAX.array).map((x) => clean(x, exposeIps, depth + 1)).filter((x) => x !== undefined);
  if (typeof v === 'object') {
    const out = {};
    for (const [k, x] of Object.entries(v).slice(0, MAX.keys)) {
      if (BAD_KEYS.has(k) || k.length > 80 || SECRET_KEY.test(k)) continue;
      if (!exposeIps && IP_KEYS.has(k.toLowerCase())) continue;
      const c = clean(x, exposeIps, depth + 1);
      if (c !== undefined) out[k] = c;
    }
    return out;
  }
  return undefined;
}

function str(v, max) { return typeof v === 'string' ? v.replace(CTRL, ' ').trim().slice(0, max) || null : null; }
function int(v) { return Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), Number.MAX_SAFE_INTEGER) : 0; }

/** Une alerte détaillée (§2.2). @returns {object|null} null si inutilisable */
function normAlert(a, exposeIps) {
  if (!a || typeof a !== 'object' || !Number.isInteger(a.id) || a.id <= 0) return null;
  const mask = (s) => (s && !exposeIps ? maskIps(s) : s);
  let evidence = null;
  if (a.evidence && typeof a.evidence === 'object') {
    const e = clean(a.evidence, exposeIps);
    const j = JSON.stringify(e);
    evidence = j.length > 4000 ? JSON.stringify({ truncated: true }) : j;
  }
  const ips = exposeIps && Array.isArray(a.ips) ? a.ips.filter((x) => typeof x === 'string' && net.isIP(x)).slice(0, 50) : [];
  return {
    remote_id: a.id, ts: int(a.ts), type: str(a.type, 40), severity: str(a.severity, 16),
    summary: mask(str(a.summary, 300)), vhost: str(a.vhost, 120), country: str(a.country, 8),
    acked: a.acked ? 1 : 0, ip_count: Math.max(int(a.ip_count), ips.length), evidence, ips: ips.length ? JSON.stringify(ips) : null,
  };
}

/** Enveloppe d'un module (§2.1) → { data, errors, expose_ips } ou null. */
function normEnvelope(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const expose = raw.expose_ips === true;
  const errors = {};
  for (const [k, v] of Object.entries(raw.errors && typeof raw.errors === 'object' ? raw.errors : {}).slice(0, 40)) {
    if (/^[a-z][a-z0-9_]{0,40}$/.test(k) && typeof v === 'string') errors[k] = v.slice(0, 40);
  }
  return { expose_ips: expose, errors, data: clean(raw.data && typeof raw.data === 'object' ? raw.data : {}, expose) };
}

module.exports = { clean, maskIps, normAlert, normEnvelope };
