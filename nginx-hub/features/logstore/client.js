'use strict';
/**
 * Client du log store (#62) : GET /v1/stats/* et /v1/instances avec le jeton `read` (Authorization: Bearer).
 * Réutilise le client sortant du Hub (HTTPS, DNS validé, aucune redirection, tailles et délais bornés).
 */
const fs = require('node:fs');
const { fetchJson } = require('../collector/fetcher');
const { DIMENSIONS, INSTANCE_RE } = require('./model');

const TOKEN_RE = /^[A-Za-z0-9_.~+/=-]{16,300}$/;

/** Jeton `read` : environnement uniquement (HUB_LOGSTORE_TOKEN ou _FILE), jamais le fichier de configuration. */
function readToken(env = process.env) {
  let raw = env.HUB_LOGSTORE_TOKEN || '';
  if (!raw && env.HUB_LOGSTORE_TOKEN_FILE) { try { raw = fs.readFileSync(env.HUB_LOGSTORE_TOKEN_FILE, 'utf8'); } catch { raw = ''; } }
  raw = String(raw).trim();
  return TOKEN_RE.test(raw) ? raw : '';
}

/** Requêtes de l'aperçu pour une fenêtre `hours` (1..744) et une instance facultative. */
function buildRequests({ hours, instance }) {
  const base = { since: `${hours}h` }; // durée Go : jamais « 7d »
  if (instance) {
    if (!INSTANCE_RE.test(instance)) throw new Error('bad_instance');
    base.instance = instance;
  }
  const reqs = [
    { name: 'visits', path: '/v1/stats/visits', query: { ...base, bucket: hours > 72 ? 'day' : 'hour' } },
    { name: 'security', path: '/v1/stats/security', query: base },
    { name: 'instances', path: '/v1/instances', query: {} },
    { name: 'health', path: '/v1/health', query: {} }, // #127 : informations de la base (version, taille, rétention…), jeton read global
  ];
  for (const d of DIMENSIONS) reqs.push({ name: 'top:' + d, path: '/v1/stats/top', query: { ...base, dimension: d, limit: 10 } });
  return reqs;
}

/** @returns {Promise<{parts:object, errors:object}>} parts brutes + code d'erreur par requête (jamais de message brut) */
async function fetchParts({ config, token, hours, instance, fetch = fetchJson }) {
  const ls = config.logstore;
  const target = { baseUrl: ls.url, token, bearer: true };
  const reqs = buildRequests({ hours, instance });
  const settled = await Promise.allSettled(reqs.map((r) => fetch(target, config, { path: r.path, query: r.query, maxBytes: ls.max_response_bytes, timeoutMs: ls.timeout_ms })));
  const parts = { tops: {} }; const errors = {};
  settled.forEach((s, i) => {
    const name = reqs[i].name;
    if (s.status === 'rejected') { errors[name] = (s.reason && s.reason.code) || 'connection'; return; }
    if (name.startsWith('top:')) parts.tops[name.slice(4)] = s.value.data; else parts[name] = s.value.data;
  });
  return { parts, errors };
}

/** Corrélation par IP : une requête « vue par ≥ N instances » et une « ≥ 3 sources » (même instance). Jamais de filtre d'IP en entrée. */
async function fetchCorrelation({ config, token, fetch = fetchJson }) {
  const ls = config.logstore; const ind = ls.indicators;
  const target = { baseUrl: ls.url, token, bearer: true };
  const base = { since: `${ind.hours}h`, limit: ind.limit };
  const reqs = [{ ...base, min_instances: ind.min_instances }, { ...base, min_instances: 1, min_sources: 3 }];
  const settled = await Promise.allSettled(reqs.map((q) => fetch(target, config, { path: '/v1/stats/ips', query: q, maxBytes: ls.max_response_bytes, timeoutMs: ls.timeout_ms })));
  const raws = []; const errors = [];
  for (const s of settled) { if (s.status === 'fulfilled') raws.push(s.value.data); else errors.push((s.reason && s.reason.code) || 'connection'); }
  return { raws, errors };
}

/** Explorateur (#107) : GET /v1/events et GET /v1/ips/{ip} avec le jeton `read`. Paramètres déjà validés (explorer.js). */
async function fetchEvents({ config, token, query, fetch = fetchJson }) {
  const ls = config.logstore;
  const { data } = await fetch({ baseUrl: ls.url, token, bearer: true }, config, { path: '/v1/events', query, maxBytes: ls.max_response_bytes, timeoutMs: ls.timeout_ms });
  return data;
}
async function fetchIpHistory({ config, token, ip, query, fetch = fetchJson }) {
  const ls = config.logstore;
  const { data } = await fetch({ baseUrl: ls.url, token, bearer: true }, config, { path: '/v1/ips/' + encodeURIComponent(ip), query, maxBytes: ls.max_response_bytes, timeoutMs: ls.timeout_ms });
  return data;
}

async function fetchTop({ config, token, query, fetch = fetchJson }) {
  const ls = config.logstore;
  const { data } = await fetch({ baseUrl: ls.url, token, bearer: true }, config, { path: '/v1/stats/top', query, maxBytes: ls.max_response_bytes, timeoutMs: ls.timeout_ms });
  return data;
}

async function fetchCampaigns({ config, token, query, fetch = fetchJson }) {
  const ls = config.logstore;
  const { data } = await fetch({ baseUrl: ls.url, token, bearer: true }, config, { path: '/v1/stats/campaigns', query, maxBytes: ls.max_response_bytes, timeoutMs: ls.timeout_ms });
  return data;
}

module.exports = { readToken, buildRequests, fetchParts, fetchCorrelation, fetchEvents, fetchIpHistory, fetchTop, fetchCampaigns, TOKEN_RE };
