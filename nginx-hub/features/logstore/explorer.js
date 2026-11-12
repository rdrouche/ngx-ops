'use strict';
/**
 * Explorateur du log store (#107) : validation des filtres et assainissement des réponses. Fonctions pures.
 * DONNÉES PERSONNELLES (IP, chemins, user-agents) : réservé à indicators:view, activé par logstore.explorer.enabled
 * (opt-in), jamais stocké ni journalisé par le Hub (l'audit ne reçoit que des noms de filtres et des compteurs).
 * Le Hub relaie en lecture seule : aucune valeur de filtre n'est interprétée au-delà d'une liste blanche de formes.
 */
const net = require('node:net');
const { INSTANCE_RE } = require('./model');

const SOURCES = ['access', 'waf', 'challenge', 'blocklist', 'crowdsec', 'analysis'];
const ACTIONS = ['allowed', 'logged', 'challenged', 'blocked'];
const SITE_RE = /^[A-Za-z0-9*_.-]{1,253}$/;
const STATUS_RE = /^[1-5](xx|\d\d)$/;
const PSEUDO_RE = /^[0-9a-f]{32}$/;
const CIDR24_RE = /^((?:\d{1,3}\.){3}0)\/24$/;
const CURSOR_RE = /^[A-Za-z0-9_=-]{1,512}$/;
const TOP_DIMS = ['rule', 'path', 'ua', 'country', 'site', 'ip', 'bot_class'];
const CTRL_RE = /[\u0000-\u001f\u007f]/;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const bad = (field) => Object.assign(new Error(`filtre invalide : ${field}`), { code: 'bad_filter', field });
const one = (v) => (Array.isArray(v) ? v[0] : v);
const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : null);
const int = (v) => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : null);

/** IP en clair, /24 ou clé de pseudonyme (selon le mode IP du log store). */
function validIpKey(v) {
  return net.isIP(v) !== 0 || PSEUDO_RE.test(v) || (CIDR24_RE.test(v) && net.isIPv4(v.replace(/\/24$/, '')));
}

/**
 * Filtres de l'URL du Hub → paramètres de GET /v1/events. Lève une erreur `bad_filter` (400) sur toute valeur hors liste blanche.
 * @returns {{query:object, used:string[]}} `used` : noms des filtres renseignés (pour l'audit, jamais les valeurs)
 */
function buildEventsQuery(q = {}, { maxLimit = 500, defaultLimit = 100 } = {}) {
  const query = {}; const used = [];
  const hours = q.hours === undefined || q.hours === '' ? 24 : Number.parseInt(one(q.hours), 10);
  if (!Number.isInteger(hours) || hours < 1 || hours > 744) throw bad('hours');
  query.since = `${hours}h`; // durée Go : jamais « 7d »
  const lim = q.limit === undefined || q.limit === '' ? defaultLimit : Number.parseInt(one(q.limit), 10);
  if (!Number.isInteger(lim) || lim < 1) throw bad('limit');
  query.limit = Math.min(lim, maxLimit);

  const set = (name, ok, as = name) => {
    const v = one(q[name]);
    if (v === undefined || v === '') return;
    if (typeof v !== 'string' || !ok(v)) throw bad(name);
    query[as] = v; used.push(name);
  };
  set('instance', (v) => INSTANCE_RE.test(v));
  set('site', (v) => SITE_RE.test(v));
  set('source', (v) => SOURCES.includes(v));
  set('action', (v) => ACTIONS.includes(v));
  set('status', (v) => STATUS_RE.test(v.toLowerCase()));
  set('ip', validIpKey);
  set('path', (v) => v.length <= 200 && !CTRL_RE.test(v));
  set('ua', (v) => v.length <= 200 && !CTRL_RE.test(v));
  set('rule', (v) => v.length <= 120 && !CTRL_RE.test(v)); // noms de liste de blocage / règles : texte libre, sans contrôle
  set('cursor', (v) => CURSOR_RE.test(v));
  return { query, used };
}

/**
 * Filtres → paramètres de GET /v1/stats/top (#107 lot C). Dimension en liste blanche ; filtres : période, instance, site, source, action, règle.
 * @returns {{query:object, used:string[], dimension:string}}
 */
function buildTopQuery(q = {}) {
  const dim = one(q.dimension);
  if (typeof dim !== 'string' || !TOP_DIMS.includes(dim)) throw bad('dimension');
  const { query, used } = buildEventsQuery({ hours: q.hours, instance: q.instance, site: q.site, source: q.source, action: q.action, rule: q.rule, status: q.status }, { maxLimit: 100, defaultLimit: 20 });
  const lim = q.limit === undefined || q.limit === '' ? 20 : Number.parseInt(one(q.limit), 10);
  if (!Number.isInteger(lim) || lim < 1) throw bad('limit');
  query.limit = Math.min(lim, 50); query.dimension = dim;
  return { query, used: used.concat('dimension'), dimension: dim };
}

/** Filtres → GET /v1/stats/campaigns (fenêtre ≤ 7 j côté log store). */
function buildCampaignsQuery(q = {}) {
  const { query, used } = buildEventsQuery({ hours: q.hours, instance: q.instance, site: q.site, source: q.source, action: q.action }, { maxLimit: 1, defaultLimit: 1 });
  const hrs = Number.parseInt(query.since, 10);
  if (hrs > 168) throw bad('hours');
  delete query.limit;
  const mi = q.min_ips === undefined || q.min_ips === '' ? 3 : Number.parseInt(one(q.min_ips), 10);
  if (!Number.isInteger(mi) || mi < 2 || mi > 1000) throw bad('min_ips');
  query.min_ips = mi; query.limit = 30;
  return { query, used: used.concat('min_ips') };
}

/** Réponse de /v1/stats/campaigns : signatures (règle, chemin) sans IP, types contrôlés. */
function shapeCampaigns(raw) {
  const items = isObj(raw) && Array.isArray(raw.items) ? raw.items : [];
  const n = (v) => Math.max(0, int(v) || 0);
  return { items: items.filter(isObj).slice(0, 50).map((c) => ({
    rule: str(c.rule, 120), path: str(c.path, 512), events: n(c.events), blocked: n(c.blocked), ips: n(c.ip_count), sites: n(c.site_count), instances: n(c.instance_count),
    sources: (Array.isArray(c.sources) ? c.sources : []).filter((s) => SOURCES.includes(s)).slice(0, 5),
    first_seen: Date.parse(c.first_seen) || null, last_seen: Date.parse(c.last_seen) || null,
  })).filter((c) => c.rule) };
}

/** Réponse de /v1/stats/top : { dimension, items:[{key,count}] } → liste bornée, types contrôlés. */
function shapeTop(raw, dimension) {
  const items = isObj(raw) && Array.isArray(raw.items) ? raw.items : [];
  return { dimension, items: items.filter(isObj).slice(0, 50).map((x) => ({ key: str(x.key, 300), count: Math.max(0, int(x.count) || 0) })).filter((x) => x.key !== null) };
}

/** Données libres de la colonne `extra` : valeurs scalaires seulement, bornées (clé ≤ 40, texte ≤ 200, ≤ 30 clés, listes ≤ 20). */
function shapeExtra(raw) {
  if (!isObj(raw)) return null;
  const out = {};
  for (const [k, v] of Object.entries(raw).slice(0, 30)) {
    if (!/^[A-Za-z0-9_.-]{1,40}$/.test(k)) continue;
    if (typeof v === 'string') out[k] = v.slice(0, 200);
    else if (typeof v === 'number' && Number.isFinite(v)) out[k] = v;
    else if (typeof v === 'boolean') out[k] = v;
    else if (Array.isArray(v)) out[k] = v.filter((x) => typeof x === 'string' || typeof x === 'number').slice(0, 20).map((x) => (typeof x === 'string' ? x.slice(0, 120) : x));
  }
  return Object.keys(out).length ? out : null;
}

/** Un événement : liste blanche de champs, types contrôlés. */
function shapeEvent(e) {
  if (!isObj(e)) return null;
  const ts = Date.parse(e.ts);
  if (!Number.isFinite(ts)) return null;
  const instance = String(e.instance_id || '');
  return {
    id: int(e.id), ts, instance: INSTANCE_RE.test(instance) ? instance : null,
    source: SOURCES.includes(e.source) ? e.source : null, action: ACTIONS.includes(e.action) ? e.action : null,
    site: str(e.site, 253), ip: str(e.ip, 64), ip_key: str(e.ip_key, 64),
    method: str(e.method, 16), path: str(e.path, 512), status: int(e.status), bytes: int(e.bytes), rt_ms: int(e.rt_ms),
    ua: str(e.ua, 300), referer_host: str(e.referer_host, 253), country: str(e.country, 8), bot_class: str(e.bot_class, 40),
    rule: str(e.rule, 120), extra: shapeExtra(e.extra),
  };
}

function shapeEvents(raw, max = 500) {
  const r = isObj(raw) ? raw : {};
  const events = (Array.isArray(r.events) ? r.events : []).slice(0, max).map(shapeEvent).filter(Boolean);
  const next = typeof r.next_cursor === 'string' && CURSOR_RE.test(r.next_cursor) ? r.next_cursor : null;
  return { events, next_cursor: next };
}

/** GET /v1/ips/{ip} : résumé (1er/dernier passage, total, répartition source/action) + chronologie, répartitions calculées ici. */
function shapeIpHistory(raw, max = 500) {
  const r = isObj(raw) ? raw : {};
  const s = isObj(r.summary) ? r.summary : {};
  const { events, next_cursor: next } = shapeEvents(r, max);
  const tally = (key) => { const m = new Map(); for (const e of events) if (e[key]) m.set(e[key], (m.get(e[key]) || 0) + 1); return [...m].map(([k, count]) => ({ key: k, count })).sort((a, b) => b.count - a.count).slice(0, 50); };
  return {
    ip_mode: ['clear', 'pseudonymized', 'truncated'].includes(r.ip_mode) ? r.ip_mode : null,
    summary: {
      first_seen: Date.parse(s.first_seen) || null, last_seen: Date.parse(s.last_seen) || null, total: Math.max(0, int(s.total) || 0),
      by_source_action: (Array.isArray(s.by_source_action) ? s.by_source_action : []).filter(isObj).slice(0, 50)
        .map((x) => ({ source: SOURCES.includes(x.source) ? x.source : null, action: ACTIONS.includes(x.action) ? x.action : null, count: Math.max(0, int(x.count) || 0) })),
    },
    events, next_cursor: next,
    by_site: tally('site'), by_instance: tally('instance'), by_rule: tally('rule'),
  };
}

module.exports = { SOURCES, ACTIONS, TOP_DIMS, validIpKey, buildEventsQuery, buildTopQuery, shapeTop, buildCampaignsQuery, shapeCampaigns, shapeEvent, shapeEvents, shapeIpHistory, shapeExtra };
