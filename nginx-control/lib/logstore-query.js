'use strict';
/**
 * Journal centralise — construction des requetes vers l'API de lecture du log store (v12.80.0).
 * Pur. Le navigateur ne choisit JAMAIS l'hote ni le chemin : seuls des parametres a liste blanche,
 * valides et bornes, sont recopies dans une requete a chemin fixe (pas de SSRF, pas d'injection de
 * parametre : chaque valeur est reencodee, aucune cle inconnue ne passe).
 */

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/;
// Le log store lit une duree Go (time.ParseDuration) : minutes ou heures, pas de jours (7 j = 168h).
const SINCE_RE = /^\d{1,4}(m|h)$/;
const SOURCES = ['access', 'waf', 'challenge', 'blocklist', 'crowdsec', 'analysis'];
const ACTIONS = ['allowed', 'blocked', 'challenged', 'logged'];
const DIMENSIONS = ['path', 'ua', 'country', 'site', 'rule', 'referer_host', 'bot_class', 'source', 'action', 'status', 'ip'];
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const SITE_RE = /^[A-Za-z0-9._*-]{1,253}$/;
const STATUS_RE = /^([1-5]\d\d|[1-5]xx)$/i;
const net = require('net');
/** IP litterale valide (v4/v6) ou cle de pseudonyme (32 hex) : rien d'autre ne forme un segment de chemin. */
const IP_RE = { test: (v) => typeof v === 'string' && v.length <= 45 && (net.isIP(v) !== 0 || /^[0-9a-f]{32}$/.test(v)) };
const CURSOR_RE = /^[A-Za-z0-9_.~=-]{1,300}$/;
const TEXT_RE = /^[^\u0000-\u001f\u007f]{1,200}$/; // ua / path : texte libre court, sans controle

const WINDOW = { from: 'iso', to: 'iso', since: 'since' };
const FILTERS = {
  instance: 'name', site: 'site', source: SOURCES, action: ACTIONS, status: 'status', ua: 'text', path: 'text', ip: 'ip',
};

function intIn(v, lo, hi) {
  if (!/^\d{1,6}$/.test(v)) return null;
  const n = Number(v);
  return n >= lo && n <= hi ? n : null;
}

function check(kind, v) {
  if (Array.isArray(kind)) return kind.includes(v);
  switch (kind) {
    case 'iso': return ISO_RE.test(v) && !Number.isNaN(Date.parse(v));
    case 'since': return SINCE_RE.test(v);
    case 'name': return NAME_RE.test(v);
    case 'site': return SITE_RE.test(v);
    case 'status': return STATUS_RE.test(v);
    case 'text': return TEXT_RE.test(v);
    case 'ip': return IP_RE.test(v);
    default: return false;
  }
}

/** Copie les parametres de `names` presents dans `src` ; renvoie { qs } ou { error }. */
function pick(src, spec, qs) {
  for (const [name, kind] of Object.entries(spec)) {
    const v = src.get(name);
    if (v === null || v === '') continue;
    if (!check(kind, v)) return { error: `parametre invalide : ${name}` };
    qs.set(name, v);
  }
  return null;
}

/**
 * @param {'events'|'ip'|'visits'|'top'|'security'|'instances'|'health'} kind
 * @param {URLSearchParams} src  parametres recus du navigateur
 * @param {string} [ip]          pour kind === 'ip'
 * @param {{instance?:string}} [opts]  instance : limite TOUTES les lectures a cette instance (#89) ; le parametre
 *                               `instance` du navigateur est alors ignore (jamais une vue d'une autre instance)
 * @returns {{path:string}|{error:string}}  `path` inclut la query string deja encodee
 */
function buildRequest(kind, src, ip, opts = {}) {
  const qs = new URLSearchParams();
  const win = { ...WINDOW };
  let base;
  switch (kind) {
    case 'health': return { path: '/v1/health' };
    case 'instances': return { path: '/v1/instances' };
    case 'events': base = '/v1/events'; break;
    case 'ip':
      if (!IP_RE.test(String(ip || ''))) return { error: 'adresse IP invalide' };
      base = `/v1/ips/${encodeURIComponent(ip)}`; break;
    case 'visits': base = '/v1/stats/visits'; break;
    case 'top': base = '/v1/stats/top'; break;
    case 'security': base = '/v1/stats/security'; break;
    default: return { error: 'requete inconnue' };
  }
  let r = pick(src, win, qs);
  if (r) return r;
  if (qs.has('since') && (qs.has('from') || qs.has('to'))) return { error: 'since est incompatible avec from/to' };
  if (kind !== 'ip') { r = pick(src, FILTERS, qs); if (r) return r; }
  else { r = pick(src, { site: 'site', source: SOURCES, action: ACTIONS }, qs); if (r) return r; }

  if (kind === 'events' || kind === 'ip' || kind === 'top') {
    const lim = src.get('limit');
    if (lim !== null && lim !== '') {
      const n = intIn(lim, 1, kind === 'top' ? 100 : 500);
      if (n === null) return { error: 'parametre invalide : limit' };
      qs.set('limit', String(n));
    }
  }
  if (kind === 'events' || kind === 'ip') {
    const cur = src.get('cursor');
    if (cur) {
      if (!CURSOR_RE.test(cur)) return { error: 'parametre invalide : cursor' };
      qs.set('cursor', cur);
    }
  }
  if (kind === 'visits') {
    const b = src.get('bucket');
    if (b) { if (!['hour', 'day', 'auto'].includes(b)) return { error: 'parametre invalide : bucket' }; qs.set('bucket', b); }
  }
  if (kind === 'top') {
    const d = src.get('dimension');
    if (!DIMENSIONS.includes(d)) return { error: 'parametre invalide : dimension' };
    qs.set('dimension', d);
  }
  if (kind === 'security') {
    const m = src.get('min_paths');
    if (m) { const n = intIn(m, 1, 1000); if (n === null) return { error: 'parametre invalide : min_paths' }; qs.set('min_paths', String(n)); }
  }
  if (opts.instance && NAME_RE.test(opts.instance)) qs.set('instance', opts.instance);
  const s = qs.toString();
  return { path: s ? `${base}?${s}` : base };
}

// ── Fenetres de plus de 31 jours (#65) ───────────────────────────────────────────────────────────────────────
// Le log store refuse une fenetre > 31 j. Pour les series (visits) et les classements (top), le dashboard decoupe
// en tranches de <= 30 j dont les coupures tombent a minuit UTC (un cumul journalier appartient a une seule
// tranche), les interroge puis fusionne. `security` n'est pas additif (scanners = chemins distincts par IP) : non decoupe.
const DAY = 86_400_000;
const MAX_SPAN_DAYS = 366;

/**
 * @param {URLSearchParams} src
 * @param {number} [now]
 * @returns {null | {error:string} | {chunks:{from:string,to:string}[]}}  null : fenetre normale (<= 31 j), aucune action
 */
function planWindows(src, now = Date.now()) {
  let to = now;
  if (src.get('to')) { to = Date.parse(src.get('to')); if (!Number.isFinite(to)) return null; }
  let from;
  if (src.get('from')) { from = Date.parse(src.get('from')); if (!Number.isFinite(from)) return null; }
  else if (src.get('since')) {
    const m = /^(\d{1,4})(m|h)$/.exec(src.get('since'));
    if (!m) return null;
    from = to - Number(m[1]) * (m[2] === 'h' ? 3_600_000 : 60_000);
  } else return null;
  if (!(from < to) || to - from <= 31 * DAY) return null;
  if (to - from > MAX_SPAN_DAYS * DAY) return { error: `fenetre limitee a ${MAX_SPAN_DAYS} jours` };
  const chunks = []; let cur = from;
  while (to - cur > 30 * DAY) {
    const cut = Math.floor((cur + 30 * DAY) / DAY) * DAY; // minuit UTC
    chunks.push({ from: new Date(cur).toISOString(), to: new Date(cut - 1).toISOString() }); // fin exclusive : les bornes du log store sont inclusives
    cur = cut;
  }
  chunks.push({ from: new Date(cur).toISOString(), to: new Date(to).toISOString() });
  return { chunks };
}

/** Parametres d'une tranche : from/to remplacent since/to, bucket force a `day`. */
function chunkParams(src, chunk) {
  const p = new URLSearchParams(src);
  p.delete('since'); p.set('from', chunk.from); p.set('to', chunk.to); p.set('bucket', 'day');
  return p;
}

/** Fusion de reponses `visits` : un cumul journalier par tranche ; un doublon eventuel est somme (visiteurs distincts : inconnus). */
function mergeVisits(bodies) {
  const by = new Map();
  for (const b of bodies) for (const pt of (b && Array.isArray(b.points) ? b.points : [])) {
    const cur = by.get(pt.bucket);
    if (!cur) { by.set(pt.bucket, { ...pt }); continue; }
    for (const k of ['requests', 's2xx', 's3xx', 's4xx', 's5xx', 'bytes']) cur[k] = (cur[k] || 0) + (pt[k] || 0);
    cur.visitors = null;
  }
  return { bucket: 'day', points: [...by.values()].sort((a, b) => (a.bucket < b.bucket ? -1 : a.bucket > b.bucket ? 1 : 0)), chunks: bodies.length };
}

/** Fusion de classements `top` : somme par cle. APPROXIMATIF (une cle hors du top d'une tranche n'y est pas comptee). */
function mergeTop(bodies, dimension, limit = 20) {
  const by = new Map();
  for (const b of bodies) for (const it of (b && Array.isArray(b.items) ? b.items : [])) by.set(it.key, (by.get(it.key) || 0) + (it.count || 0));
  const items = [...by].map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count || (a.key < b.key ? -1 : 1)).slice(0, limit);
  return { dimension, items, approximate: true, chunks: bodies.length };
}

module.exports = { buildRequest, planWindows, chunkParams, mergeVisits, mergeTop, SOURCES, ACTIONS, DIMENSIONS, IP_RE };
