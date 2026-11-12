'use strict';
/**
 * Modules de données exposés au Hub (v12.78.0), lecture seule :
 *   inventory · traffic · security · ops · monitoring · reports · indicators
 * Chaque module assemble des « parties » issues des routes internes existantes (liste blanche
 * ci-dessous) et passe le tout par `sanitize()` : clés secrètes retirées, IP retirées sauf
 * `expose_ips: true`, tableaux et profondeur bornés. `indicators` (corrélation) exige expose_ips.
 */
const { callInternal } = require('./hub-internal');
const detail = require('./hub-detail');

const MODULE_IDS = ['inventory', 'traffic', 'security', 'ops', 'monitoring', 'reports', 'indicators'];

const SECRET_KEY = /token|secret|passw|private|api[_-]?key|credential|authorization|cookie|licen[sc]e|fingerprint|hash$/i;
const IP_KEY = /^(ip|ips|clientip|client_ip|remoteaddr|remote_addr|sourceip|source_ip|topips|addresses|value|origin_ip)$/i;
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/g;
const IPV6_FULL = /^[0-9a-f:]*:[0-9a-f:]+(?:\/\d{1,3})?$/i;
const MAX_ARRAY = 500, MAX_DEPTH = 9, MAX_STR = 600;

function looksLikeIp(s) { return typeof s === 'string' && (/^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/.test(s) || (s.includes(':') && IPV6_FULL.test(s))); }

/** Copie assainie. `value` (CrowdSec) n'est retiré que s'il ressemble à une IP. */
function sanitize(v, exposeIps, depth = 0) {
  if (v == null || depth > MAX_DEPTH) return v == null ? v : undefined;
  if (typeof v === 'string') {
    const s = v.length > MAX_STR ? v.slice(0, MAX_STR) + '…' : v;
    return exposeIps ? s : s.replace(IPV4, '[ip]');
  }
  if (typeof v !== 'object') return v;
  if (Array.isArray(v)) {
    return v.slice(0, MAX_ARRAY).map(x => sanitize(x, exposeIps, depth + 1)).filter(x => x !== undefined);
  }
  const out = {};
  for (const [k, val] of Object.entries(v)) {
    if (SECRET_KEY.test(k)) continue;
    if (!exposeIps && IP_KEY.test(k)) {
      if (k.toLowerCase() !== 'value' || looksLikeIp(val) || (Array.isArray(val) && val.some(looksLikeIp))) continue;
    }
    const s = sanitize(val, exposeIps, depth + 1);
    if (s !== undefined) out[k] = s;
  }
  return out;
}

const hoursOf = (q, d = 24) => Math.min(720, Math.max(1, parseInt(q.get('hours'), 10) || d));
const limitOf = (q, d, max) => Math.min(max, Math.max(1, parseInt(q.get('limit'), 10) || d));

/** Définition des parties : [nom, (q)=>chemin interne]. */
const PARTS = {
  inventory: [
    ['vhosts', () => '/api/backends'],
    ['certificates', () => '/api/ssl'],
    ['agents', () => '/api/agents'],
    ['containers_managed', () => '/api/analyzer/status'],
  ],
  traffic: [
    ['series_hourly', q => `/api/analyzer/traffic/series?grain=hour&hours=${hoursOf(q)}`],
    ['countries', q => `/api/analyzer/traffic/countries?hours=${hoursOf(q)}`],
    ['vhosts', q => `/api/analyzer/traffic/vhosts?hours=${hoursOf(q)}`],
    ['clients', q => `/api/analyzer/traffic/bots?hours=${hoursOf(q)}`],
    ['clients_by_vhost', q => `/api/analyzer/traffic/bots/vhosts?hours=${hoursOf(q)}`],
    ['clients_by_country', q => `/api/analyzer/traffic/bots/countries?hours=${hoursOf(q)}`],
  ],
  security: [
    ['blocklists_status', () => '/api/blocklists/status'],
    ['blocklists_hits', q => `/api/blocklists/hit-stats?hours=${hoursOf(q)}`],
    ['challenge_status', () => '/api/challenge/status'],
    ['challenge_stats', q => `/api/challenge/stats?hours=${hoursOf(q)}`],
    ['challenge_blocks', q => `/api/challenge/offenders?hours=${Math.min(168, hoursOf(q))}&min=1&limit=200&neverSolved=1`],
    ['waf_status', () => '/api/waf/status'],
    ['waf_top_rules', q => `/api/analyzer/waf/top-rules?hours=${hoursOf(q)}`],
    ['waf_series', q => `/api/analyzer/waf/series?hours=${hoursOf(q)}`],
    ['crowdsec_status', () => '/api/crowdsec/status'],
    ['crowdsec_decisions', q => `/api/crowdsec/decisions?limit=${limitOf(q, 200, 500)}`],
  ],
  ops: [
    ['scheduler_tasks', () => '/api/scheduler/tasks'],
    ['scheduler_runs', () => '/api/scheduler/runs'],
    ['digests', () => '/api/digest/history'],
  ],
  reports: [
    ['rules', () => '/api/analyzer/rules'],
    ['exceptions', () => '/api/analyzer/exceptions'],
    ['baseline', () => '/api/analyzer/baseline'],
    ['baseline_country', () => '/api/analyzer/baseline/country'],
    ['baseline_data', () => '/api/analyzer/baseline/data'],
  ],
  monitoring: [['targets', () => '/api/monitor']],
};

/** Chemins autorisés (sans requête) pour callInternal. */
const ALLOWED = new Set();
for (const parts of Object.values(PARTS)) for (const [, f] of parts) ALLOWED.add(new URL(f(new URLSearchParams()), 'http://x').pathname);
ALLOWED.add('/api/monitor/history');
ALLOWED.add('/api/analyzer/waf/top-ips');
ALLOWED.add('/api/crowdsec/decisions');
ALLOWED.add('/api/challenge/offenders');

async function runParts(ctx, id, q) {
  const data = {}, errors = {};
  await Promise.all(PARTS[id].map(async ([name, path]) => {
    const r = await callInternal(ctx.router, path(q), { allow: ALLOWED });
    if (r.status === 200 && r.json !== null) data[name] = r.json; else errors[name] = r.status === 403 ? 'forbidden' : r.status === 404 ? 'unavailable' : 'error_' + r.status;
  }));
  return { data, errors };
}

// ── nginx -V (mis en cache 1 h) ─────────────────────────────────────────────
let buildCache = { at: 0, v: null };
function parseNginxV(text) {
  const t = String(text || '');
  const ver = (t.match(/nginx\/([\w.\-]+)/) || [])[1] || null;
  const args = (t.match(/configure arguments:\s*(.*)/) || [])[1] || '';
  const modules = [...args.matchAll(/--(with-[\w_\-]+|add-(?:dynamic-)?module=[^\s]+)/g)].map(m => m[1]);
  const tls = (t.match(/built with (OpenSSL [\w. ]+?)(?:\s*\(|\s*$)/m) || [])[1] || null;
  return { version: ver, tls, modules: [...new Set(modules)].slice(0, 200) };
}
async function nginxBuild(ctx) {
  if (buildCache.v && Date.now() - buildCache.at < 3_600_000) return buildCache.v;
  let v = null;
  try {
    const r = await ctx.execNginx('nginx -V');
    v = parseNginxV((r && (r.stderr || '')) + '\n' + (r && (r.stdout || '')));
  } catch { v = null; }
  buildCache = { at: Date.now(), v };
  return v;
}

// ── builders ────────────────────────────────────────────────────────────────
async function buildInventory(ctx, q) {
  const { data, errors } = await runParts(ctx, 'inventory', q);
  const vts = await ctx.fetchVTS().catch(() => null);
  const build = await nginxBuild(ctx);
  data.nginx = { running: !!vts, version: (build && build.version) || (vts && vts.nginxVersion) || null, tls: build && build.tls, modules: build ? build.modules : null,
    connections: vts ? vts.connections || null : null };
  if (Array.isArray(data.agents && data.agents.agents)) {
    data.agents = { agents: data.agents.agents.map(a => ({ id: a.id, hostname: a.hostnameProposed, status: a.status, online: a.online, tunnel_connected: a.tunnelConnected,
      last_seen: a.lastManifestAt, last_ok: a.lastManifestOk, vhost_count: a.vhostCount, protocol: a.protocolVersion, since: a.createdAt })) };
  }
  if (data.containers_managed) data.containers_managed = { reachable: !!data.containers_managed.reachable, container: data.containers_managed.container };
  return { data, errors };
}

async function buildTraffic(ctx, q) {
  const { data, errors } = await runParts(ctx, 'traffic', q);
  // Séries horaires par vhost : les N premiers vhosts par volume.
  const n = limitOf(q, 10, 25);
  const list = (data.vhosts && (data.vhosts.vhosts || data.vhosts.rows)) || [];
  const names = list.map(v => v.vhost || v.name).filter(Boolean).slice(0, n);
  const perVhost = {};
  await Promise.all(names.map(async name => {
    const r = await callInternal(ctx.router, `/api/analyzer/traffic/series?grain=hour&hours=${hoursOf(q)}&vhost=${encodeURIComponent(name)}`, { allow: ALLOWED });
    if (r.status === 200 && r.json) perVhost[name] = r.json.series || [];
  }));
  data.series_hourly_by_vhost = perVhost;
  return { data, errors };
}

async function buildSecurity(ctx, q) {
  const { data, errors } = await runParts(ctx, 'security', q);
  const topIps = await callInternal(ctx.router, `/api/analyzer/waf/top-ips?hours=${hoursOf(q)}`, { allow: ALLOWED });
  if (topIps.status === 200) data.waf_top_ips = topIps.json;
  // Alertes d'analyse sur la fenêtre : répartition par type / gravité (le détail est dans /alerts).
  const al = await ctx.analyzerApi(`/api/alerts?limit=500&since=${Date.now() - hoursOf(q) * 3_600_000}`).catch(() => null);
  if (al && al.data) {
    const shaped = detail.shapeAlerts(al.data.alerts, false);
    data.alerts = { total: al.data.total ?? shaped.length, unacked: shaped.filter(a => !a.acked).length, ...detail.tally(shaped) };
  }
  return { data, errors };
}

async function buildOps(ctx, q) {
  const { data, errors } = await runParts(ctx, 'ops', q);
  const since = Date.now() - hoursOf(q) * 3_600_000;
  const ev = ctx.queryEvents({ limit: limitOf(q, 200, 500), since });
  data.events = { total: ev.total, events: ev.events.map(e => ({ id: e.id, ts: e.ts, type: e.type, source: e.source, data: e.data })) };
  return { data, errors };
}

async function buildMonitoring(ctx, q) {
  const { data, errors } = await runParts(ctx, 'monitoring', q);
  const targets = (data.targets && data.targets.targets) || [];
  const history = {};
  await Promise.all(targets.slice(0, 40).map(async t => {
    if (!t.key) return;
    const r = await callInternal(ctx.router, `/api/monitor/history?key=${encodeURIComponent(t.key)}`, { allow: ALLOWED });
    if (r.status === 200 && r.json) history[t.key] = { incidents: (r.json.incidents || []).slice(0, 20) };
  }));
  return { data: { enabled: targets.length > 0, targets, incidents: history }, errors };
}

async function buildReports(ctx, q) { return runParts(ctx, 'reports', q); }

/** Corrélation : une ligne par IP avec TOUTES les sources qui la connaissent. Exige expose_ips. */
async function buildIndicators(ctx, q) {
  const h = hoursOf(q), since = Date.now() - h * 3_600_000;
  const map = new Map();
  const add = (ip, kind, detail = {}) => {
    ip = typeof ip === 'string' ? ip.trim() : '';
    if (!looksLikeIp(ip)) return;
    const e = map.get(ip) || { ip, kinds: new Set(), sources: [] };
    e.kinds.add(kind);
    if (e.sources.length < 20) e.sources.push({ kind, ...detail });
    map.set(ip, e);
  };
  const get = async (p) => { const r = await callInternal(ctx.router, p, { allow: ALLOWED }); return r.status === 200 ? r.json : null; };

  const al = await ctx.analyzerApi(`/api/alerts?limit=500&since=${since}`).catch(() => null);
  for (const a of (al && al.data && al.data.alerts) || []) {
    const ev = a.evidence || {};
    // Alerte de CAMPAGNE (regle globale) : evidence.ips = [[ip, nb], ...] ; kind distinct « campaign » (#83),
    // la regle (a.type) est conservee pour que le Hub montre dans quelle campagne l'IP apparait.
    if (ev.campaign === true && Array.isArray(ev.ips)) {
      for (const pair of ev.ips.slice(0, 200)) {
        const hits = Array.isArray(pair) ? Number(pair[1]) : NaN;
        add(Array.isArray(pair) ? pair[0] : pair, 'campaign', { type: a.type, severity: a.severity, ts: a.ts, vhost: (Array.isArray(ev.vhosts) && ev.vhosts[0]) || ev.vhost || null, ...(hits > 0 ? { hits } : {}) });
      }
      continue;
    }
    const ips = [].concat(ev.ip || [], Array.isArray(ev.ips) ? ev.ips : [], Array.isArray(ev.topIps) ? ev.topIps.map(x => x && x.ip) : []);
    for (const ip of ips.slice(0, 200)) add(ip, 'alert', { type: a.type, severity: a.severity, ts: a.ts, vhost: ev.vhost || null });
  }
  const off = await get(`/api/challenge/offenders?hours=${Math.min(168, h)}&min=1&limit=500&neverSolved=1`);
  for (const o of (off && off.offenders) || []) add(o.ip, 'challenge_fail', { attempts: o.attempts, last: o.lastSeen, banned_until: o.bannedUntil || null });
  for (const b of (off && off.bans) || []) add(b.ip, 'challenge_ban', { since: b.since, until: b.until, attempts: b.attempts });
  const cs = await get('/api/crowdsec/decisions?limit=500');
  for (const d of (cs && cs.decisions) || []) add(d.value, 'crowdsec', { scenario: d.scenario, type: d.type, origin: d.origin, duration: d.duration });
  const wf = await get(`/api/analyzer/waf/top-ips?hours=${h}`);
  for (const w of (wf && wf.ips) || []) add(w.ip, 'waf', { hits: w.count, blocked: w.blocked });
  const bl = await ctx.analyzerApi(`/api/blocklist-hits/summary?hours=${h}&limit=500`).catch(() => null);
  for (const b of (bl && bl.data && bl.data.topIps) || []) add(b.ip, 'blocklist_hit', { hits: b.hits || b.count, sources: b.sources });

  const rows = [...map.values()].map(e => ({ ip: e.ip, score: e.kinds.size, kinds: [...e.kinds].sort(), sources: e.sources }))
    .sort((a, b) => b.score - a.score || b.sources.length - a.sources.length).slice(0, limitOf(q, 500, 1000));
  return { data: { window_hours: h, count: rows.length, indicators: rows }, errors: {} };
}

const BUILDERS = { inventory: buildInventory, traffic: buildTraffic, security: buildSecurity, ops: buildOps, monitoring: buildMonitoring, reports: buildReports, indicators: buildIndicators };

/** @returns {{status:number, body:object}} */
async function buildModule(ctx, id, query, settings) {
  if (!BUILDERS[id]) return { status: 404, body: { error: 'Not found' } };
  if (!settings.expose.includes(id)) return { status: 404, body: { error: 'Not found' } };       // module désactivé : comme s'il n'existait pas
  if (id === 'indicators' && !settings.exposeIps) return { status: 403, body: { error: 'expose_ips_disabled' } };
  const { data, errors } = await BUILDERS[id](ctx, query);
  return { status: 200, body: { schema: 1, module: id, generated_at: new Date().toISOString(), instance: { id: ctx.instanceId, version: ctx.version }, expose_ips: !!settings.exposeIps,
    data: sanitize(data, settings.exposeIps && id === 'indicators' ? true : settings.exposeIps), errors } };
}

module.exports = { MODULE_IDS, PARTS, ALLOWED, sanitize, parseNginxV, buildModule, looksLikeIp };
