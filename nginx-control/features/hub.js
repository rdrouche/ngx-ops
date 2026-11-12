'use strict';
/**
 * NGX Ops Hub (v12.76.0) — API machine-à-machine consommée par le Hub.
 *
 *  Pull (le Hub interroge) — publiques, authentifiées par jeton, via maybeHandle()
 *  (appelé par server.js avant la session, comme /public/* et /auth/mfa) :
 *    GET /api/hub/v1/summary            en-tête X-Hub-Token  ↔ HUB_TOKEN_SHA256
 *    GET /api/hub/v1/backup/manifest    X-Hub-Token ↔ HUB_BACKUP_TOKEN_SHA256 (+ backup_enable)
 *    GET /api/hub/v1/backup/archive     idem — archive tar.gz (chiffrée si phrase de passe)
 *  Push (le dashboard envoie) : tâche planifiée « hub_backup » ou POST /api/hub/backup/push (admin).
 *
 * Désactivé par défaut : sans empreinte configurée la route répond 404. Lecture seule,
 * aucune IP de visiteur, aucun secret, aucun chemin disque dans le résumé.
 */
const crypto = require('crypto');
const cfg = require('../lib/config');
const auth = require('../lib/auth');
const httpLib = require('../lib/http');
const settingsLib = require('../lib/hub-settings');
const backupLib = require('../lib/hub-backup');
const pushLib = require('../lib/hub-push');
const digest = require('../lib/digest');
const detail = require('../lib/hub-detail');
const hubModules = require('../lib/hub-modules');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;

const SCHEMA = 1;
let deps = { fetchVTS: async () => null, analyzerApi: null };
let routerRef = null;
const modCache = new Map();   // route+requête -> { at, status, body } (15 s)
function setDeps(d) { Object.assign(deps, d || {}); }

// ── jeton + limitation de débit ─────────────────────────────────────────────
function verifyToken(received, hashes) {
  const got = crypto.createHash('sha256').update(String(received || '')).digest();
  let ok = false;
  for (const h of hashes) ok = crypto.timingSafeEqual(got, Buffer.from(h, 'hex')) || ok;
  return ok;
}
const hits = new Map();
function limited(key, max, windowMs = 60_000) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter(t => now - t < windowMs);
  arr.push(now); hits.set(key, arr);
  if (hits.size > 5000) hits.clear();
  return arr.length > max;
}

// ── résumé ──────────────────────────────────────────────────────────────────
let sumCache = { at: 0, body: null };
async function buildSummary(now = Date.now()) {
  const [vts, d] = await Promise.all([
    deps.fetchVTS().catch(() => null),
    digest.generateDigest(24).catch(() => null),
  ]);
  let alerts = { active: 0, critical: 0, items: [] };
  if (deps.analyzerApi) {
    try {
      const r = await deps.analyzerApi('/api/alerts?limit=10');
      const list = Array.isArray(r?.data?.alerts) ? r.data.alerts : [];
      alerts = {
        active: r?.data?.total ?? list.length,
        critical: list.filter(a => String(a.severity || '').toLowerCase() === 'high').length,
        items: list.slice(0, 10).map(a => ({ id: a.id, severity: a.severity || 'low', title: String(a.type || a.rule || 'alert').slice(0, 80), since: a.ts || a.created_at || null })),
      };
    } catch { /* analyseur absent */ }
  }
  const zones = vts && vts.serverZones ? Object.keys(vts.serverZones).filter(z => z !== '*').length : null;
  const sec = (d && d.certs && d.certs.expiringSoon) || [];
  return {
    schema: SCHEMA, generated_at: new Date(now).toISOString(),
    instance: { id: cfg.INSTANCE_ID, version: cfg.VERSION || cfg.APP_VERSION, name: process.env.SITE_NAME || undefined },
    nginx: { status: vts ? 'running' : 'unknown', version: vts?.nginxVersion || null, connections: vts?.connections || null },
    vhosts: { count: zones },
    traffic_24h: d && d.traffic ? {
      requests: d.traffic.totalRequests, errors: d.traffic.totalErrors, bytes: d.traffic.totalBytes,
      humans: d.bots ? d.bots.human : null, robots: d.bots ? d.bots.bots : null, blocked: d.waf?.configured ? d.waf.blockedCount : null,
    } : null,
    top_vhosts: d && d.traffic ? d.traffic.byVhost.slice(0, 10).map(v => ({ name: v.vhost, requests: v.requests, bytes: v.bytes, errors: v.errors })) : [],
    top_countries: d ? d.topCountries.map(c => ({ country: c.country, requests: c.requests })) : [],
    alerts,
    security: d ? {
      crowdsec: d.crowdsec.configured ? { active: d.crowdsec.activeTotal } : null,
      waf: d.waf.configured ? { blocked_24h: d.waf.blockedCount } : null,
      blocklists: d.blocklists?.enable ? { ips: d.blocklists.totalUniqueIps, hits_24h: d.blocklists.totalHits ?? null } : null,
    } : null,
    certs_expiring: sec.slice(0, 20),
    components: componentStates(d),
    mfa: { accounts: Object.keys(require('../lib/mfa-store').load().users).length },
  };
}

/** #126 : états du vocabulaire du contrat (ok | degraded | disabled | unknown). « configured »/« unreachable » n'en font pas partie
 *  et s'affichaient « Inconnu » dans le Hub. Un composant configuré dont la dernière collecte a échoué est « degraded ». */
function componentStates(d) {
  const failed = (name) => Array.isArray(d && d.errors) && d.errors.some((e) => String(e).startsWith(name + ':'));
  const comp = (cfgd, name) => (!cfgd ? { state: 'disabled' } : failed(name) ? { state: 'degraded' } : { state: 'ok' });
  return {
    analyzer: { state: d && d.traffic ? 'ok' : 'unknown' }, // pas de données de trafic ≠ analyseur arrêté : ne dégrade pas la santé de l'instance
    crowdsec: comp(d && d.crowdsec && d.crowdsec.configured, 'crowdsec'),
    waf: comp(d && d.waf && d.waf.configured, 'waf'),
  };
}

// ── détail : alertes et sécurité (v12.78.0) ─────────────────────────────────
async function fetchAlerts(params) {
  if (!deps.analyzerApi) return { alerts: [], total: 0, reachable: false };
  try {
    const r = await deps.analyzerApi('/api/alerts?' + params);
    const d = r && r.data;
    return { alerts: Array.isArray(d?.alerts) ? d.alerts : [], total: d?.total ?? 0, reachable: !!d };
  } catch { return { alerts: [], total: 0, reachable: false }; }
}
const intIn = (v, d, lo, hi) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d; };

/** GET /api/hub/v1/alerts?limit=100&since=<ms>&sinceId=<id>&severity=&type=&acked=0|1&order=asc|desc */
async function buildAlerts(s, q) {
  const p = new URLSearchParams({ limit: String(intIn(q.get('limit'), 100, 1, 500)) });
  for (const k of ['since', 'sinceId', 'offset']) if (/^\d{1,15}$/.test(q.get(k) || '')) p.set(k, q.get(k));
  for (const k of ['severity', 'type']) if (/^[a-z_]{1,40}$/.test(q.get(k) || '')) p.set(k, q.get(k));
  if (['0', '1'].includes(q.get('acked'))) p.set('acked', q.get('acked'));
  if (q.get('order') === 'asc') p.set('order', 'asc');
  const r = await fetchAlerts(p.toString());
  const alerts = detail.shapeAlerts(r.alerts, s.exposeIps);
  return { schema: SCHEMA, generated_at: new Date().toISOString(), instance: { id: cfg.INSTANCE_ID }, expose_ips: s.exposeIps,
    reachable: r.reachable, total: r.total, count: alerts.length, alerts };
}

// ── sauvegarde ──────────────────────────────────────────────────────────────
const lastPush = { at: null, ok: null, message: null, size: null, id: null };
let archCache = { at: 0, key: '', built: null };

function dirsFromCfg() {
  return { nginx: [cfg.DIR_SITES, cfg.DIR_CONF, cfg.DIR_SNIPPETS, cfg.DIR_STREAMS].filter(Boolean), config: cfg.CONFIG_DIR, ssl: cfg.DIR_SSL };
}
function buildBackup(s = settingsLib.load()) {
  return backupLib.build({
    dirs: dirsFromCfg(), include: s.include, includeSecrets: s.includeSecrets, passphrase: s.passphrase,
    retentionDays: s.retentionDays, instance: { id: cfg.INSTANCE_ID, version: cfg.VERSION || cfg.APP_VERSION },
  });
}
async function runPush(reason = 'manual') {
  const s = settingsLib.load();
  const fail = (message) => { Object.assign(lastPush, { at: new Date().toISOString(), ok: false, message }); return { ok: false, message }; };
  if (!s.backupEnable) return fail('backup_enable is false (config/hub.yml)');
  if (!s.hubUrl) return fail('hub_url missing or invalid (config/hub.yml)');
  if (!s.pushToken) return fail('HUB_PUSH_TOKEN not set');
  let built;
  try { built = buildBackup(s); } catch (e) { return fail(e.message); }
  const r = await pushLib.sendBackup({ hubUrl: s.hubUrl, token: s.pushToken, archive: built.archive, sha256: built.sha256, manifest: built.manifest, instanceId: cfg.INSTANCE_ID, version: cfg.VERSION || cfg.APP_VERSION, timeoutMs: s.timeoutSeconds * 1000 });
  Object.assign(lastPush, { at: new Date().toISOString(), ok: r.ok, message: r.ok ? `${built.manifest.files.length} file(s), ${built.archive.length} B (${reason})` : r.error, size: built.archive.length, id: r.id || null });
  return { ok: r.ok, message: lastPush.message, files: built.manifest.files.length, size: built.archive.length, id: r.id };
}

// ── HTTP public (pull) ──────────────────────────────────────────────────────
async function maybeHandle(req, res, pathname, ip) {
  if (!pathname.startsWith('/api/hub/v1/')) return false;
  const s = settingsLib.load();
  const route = pathname.slice('/api/hub/v1/'.length);
  const notFound = () => { send(res, 404, { error: 'Not found' }); return true; };
  if (req.method !== 'GET') return notFound();
  const needBackup = route === 'backup/manifest' || route === 'backup/archive';
  const isModule = hubModules.MODULE_IDS.includes(route);
  const needDetail = route === 'alerts';
  if (route !== 'summary' && !needBackup && !needDetail && !isModule) return notFound();
  const hashes = needBackup ? (s.backupEnable ? s.backupHashes : []) : s.summaryHashes;
  if (!hashes.length) return notFound();                       // désactivé : comme si la route n'existait pas
  if (limited('hub:' + needBackup + ':' + ip, needBackup ? 20 : 30)) { send(res, 429, { error: 'rate_limited' }, 'application/json', { 'Retry-After': '60' }); return true; }
  if (!verifyToken(req.headers['x-hub-token'], hashes)) { send(res, 401, { error: 'unauthorized' }); return true; }

  const noStore = { 'Cache-Control': 'no-store' };
  if (isModule) {
    if (!routerRef) return notFound();
    const qs = new URL(req.url, 'http://x').searchParams;
    const ck = route + '?' + [...qs.entries()].filter(([k]) => ['hours', 'limit'].includes(k)).map(([k, v]) => k + '=' + v).sort().join('&');
    let hit = modCache.get(ck);
    if (!hit || Date.now() - hit.at > 15_000) {
      const ctx = { router: routerRef, analyzerApi: deps.analyzerApi || (async () => null), fetchVTS: deps.fetchVTS, execNginx: deps.execNginx || (async () => null),
        queryEvents: require('../lib/events').queryEvents, instanceId: cfg.INSTANCE_ID, version: cfg.VERSION || cfg.APP_VERSION };
      let out;
      try { out = await hubModules.buildModule(ctx, route, qs, s); } catch (e) { out = { status: 500, body: { error: 'module_error' } }; }
      hit = { at: Date.now(), ...out };
      if (modCache.size > 50) modCache.clear();
      modCache.set(ck, hit);
    }
    send(res, hit.status, hit.body, 'application/json', noStore); return true;
  }
  if (needDetail) {
    const q = new URL(req.url, 'http://x').searchParams;
    const out = await buildAlerts(s, q);
    send(res, 200, out, 'application/json', noStore); return true;
  }
  if (route === 'summary') {
    if (!sumCache.body || Date.now() - sumCache.at > 5000) sumCache = { at: Date.now(), body: await buildSummary() };
    send(res, 200, sumCache.body, 'application/json', noStore); return true;
  }
  const key = JSON.stringify([s.include, s.includeSecrets, !!s.passphrase]);
  if (!archCache.built || archCache.key !== key || Date.now() - archCache.at > 30_000) {
    try { archCache = { at: Date.now(), key, built: buildBackup(s) }; }
    catch (e) { send(res, 409, { error: e.message }); return true; }
  }
  const b = archCache.built;
  if (route === 'backup/manifest') { send(res, 200, { ...b.manifest, archive_sha256: b.sha256, archive_bytes: b.archive.length }, 'application/json', noStore); return true; }
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': b.archive.length, 'X-Backup-Sha256': b.sha256, 'X-Backup-Encrypted': b.manifest.encrypted ? '1' : '0', ...noStore, 'X-Content-Type-Options': 'nosniff' });
  res.end(b.archive); return true;
}

// ── API admin (session) ─────────────────────────────────────────────────────
function register(router) {
  routerRef = router;
  router.get('/api/hub/status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    const s = settingsLib.load();
    return send(res, 200, {
      summary: { enabled: s.summaryHashes.length > 0, tokens: s.summaryHashes.length },
      backup: { enabled: s.backupEnable, hubUrl: s.hubUrl, include: s.include, includeSecrets: s.includeSecrets, encrypted: !!s.passphrase,
        retentionDays: s.retentionDays, pushConfigured: !!(s.hubUrl && s.pushToken), pullEnabled: s.backupEnable && s.backupHashes.length > 0 },
      lastPush,
    });
  });
  router.post('/api/hub/backup/push', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    const r = await runPush('manual');
    require('../lib/events').logEvent('hub.backup.push', { ok: r.ok, message: r.message, by: session.username }, 'hub');
    return send(res, r.ok ? 200 : 502, r);
  });
}

module.exports = { register, maybeHandle, setDeps, buildSummary, runPush, buildBackup, verifyToken, componentStates };
