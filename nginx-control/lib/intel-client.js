'use strict';
/**
 * NGX Ops Intelligence (v12.69.0) — client d'envoi des alertes de
 * l'analyse vers la plateforme centrale. Logique pure (aucune E/S directe : le
 * transport et la lecture des alertes sont injectés) pour être testée
 * isolément ; features/intelligence.js l'assemble avec le réseau et le disque.
 *
 * Contrat du protocole (schéma 1) : voir README.md, section « NGX Ops
 * Intelligence », et le document du Projet `design-intelligence-api.md`.
 */
const crypto = require('crypto');
const { SEVERITY_RANK } = require('./intel-settings');
const { ipInCidr } = require('./cidr');

const SCHEMA = 1;
const BUILTIN_RULES = new Set(['bruteforce', 'scan', 'flood', 'scraping', 'volumetric', 'country_traffic', 'data_volume']);
const MAX_PATHS = 10, MAX_UAS = 3, MAX_CAMPAIGN_IPS = 50, MAX_STR = 200;
const BACKOFF_BASE_MS = 30_000, BACKOFF_MAX_MS = 3_600_000, RETRY_AFTER_MAX_MS = 86_400_000;

const str = (v, n = MAX_STR) => String(v == null ? '' : v).slice(0, n);
const iso = (ms) => (Number.isFinite(+ms) && +ms > 0 ? new Date(+ms).toISOString() : null);

/** { key, kind, id, name } d'une alerte de l'analyseur. */
function ruleOf(a) {
  const type = String(a.type || '');
  // v12.70.0 : alertes du WAF émulé (score d'anomalie CRS cumulé par IP)
  if (type === 'waf') return { key: 'waf', kind: 'waf', id: null, name: 'waf' };
  // v12.73.0 : blocage automatique d'une IP par le challenge integre (echecs repetes)
  if (type === 'challenge') return { key: 'challenge', kind: 'challenge', id: null, name: 'challenge' };
  if (BUILTIN_RULES.has(type)) return { key: type, kind: 'builtin', id: null, name: type };
  const ev = a.evidence || {};
  return { key: 'custom', kind: 'custom', id: ev.ruleId != null ? ev.ruleId : null, name: str(ev.ruleName || type, 64) };
}

/** Faut-il envoyer cette alerte ? (règle exclue/non incluse, sévérité trop basse) */
function shouldSend(a, s) {
  // v12.75.0 : IP exclues (exclude_ips) — l'alerte n'est jamais envoyee, quelle que soit la regle.
  if (s.excludeIps && s.excludeIps.length) {
    const ev = a.evidence || {};
    const ips = [a.ip, ev.ip].filter(Boolean);
    if (ips.some(ip => s.excludeIps.some(p => ipInCidr(ip, p)))) return false;
  }
  const r = ruleOf(a);
  const names = [r.key, r.name, String(a.type || '')];
  if (names.some(n => s.excludeRules.includes(n))) return false;
  if (s.includeRules.length && !names.some(n => s.includeRules.includes(n))) return false;
  return (SEVERITY_RANK[a.severity] || 2) >= (SEVERITY_RANK[s.minSeverity] || 1);
}

/** Alerte de l'analyseur -> objet du lot (schéma 1). Les champs partagés dépendent des réglages. */
function shapeAlert(a, s) {
  const ev = a.evidence || {};
  const campaign = !!ev.campaign;
  const out = {
    id: String(a.id),
    ts: iso(a.ts),
    rule: ruleOf(a),
    severity: a.severity || 'medium',
    scope: campaign ? 'campaign' : 'ip',
    ip: campaign ? null : (a.ip || ev.ip || null),
  };
  if (campaign && Array.isArray(ev.ips)) {
    out.ips = ev.ips.filter(x => !(s.excludeIps || []).some(p => ipInCidr(String(x[0]), p))).slice(0, MAX_CAMPAIGN_IPS).map(x => [str(x[0], 45), Number(x[1]) || 0]);
  }
  const num = (k, v) => { if (Number.isFinite(+v) && v != null) out[k] = +v; };
  num('window_minutes', ev.windowMinutes);
  num('requests', ev.requests);
  num('distinct_paths', ev.distinctPaths);
  num('matches', ev.matches);
  num('not_found', ev.notFound);
  num('auth_failures', ev.authFailures);
  num('distinct_ips', ev.globalIps);
  const fs = iso(ev.firstSeen), ls = iso(ev.lastSeen);
  if (fs) out.first_seen = fs;
  if (ls) out.last_seen = ls;
  if (ev.statuses && typeof ev.statuses === 'object') {
    out.statuses = {};
    for (const [k, v] of Object.entries(ev.statuses).slice(0, 20)) out.statuses[str(k, 3)] = Number(v) || 0;
  }
  if (String(a.type || '') === 'waf') {
    const rules = Array.isArray(ev.rules) ? ev.rules : [];
    out.waf = {
      score: Number(ev.score) || 0,
      mode: ev.mode === 'remediate' ? 'remediate' : 'observe',
      rules: rules.slice(0, 20).map(r => ({ id: Number(r.id) || 0, count: Number(r.count) || 1, severity: str(r.severity, 12) })),
      tags: (Array.isArray(ev.tags) ? ev.tags : []).slice(0, 20).map(x => str(x, 64)),
      categories: (Array.isArray(ev.categories) ? ev.categories : []).slice(0, 12).map(x => str(x, 32)),
    };
    if (s.shareUserAgents) out.user_agents = (ev.userAgents || []).slice(0, MAX_UAS).map(u => str(u));
    if (s.sharePaths) out.paths = (ev.paths || []).slice(0, MAX_PATHS).map(p => str(p));
    if (s.shareVhost && (a.vhost || ev.vhost)) out.vhost = str(a.vhost || ev.vhost, 253);
    return out;
  }
  if (String(a.type || '') === 'challenge') {
    out.challenge = {
      attempts: Number(ev.requests) || 0,
      redirected: Number(ev.redirected) || 0,
      failed: Number(ev.failed) || 0,
      rate_limited: Number(ev.rateLimited) || 0,
      ban_hours: Number(ev.banHours) || 0,
    };
    if (s.shareUserAgents) out.user_agents = (ev.userAgents || []).slice(0, MAX_UAS).map(u => str(u));
    if (s.shareVhost && (a.vhost || ev.vhost)) out.vhost = str(a.vhost || ev.vhost, 253);
    return out;
  }
  if (s.shareUserAgents) {
    const uas = campaign ? (ev.topUserAgents || []).map(x => x.ua) : (ev.userAgents || []);
    out.user_agents = uas.slice(0, MAX_UAS).map(u => str(u));
  }
  if (s.sharePaths) {
    const paths = campaign ? (ev.topPaths || []).map(x => x.path)
      : [...new Set((ev.samples || []).map(x => x && x.path).filter(Boolean))];
    out.paths = paths.slice(0, MAX_PATHS).map(p => str(p));
  }
  if (s.shareVhost && (a.vhost || ev.vhost)) out.vhost = str(a.vhost || ev.vhost, 253);
  return out;
}

/** Corps d'une requête d'envoi. `alerts` : alertes brutes de l'analyseur, déjà filtrées. */
function buildBatch({ settings, instance, alerts, now = Date.now(), batchId = crypto.randomUUID() }) {
  const body = {
    schema: SCHEMA,
    batch_id: batchId,
    sent_at: iso(now),
    mode: settings.mode,
    instance: { id: instance.id, version: instance.version },
    alerts: alerts.map(a => shapeAlert(a, settings)),
  };
  if (settings.mode === 'identified') body.user = settings.user;
  return body;
}

/** En-têtes de la requête. Le jeton n'apparaît qu'en mode identifié. */
function buildHeaders({ settings, instance, body, userAgent }) {
  const h = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': userAgent || 'NGXOps',
    'X-NC-Schema': String(SCHEMA),
    'X-NC-Instance-Id': instance.id,
    'X-NC-Client-Version': instance.version,
    'Idempotency-Key': body.batch_id,
  };
  if (settings.mode === 'identified') {
    h['Authorization'] = `Bearer ${settings.token}`;
    h['X-NC-User'] = settings.user;
  }
  return h;
}

/** Requete de ping : memes en-tetes que l'envoi (sans Idempotency-Key), corps minimal optionnel. */
function buildPingRequest({ settings, instance, userAgent }) {
  const body = { schema: SCHEMA, mode: settings.mode, instance: { id: instance.id, version: instance.version } };
  if (settings.mode === 'identified') body.user = settings.user;
  const headers = buildHeaders({ settings, instance, body: {}, userAgent });
  delete headers['Idempotency-Key'];
  return { url: settings.pingUrl, headers, body, timeoutMs: Math.min(settings.timeoutSeconds, 15) * 1000 };
}

function parseRetryAfter(v, now = Date.now()) {
  if (v == null || v === '') return null;
  if (/^\d+$/.test(String(v).trim())) return Math.min(RETRY_AFTER_MAX_MS, Number(v) * 1000);
  const t = Date.parse(v);
  return Number.isFinite(t) ? Math.min(RETRY_AFTER_MAX_MS, Math.max(0, t - now)) : null;
}

function backoffMs(failures, rand = Math.random) {
  const base = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** Math.max(0, failures - 1));
  return Math.round(base * (0.8 + 0.4 * rand())); // ±20 % : évite que toute une flotte réessaie en même temps
}

/**
 * Réponse de la plateforme -> décision.
 *  ok          2xx : lot accepté (même partiellement : `rejected` est compté, pas rejoué)
 *  rateLimited 429 : on attend Retry-After (sinon backoff), on rejoue le même lot
 *  auth        401/403 : on s'arrête tant que la configuration ne change pas
 *  tooLarge    413 : on réduit la taille des lots
 *  drop        autres 4xx (400, 404, 410, 422…) : lot invalide, on l'abandonne pour ne pas bloquer la file
 *  retry       5xx, 408, 3xx (redirections non suivies), erreur réseau : backoff exponentiel
 */
function classifyResponse(res, now = Date.now()) {
  if (!res || res.error) return { kind: 'retry', reason: (res && res.error) || 'network' };
  const st = res.status;
  if (st >= 200 && st < 300) return { kind: 'ok' };
  if (st === 429) return { kind: 'rateLimited', retryAfterMs: parseRetryAfter(res.headers && res.headers['retry-after'], now), reason: 'http 429' };
  if (st === 401 || st === 403) return { kind: 'auth', reason: `http ${st}` };
  if (st === 413) return { kind: 'tooLarge', reason: 'http 413' };
  if (st === 408 || st >= 500 || (st >= 300 && st < 400)) return { kind: 'retry', reason: `http ${st}` };
  if (st >= 400) return { kind: 'drop', reason: `http ${st}` };
  return { kind: 'retry', reason: `http ${st}` };
}

function configHash(s) {
  return crypto.createHash('sha256').update([s.mode, s.apiUrl, s.user, s.token].join('\n')).digest('hex').slice(0, 16);
}

function initialState() {
  return {
    cursor: null, failures: 0, nextAttemptAt: 0, lastRunAt: 0, lastSuccessAt: 0,
    lastError: null, lastHttpStatus: null, authError: false, authConfigHash: null,
    batchLimit: null, pending: false,
    rejectReasons: {}, // motif -> nombre (borné), pour comprendre les rejets du serveur (#83)
    counters: { batches: 0, sent: 0, accepted: 0, rejected: 0, skipped: 0, dropped: 0, http429: 0, errors: 0 },
  };
}

/**
 * Un cycle d'envoi. Retourne { state, outcome, request? } sans jamais lever.
 *
 * deps.fetchAlerts({ sinceId, sinceTs, limit, order }) -> { alerts, latestId } | null (analyseur injoignable)
 * deps.post({ url, headers, body, timeoutMs }) -> { status, headers, body } | { error }
 */
async function runCycle({ settings, state, instance, now = Date.now(), deps, userAgent, dryRun = false, force = false }) {
  const st = { ...initialState(), ...state, counters: { ...initialState().counters, ...(state && state.counters) } };
  const done = (outcome, extra = {}) => ({ state: st, outcome, ...extra });
  if (!settings.enable && !dryRun) return done('disabled');
  if (!settings.ready && !dryRun) return done('not_ready');
  const hash = configHash(settings);
  if (st.authError && st.authConfigHash === hash && !force) return done('auth_error');
  if (st.authError && st.authConfigHash !== hash) { st.authError = false; st.failures = 0; st.nextAttemptAt = 0; }
  if (!force && !dryRun && now < st.nextAttemptAt) return done('backoff');

  const limit = Math.min(settings.batchSize, st.batchLimit || settings.batchSize);
  let q;
  if (st.cursor == null && dryRun) {
    q = { limit, order: 'desc' }; // aperçu : les dernières alertes, sans toucher au curseur
  } else {
    if (st.cursor == null) {
      // Premier envoi : on part de maintenant (pas d'historique) sauf backfill_hours.
      if (settings.backfillHours > 0) st.cursor = 0;
      else {
        const head = await deps.fetchAlerts({ limit: 1, order: 'desc' });
        if (!head) { st.lastError = 'analyzer_unreachable'; st.nextAttemptAt = now + 60_000; return done('analyzer_unreachable'); }
        st.cursor = head.alerts.length ? head.alerts[0].id : 0;
        return done('initialized');
      }
    }
    q = settings.backfillHours > 0 && st.cursor === 0
      ? { sinceTs: now - settings.backfillHours * 3600_000, limit, order: 'asc' }
      : { sinceId: st.cursor, limit, order: 'asc' };
  }
  const page = await deps.fetchAlerts(q);
  if (!page) { st.lastError = 'analyzer_unreachable'; st.nextAttemptAt = now + 60_000; return done('analyzer_unreachable'); }
  if (q.order === 'desc' && page.alerts) page.alerts = [...page.alerts].reverse();
  st.lastRunAt = now;
  const raw = page.alerts || [];
  if (!raw.length) {
    // Base de l'analyseur remise à zéro : le curseur dépasse les identifiants existants.
    if (page.latestId != null && st.cursor > page.latestId) st.cursor = page.latestId;
    st.pending = false;
    return done('empty');
  }
  const lastRawId = raw[raw.length - 1].id;
  const chosen = raw.filter(a => shouldSend(a, settings));
  if (!chosen.length) {
    if (!dryRun) { st.cursor = lastRawId; st.counters.skipped += raw.length; st.pending = raw.length >= limit; }
    return done('filtered', { skipped: raw.length });
  }
  const body = buildBatch({ settings, instance, alerts: chosen, now });
  const request = { url: settings.apiUrl, headers: buildHeaders({ settings, instance, body, userAgent }), body, timeoutMs: settings.timeoutSeconds * 1000 };
  if (dryRun) return done('preview', { request: { ...request, headers: { ...request.headers, ...(request.headers.Authorization ? { Authorization: 'Bearer ***' } : {}) } } });

  const res = await deps.post(request);
  st.counters.batches++;
  st.lastHttpStatus = res && res.status != null ? res.status : null;
  const c = classifyResponse(res, now);
  switch (c.kind) {
    case 'ok': {
      const r = res.body && typeof res.body === 'object' ? res.body : {};
      const rejected = Array.isArray(r.rejected) ? r.rejected.length : 0;
      st.cursor = lastRawId;
      st.counters.sent += chosen.length;
      st.counters.accepted += Number.isFinite(+r.accepted) ? +r.accepted : chosen.length - rejected;
      st.counters.rejected += rejected;
      if (rejected) {
        const rr = { ...(st.rejectReasons || {}) };
        for (const x of r.rejected) { const k = str(x && x.reason, 80) || 'unknown'; if (k in rr || Object.keys(rr).length < 20) rr[k] = (rr[k] || 0) + 1; }
        st.rejectReasons = rr;
      }
      st.counters.skipped += raw.length - chosen.length;
      st.failures = 0; st.lastError = null; st.lastSuccessAt = now; st.nextAttemptAt = 0;
      st.pending = raw.length >= limit; // il reste probablement des alertes : on enchaîne sans attendre l'intervalle
      return done('sent', { sent: chosen.length, rejected });
    }
    case 'rateLimited':
      st.failures++; st.counters.http429++; st.lastError = c.reason; st.pending = false;
      st.nextAttemptAt = now + Math.max(c.retryAfterMs || 0, backoffMs(st.failures));
      return done('rate_limited');
    case 'auth':
      st.authError = true; st.authConfigHash = hash; st.lastError = c.reason; st.counters.errors++; st.pending = false;
      return done('auth_error');
    case 'tooLarge':
      st.batchLimit = Math.max(1, Math.floor(chosen.length / 2)); st.lastError = c.reason; st.nextAttemptAt = 0; st.pending = true;
      return done('batch_reduced');
    case 'drop':
      st.cursor = lastRawId; st.counters.dropped += chosen.length; st.counters.errors++; st.lastError = c.reason; st.pending = false;
      return done('dropped');
    default:
      st.failures++; st.counters.errors++; st.lastError = c.reason; st.pending = false;
      st.nextAttemptAt = now + backoffMs(st.failures);
      return done('retry_later');
  }
}

/**
 * Reponse du ping -> resultat affichable (jamais de jeton). `kind` pilote la suite :
 *  ok | auth (401/403 : plus de ping periodique tant que la config ne change pas) | rateLimited | retry
 */
function classifyPing(res, now = Date.now()) {
  const base = { at: now, status: res && res.status != null ? res.status : null };
  if (!res || res.error) return { ...base, ok: false, kind: 'retry', code: 'network', detail: (res && res.error) || 'network' };
  const b = res.body && typeof res.body === 'object' ? res.body : {};
  const str = (v, n) => (typeof v === 'string' ? v.slice(0, n) : null);
  if (res.status >= 200 && res.status < 300) {
    const lim = b.limits && typeof b.limits === 'object' ? b.limits : {};
    const n = (v) => (Number.isFinite(+v) && +v > 0 ? Math.round(+v) : null);
    return {
      ...base, ok: true, kind: 'ok', code: null, detail: null,
      server: b.server && typeof b.server === 'object' ? { name: str(b.server.name, 80), version: str(b.server.version, 40), time: str(b.server.time, 40) } : null,
      authenticated: b.authenticated === true, mode: str(b.mode, 20), user: str(b.user, 254),
      instance: b.instance && typeof b.instance === 'object'
        ? { isNew: b.instance.new === true, trustLevel: str(b.instance.trust_level, 40), lastBatchAt: str(b.instance.last_batch_at, 40), pings: n(b.instance.pings) }
        : null,
      limits: { maxAlertsPerBatch: n(lim.max_alerts_per_batch), maxBodyBytes: n(lim.max_body_bytes), batchesPerMinute: n(lim.batches_per_minute) },
      warnings: Array.isArray(b.warnings) ? b.warnings.map(w => String(w).slice(0, 300)).slice(0, 10) : [],
      schemas: Array.isArray(b.schemas) ? b.schemas.filter(x => Number.isInteger(x)).slice(0, 10) : [],
    };
  }
  const code = str(b.code, 60) || (res.status === 429 ? 'rate_limited' : 'http_' + res.status);
  const detail = str(b.detail, 300) || str(b.error, 300) || null;
  if (res.status === 401 || res.status === 403) return { ...base, ok: false, kind: 'auth', code, detail };
  if (res.status === 429) return { ...base, ok: false, kind: 'rateLimited', code, detail, retryAfterMs: parseRetryAfter(res.headers && res.headers['retry-after'], now) };
  return { ...base, ok: false, kind: 'retry', code, detail };
}

/**
 * Faut-il pinguer maintenant ? `pingState` = state.ping (ou null). Retourne la raison ou null.
 *  - config changee (ou jamais pingue) : tout de suite (demarrage, modification du fichier) ;
 *  - 401/403 sur ce ping et config inchangee : jamais en periodique (inutile, bruit cote serveur) ;
 *  - sinon : quand l'intervalle est ecoule depuis la derniere preuve de connexion (ping OU lot accepte),
 *    donc aucun ping superflu pendant qu'un trafic d'alertes passe deja ;
 *  - jamais avant `nextAt` (backoff apres echec / Retry-After).
 */
function pingDue({ settings, state, now = Date.now() }) {
  if (!settings.enable || !settings.ready || !settings.pingEnable || !settings.pingUrl) return null;
  const p = state && state.ping;
  const hash = configHash(settings);
  if (!p || p.configHash !== hash) return (p && p.nextAt > now) ? null : 'config';
  if (p.nextAt > now) return null;
  if (p.kind === 'auth') return null;
  const last = Math.max(p.at || 0, (state && state.lastSuccessAt) || 0);
  return now - last >= settings.pingIntervalMinutes * 60_000 ? 'interval' : null;
}

/** Nouvel etat `ping` apres un resultat (compteurs, prochain essai). */
function nextPingState(prev, result, settings, now = Date.now()) {
  const p = prev || {};
  const failures = result.ok ? 0 : (p.failures || 0) + 1;
  let nextAt = 0;
  if (!result.ok) {
    nextAt = result.kind === 'rateLimited'
      ? now + Math.max(result.retryAfterMs || 0, settings.pingIntervalMinutes * 60_000)
      : now + Math.max(settings.pingIntervalMinutes * 60_000, backoffMs(failures));
  }
  return { ...result, configHash: configHash(settings), failures, nextAt, okAt: result.ok ? now : (p.okAt || null), total: (p.total || 0) + 1 };
}

module.exports = {
  buildPingRequest, classifyPing, pingDue, nextPingState,
  SCHEMA, BUILTIN_RULES, ruleOf, shouldSend, shapeAlert, buildBatch, buildHeaders,
  parseRetryAfter, backoffMs, classifyResponse, configHash, initialState, runCycle,
};
