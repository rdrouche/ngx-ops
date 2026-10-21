'use strict';
/**
 * NGX Ops Intelligence (v12.69.0) — envoi des alertes de l'analyse vers
 * la plateforme centrale (qui n'existe pas encore : ce module est le CLIENT).
 *
 * Désactivé par défaut (config/intelligence.yml, `enable: false`). Deux modes :
 *  - anonymous : l'instance se présente avec son identifiant unique (INSTANCE_ID)
 *  - identified : identifiant + utilisateur + jeton (Authorization: Bearer)
 *
 * Le protocole (en-têtes, corps, codes de réponse, 429/Retry-After) est décrit
 * dans README.md et dans lib/intel-client.js, qui porte toute la logique.
 * Ici : lecture des réglages, transport HTTPS, état persistant, planificateur,
 * routes d'administration.
 */
const fs = require('fs');
const https = require('https');

const cfg      = require('../lib/config');
const httpLib  = require('../lib/http');
const auth     = require('../lib/auth');
const events   = require('../lib/events');
const notifications = require('../lib/notifications');
const settingsLib = require('../lib/intel-settings');
const client   = require('../lib/intel-client');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { logEvent } = events;

const MAX_RESPONSE = 64 * 1024;
let running = false;
let timer = null;

function readFileOr(f, d = '') { try { return fs.readFileSync(f, 'utf8'); } catch { return d; } }

function loadSettings() {
  return settingsLib.normalizeIntelSettings(readFileOr(cfg.INTELLIGENCE_CONFIG_FILE), {
    apiUrl: cfg.INTEL_API_URL, token: cfg.INTEL_TOKEN,
  });
}

function loadState() {
  try { return { ...client.initialState(), ...JSON.parse(fs.readFileSync(cfg.INTELLIGENCE_STATE_FILE, 'utf8')) }; }
  catch { return client.initialState(); }
}

function saveState(st) {
  try {
    const tmp = cfg.INTELLIGENCE_STATE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(st, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, cfg.INTELLIGENCE_STATE_FILE);
  } catch (e) { console.warn('[intelligence] etat non enregistre:', e.message); }
}

const instance = () => ({ id: cfg.INSTANCE_ID, version: cfg.VERSION });

/** Transport : HTTPS, aucune redirection suivie (le jeton ne doit jamais partir ailleurs), réponse bornée. */
function post({ url, headers, body, timeoutMs }) {
  return new Promise((resolve) => {
    let u; try { u = new URL(url); } catch { return resolve({ error: 'bad_url' }); }
    const payload = Buffer.from(JSON.stringify(body));
    const req = https.request({
      protocol: u.protocol, hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method: 'POST',
      headers: { ...headers, 'Content-Length': payload.length }, timeout: timeoutMs,
    }, (res) => {
      let buf = ''; let over = false;
      res.on('data', d => { if (buf.length + d.length > MAX_RESPONSE) { over = true; res.destroy(); } else buf += d; });
      const finish = () => {
        let parsed = null;
        if (buf) { try { parsed = JSON.parse(buf); } catch { parsed = null; } }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed, truncated: over });
      };
      res.on('end', finish); res.on('close', finish);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => resolve({ error: e.code || e.message }));
    req.write(payload); req.end();
  });
}

async function fetchAlerts(q) {
  const analyzer = require('./analyzer'); // chargé à la demande : pas de dépendance circulaire au démarrage
  const params = new URLSearchParams({ limit: String(q.limit || 100), order: q.order || 'asc' });
  if (q.sinceId) params.set('sinceId', String(q.sinceId));
  if (q.sinceTs) params.set('since', String(q.sinceTs));
  const r = await analyzer.analyzerApi('/api/alerts?' + params.toString());
  if (!r || r.status !== 200 || !r.data) return null;
  const alerts = r.data.alerts || [];
  let latestId = null;
  if (!alerts.length && q.sinceId) {
    const head = await analyzer.analyzerApi('/api/alerts?limit=1&order=desc');
    latestId = head && head.data && head.data.alerts && head.data.alerts[0] ? head.data.alerts[0].id : 0;
  }
  return { alerts, latestId };
}

/** Alertes du WAF émulé (conteneur ngx-waf) : même forme que celles de l'analyseur, curseur propre. */
async function fetchWafAlerts(q) {
  const waf = require('./waf'); // chargé à la demande
  const params = new URLSearchParams({ limit: String(q.limit || 100), order: q.order || 'asc' });
  if (q.sinceId) params.set('sinceId', String(q.sinceId));
  const r = await waf.wafApi('/api/alerts?' + params.toString());
  if (!r || r.status !== 200 || !r.data) return null;
  const alerts = r.data.alerts || [];
  return { alerts, latestId: r.data.latestId != null ? r.data.latestId : null };
}

/** Blocages automatiques du challenge integre (v12.73.0) : un evenement de blocage = une alerte, curseur = numero de sequence. */
async function fetchChallengeAlerts(q) {
  const CC = require('./challenge-container'); // charge a la demande
  const r = await CC.challengeBanEvents(q.sinceId || 0, 200);
  if (!r.ok) return null;
  const toAlert = (b) => ({
    id: b.seq, ts: b.since * 1000, type: 'challenge', severity: 'medium', ip: b.ip, vhost: b.host || null,
    evidence: { ip: b.ip, windowMinutes: b.windowMinutes, requests: b.attempts, redirected: b.redirected, failed: b.failed,
      rateLimited: b.rateLimited, banHours: Math.max(1, Math.round((b.until - b.since) / 3600)), userAgents: b.userAgent ? [b.userAgent] : [],
      firstSeen: b.since * 1000, lastSeen: b.since * 1000 },
  });
  const events = r.events || [];
  if (q.order === 'desc') return { alerts: events.length ? [toAlert(events[events.length - 1])] : [], latestId: r.latest };
  return { alerts: events.slice(0, q.limit || 100).map(toAlert), latestId: r.latest };
}

function challengeEnabled() {
  try {
    const { settings } = loadSettings();
    if (!settings.includeChallenge) return false;
    return require('./challenge-container').resolve().engine === 'builtin';
  } catch { return false; }
}

function wafEnabled() {
  try { return require('./waf').isEnabled(); } catch { return false; }
}

async function cycle(opts = {}) {
  if (running) return { outcome: 'busy' };
  running = true;
  try {
    const { settings } = loadSettings();
    const before = loadState();
    // La taille des lots suit la limite annoncee par le serveur (ping), sans jamais depasser le reglage.
    const eff = before.serverBatchLimit ? { ...settings, batchSize: Math.min(settings.batchSize, before.serverBatchLimit) } : settings;
    const r = await client.runCycle({ settings: eff, state: before, instance: instance(), deps: { fetchAlerts, post },
      userAgent: cfg.HTTP_USER_AGENT, force: !!opts.force });
    // Source WAF : cycle indépendant (curseur, backoff et 429 propres), mêmes réglages et même plateforme.
    let wafOutcome = null;
    if (wafEnabled() && !['disabled', 'not_ready', 'auth_error'].includes(r.outcome)) {
      const w = await client.runCycle({ settings: eff, state: before.waf, instance: instance(), deps: { fetchAlerts: fetchWafAlerts, post },
        userAgent: cfg.HTTP_USER_AGENT, force: !!opts.force });
      r.state.waf = w.state; wafOutcome = w.outcome;
      if (w.outcome === 'sent') r.sent = (r.sent || 0) + (w.sent || 0);
    } else if (before.waf) r.state.waf = before.waf;
    // Source challenge integre (opt-in include_challenge) : meme principe, curseur propre.
    let challengeOutcome = null;
    if (challengeEnabled() && !['disabled', 'not_ready', 'auth_error'].includes(r.outcome)) {
      const c = await client.runCycle({ settings: eff, state: before.challenge, instance: instance(), deps: { fetchAlerts: fetchChallengeAlerts, post },
        userAgent: cfg.HTTP_USER_AGENT, force: !!opts.force });
      r.state.challenge = c.state; challengeOutcome = c.outcome;
      if (c.outcome === 'sent') r.sent = (r.sent || 0) + (c.sent || 0);
    } else if (before.challenge) r.state.challenge = before.challenge;
    { const cur = loadState(); r.state.ping = cur.ping; r.state.serverBatchLimit = cur.serverBatchLimit; } // ecrits par un ping concurrent
    saveState(r.state);
    if (r.outcome === 'auth_error' && !before.authError) {
      logEvent('intelligence.auth_error', `Plateforme centrale : ${r.state.lastError} — envoi suspendu jusqu'a modification de la configuration`, 'system');
      try { notifications.pushNotification({ type: 'intelligence_auth', level: 'warning', message: `NGX Ops Intelligence : authentification refusee (${r.state.lastError}). Verifiez user/token dans intelligence.yml.` }); } catch { /* best effort */ }
    }
    if (r.outcome === 'sent' && !before.lastSuccessAt) logEvent('intelligence.first_send', `Premier lot envoye a la plateforme centrale (${r.sent} alerte(s))`, 'system');
    journalCycle(before, r);
    return { outcome: r.outcome, wafOutcome, challengeOutcome, state: r.state, sent: r.sent, rejected: r.rejected };
  } catch (e) {
    console.warn('[intelligence] cycle:', e.message);
    return { outcome: 'error', error: e.message };
  } finally { running = false; }
}

// ── Ping de connexion (POST /api/v1/ping) ────────────────────────────────────
let pinging = false;

/** Un ping : requete, classement, etat persiste, evenements sur transitions. `force` = bouton « Tester ». */
async function doPing({ force = false } = {}) {
  if (pinging) return { busy: true };
  pinging = true;
  try {
    const { settings } = loadSettings();
    if (!settings.ready || !settings.pingUrl) return { ok: false, kind: 'not_ready', code: 'not_ready', detail: null };
    const req = client.buildPingRequest({ settings, instance: instance(), userAgent: cfg.HTTP_USER_AGENT });
    const t0 = Date.now();
    const res = await post(req);
    const result = { ...client.classifyPing(res), latencyMs: Date.now() - t0 };
    const st = loadState(); // relu APRES l'attente reseau : un cycle d'envoi a pu avancer le curseur entre-temps
    const prev = st.ping || null;
    st.ping = client.nextPingState(prev, result, settings);
    // Credentials acceptes : on leve la suspension d'un echec d'authentification anterieur.
    if (result.ok && st.authError) { st.authError = false; st.failures = 0; st.nextAttemptAt = 0; st.lastError = null; }
    // Limites annoncees par le serveur : la taille des lots s'y adapte (jamais au-dessus du reglage).
    if (result.ok && result.limits && result.limits.maxAlertsPerBatch) st.serverBatchLimit = result.limits.maxAlertsPerBatch;
    saveState(st);
    journalPing(prev, st.ping, force);
    return st.ping;
  } catch (e) {
    return { ok: false, kind: 'retry', code: 'error', detail: String(e.message || e).slice(0, 200) };
  } finally { pinging = false; }
}

function journalPing(prev, cur, manual) {
  try {
    const was = prev ? prev.ok : null;
    if (cur.ok && (was !== true || manual)) {
      logEvent('intelligence.ping_ok', `Ping plateforme centrale : OK (${cur.latencyMs} ms${cur.server && cur.server.version ? ', serveur ' + cur.server.version : ''}${cur.authenticated ? ', authentifie' : ''})`, manual ? 'user' : 'system');
    } else if (!cur.ok && (!prev || prev.ok || prev.code !== cur.code)) {
      logEvent('intelligence.ping_error', `Ping plateforme centrale : echec ${cur.code}${cur.detail ? ' — ' + cur.detail : ''}${cur.status ? ' (HTTP ' + cur.status + ')' : ''}`, manual ? 'user' : 'system');
    }
    const w = (cur.warnings || []).join(' | ');
    if (cur.ok && w && w !== ((prev && prev.warnings) || []).join(' | ')) logEvent('intelligence.ping_warning', `Ping plateforme centrale : ${w}`, 'system');
  } catch { /* le journal ne doit jamais casser un ping */ }
}

function pingIfDue() {
  const { settings } = loadSettings();
  const why = client.pingDue({ settings, state: loadState() });
  if (why) doPing().catch(() => {});
}

/**
 * v12.70.5 : journal d'evenements (page Evenements) — un evenement par lot envoye, par nouvelle erreur et
 * par retour a la normale. Jamais d'evenement quand il n'y a rien a envoyer (pas de bruit toutes les 5 min).
 */
function journalCycle(before, r) {
  try {
    if (r.outcome === 'sent') {
      if (before.lastError) logEvent('intelligence.recovered', 'Envoi vers la plateforme centrale retabli', 'system');
      logEvent('intelligence.sent', `${r.sent || 0} alerte(s) envoyee(s) a la plateforme centrale${r.rejected ? ` (${r.rejected} rejetee(s))` : ''}${r.wafOutcome === 'sent' ? ' — WAF inclus' : ''}${r.challengeOutcome === 'sent' ? ' — blocages challenge inclus' : ''}`, 'system');
      return;
    }
    if (r.outcome === 'initialized') {
      logEvent('intelligence.initialized', 'Envoi initialise : seules les alertes a venir seront envoyees (backfill_hours dans intelligence.yml pour rejouer l\'historique)', 'system');
      return;
    }
    const failing = ['retry_later', 'rate_limited', 'dropped', 'batch_reduced', 'analyzer_unreachable'];
    if (failing.includes(r.outcome) && r.state.lastError && r.state.lastError !== before.lastError) {
      logEvent('intelligence.error', `Envoi vers la plateforme centrale : ${r.outcome} (${r.state.lastError}${r.state.lastHttpStatus ? ', HTTP ' + r.state.lastHttpStatus : ''})`, 'system');
    }
  } catch { /* le journal ne doit jamais casser un cycle */ }
}

// Configuration : un evenement a chaque changement de diagnostic (fichier present mais envoi impossible).
let lastConfigSig = null;
function journalConfig(settings, errors) {
  const reason = errors.length ? errors.join(' ; ')
    : (settings.enable && !settings.ready ? 'envoi non pret (url, utilisateur ou jeton manquant)' : '');
  const sig = reason + '|' + settings.enable;
  if (sig === lastConfigSig) return;
  const first = lastConfigSig === null;
  lastConfigSig = sig;
  if (reason) logEvent('intelligence.config_error', `Configuration NGX Ops Intelligence : ${reason}`, 'system');
  else if (!first && settings.enable) logEvent('intelligence.config_ok', 'Configuration NGX Ops Intelligence valide, envoi actif', 'system');
}

function startScheduler() {
  if (timer) return;
  try { const l = loadSettings(); journalConfig(l.settings, l.errors); } catch { /* ignore */ }
  timer = setInterval(() => {
    const { settings, errors } = loadSettings();
    journalConfig(settings, errors);
    pingIfDue();
    if (!settings.enable || !settings.ready) return;
    const st = loadState();
    const now = Date.now();
    if (st.pending || (st.waf && st.waf.pending) || (st.challenge && st.challenge.pending) || now - st.lastRunAt >= settings.intervalSeconds * 1000 || st.cursor == null) cycle().catch(() => {});
  }, 15_000);
  timer.unref();
}

function hostPath(u) { try { const x = new URL(u); return x.host + x.pathname; } catch { return null; } }
function pingPublic(p) {
  if (!p) return null;
  const { configHash: _h, nextAt, ...rest } = p; // eslint-disable-line no-unused-vars
  return { ...rest, nextAt: nextAt > Date.now() ? nextAt : null };
}

function publicStatus() {
  const { settings, errors } = loadSettings();
  const st = loadState();
  let host = null; try { host = settings.apiUrl ? new URL(settings.apiUrl).host : null; } catch { /* invalide */ }
  return {
    enabled: settings.enable, ready: settings.ready, mode: settings.mode, instanceId: cfg.INSTANCE_ID,
    apiHost: host, user: settings.mode === 'identified' ? settings.user : null, tokenSet: !!settings.token,
    intervalSeconds: settings.intervalSeconds, batchSize: settings.batchSize,
    excludeRules: settings.excludeRules, includeRules: settings.includeRules, minSeverity: settings.minSeverity,
    share: { userAgents: settings.shareUserAgents, paths: settings.sharePaths, vhost: settings.shareVhost },
    errors, configFile: cfg.INTELLIGENCE_CONFIG_FILE,
    state: {
      lastRunAt: st.lastRunAt || null, lastSuccessAt: st.lastSuccessAt || null, lastError: st.lastError,
      lastHttpStatus: st.lastHttpStatus, nextAttemptAt: st.nextAttemptAt > Date.now() ? st.nextAttemptAt : null,
      authError: !!st.authError, failures: st.failures, cursor: st.cursor, counters: st.counters,
    },
    ping: {
      enabled: settings.pingEnable, url: settings.pingUrl ? hostPath(settings.pingUrl) : null, intervalMinutes: settings.pingIntervalMinutes,
      canTest: !!settings.ready && !!settings.pingUrl, last: pingPublic(st.ping),
    },
    challenge: challengeEnabled() ? { cursor: st.challenge ? st.challenge.cursor : null, counters: st.challenge ? st.challenge.counters : null, lastError: st.challenge ? st.challenge.lastError : null } : null,
    waf: wafEnabled() ? { cursor: st.waf ? st.waf.cursor : null, counters: st.waf ? st.waf.counters : null, lastError: st.waf ? st.waf.lastError : null } : null,
  };
}

function register(router) {
  const guard = (session, res) => { if (!hasPerm(session, PERMS.ADMIN)) { httpLib.forbidden(res); return false; } return true; };

  router.get('/api/intelligence/status', async ({ res, session }) => {
    if (!guard(session, res)) return;
    return send(res, 200, publicStatus());
  });

  // Aperçu exact du prochain lot (jeton masqué) : sert aussi de référence de format.
  router.get('/api/intelligence/preview', async ({ res, session }) => {
    if (!guard(session, res)) return;
    const { settings } = loadSettings();
    const r = await client.runCycle({ settings, state: loadState(), instance: instance(), dryRun: true,
      deps: { fetchAlerts, post: async () => ({ error: 'dry_run' }) }, userAgent: cfg.HTTP_USER_AGENT });
    return send(res, 200, { outcome: r.outcome, request: r.request || null });
  });

  router.post('/api/intelligence/send-now', async ({ res, session }) => {
    if (!guard(session, res)) return;
    const { settings } = loadSettings();
    if (!settings.enable || !settings.ready) return httpLib.badRequest(res, 'intelligence disabled or not configured');
    const r = await cycle({ force: true });
    logEvent('intelligence.send_now', `Envoi manuel : ${r.outcome}`, session.username);
    return send(res, 200, { outcome: r.outcome, sent: r.sent || 0, rejected: r.rejected || 0, status: publicStatus().state });
  });

  // Test de connexion manuel (bouton de la page Systeme) : fonctionne des que l'URL (et l'identifiant en mode identified) sont configures.
  router.post('/api/intelligence/ping', async ({ res, session }) => {
    if (!guard(session, res)) return;
    const { settings } = loadSettings();
    if (!settings.ready || !settings.pingUrl) return httpLib.badRequest(res, 'intelligence not configured');
    const r = await doPing({ force: true });
    if (r.busy) return send(res, 200, { busy: true });
    return send(res, 200, { ping: pingPublic(r) });
  });

  router.post('/api/intelligence/reset', async ({ res, session }) => {
    if (!guard(session, res)) return;
    const st = loadState();
    st.authError = false; st.failures = 0; st.nextAttemptAt = 0; st.lastError = null; st.batchLimit = null;
    saveState(st);
    logEvent('intelligence.reset', 'Etat d\'erreur reinitialise', session.username);
    return send(res, 200, { ok: true });
  });
}

module.exports = { register, startScheduler, loadSettings, loadState, cycle, post, publicStatus };
