'use strict';
/**
 * WAF emule (conteneur `ngx-waf`) — cycle de vie Docker + proxy de son API.
 *
 * Le WAF est EMULE : un conteneur Go (Coraza v3 en DetectionOnly + OWASP CRS)
 * relit les journaux d'acces a posteriori et reconstruit une requete synthetique
 * par ligne. Il ne bloque jamais directement et ne voit pas les corps POST ; la
 * « remediation » alimente des listes (waf-block / waf-challenge) consommees par
 * la fonctionnalite Blocklists (source `type: waf`), qui protegent les requetes
 * SUIVANTES. Le contrat complet (variables d'ENV, endpoints) est dans
 * WAF-CONTRACT.md ; la logique pure est dans lib/waf-config.js,
 * lib/waf-validate.js et lib/waf-diagnostics.js.
 *
 * Meme modele que features/analyzer.js : le dashboard possede le cycle de vie
 * (pull, creation, arret, redemarrage, mise a jour d'image) et proxifie l'API.
 * Securite :
 *  - le port du WAF n'est jamais publie ; l'API exige l'en-tete X-WAF-Token (secret
 *    genere une fois, lib/waf-token.js), jamais envoye au navigateur ni journalise ;
 *  - l'hote appele est le nom du conteneur de config/waf.yml (valide), JAMAIS une
 *    entree utilisateur (pas de SSRF) ; chaque parametre/corps relaye est valide
 *    (liste blanche + bornes, lib/waf-validate.js) ;
 *  - lectures : PERMS.VIEW_CONFIGS ; actions qui modifient : PERMS.DEPLOY.
 */
const fs   = require('fs');
const path = require('path');
const http = require('http');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const lifecycle = require('../lib/container-lifecycle');
const events  = require('../lib/events');
const WC      = require('../lib/waf-config');
const WV      = require('../lib/waf-validate');
const WD      = require('../lib/waf-diagnostics');
const { getWafToken } = require('../lib/waf-token');
const { getShipperToken } = require('../lib/shipper-token');
const { listVhostTargets } = require('../lib/vhost-targets');
const { parseAndValidate } = require('../lib/blocklist-yaml');
const { readChallengeOverrides } = require('../lib/challenge-settings');
const { safeReadDir, safeReadFile } = require('../lib/fs-tree');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { dockerCall } = docker;
const { logEvent } = events;

const MAX_JSON = 8 * 1024 * 1024;
const MAX_TEXT = 2 * 1024 * 1024;

function readFileOr(f, def = '') { try { return fs.readFileSync(f, 'utf8'); } catch { return def; } }

/** Configuration effective, relue a chaque appel (waf.yml est editable a chaud). */
function resolveConfig() {
  const exists = fs.existsSync(cfg.WAF_CONFIG_FILE);
  const r = WC.normalizeWafConfig(readFileOr(cfg.WAF_CONFIG_FILE), {
    defaultImage: cfg.WAF_DEFAULT_IMAGE, defaultLogsPath: cfg.HOST_LOGS,
  });
  return { ...r, exists };
}

// ─── Messages de refus (bilingues : l'UI les traduit aussi par `code`) ───────
const REFUSALS = {
  disabled: {
    fr: "Le WAF émulé n'est pas activé (config/waf.yml : enable: true).",
    en: 'The emulated WAF is not enabled (config/waf.yml: enable: true).',
  },
  accept_limits_required: {
    fr: "Le WAF est émulé : il analyse les journaux d'accès a posteriori, ne bloque jamais directement et ne voit pas les corps de requête POST ; la remédiation (listes block/challenge) ne protège que les requêtes SUIVANTES. Pour le démarrer, reconnaissez ces limites avec « accept_limits: true » dans config/waf.yml.",
    en: 'The WAF is emulated: it analyses access logs after the fact, never blocks directly and cannot see POST bodies; remediation (block/challenge lists) only protects FOLLOWING requests. To start it, acknowledge these limits with "accept_limits: true" in config/waf.yml.',
  },
  host_data_path_required: {
    fr: "host_data_path manquant dans waf.yml : chemin HÔTE du dossier d'état (réglages, base des hits), sans lui tout est perdu à chaque recréation du conteneur.",
    en: 'host_data_path is missing in waf.yml: HOST path of the state folder (settings, hits database); without it everything is lost whenever the container is recreated.',
  },
  host_rules_path_required: {
    fr: "host_rules_path manquant dans waf.yml : chemin HÔTE du dossier des règles (jeu OWASP CRS téléchargé, règles personnalisées).",
    en: 'host_rules_path is missing in waf.yml: HOST path of the rules folder (downloaded OWASP CRS, custom rules).',
  },
  host_logs_path_required: {
    fr: "host_logs_path manquant (waf.yml ou HOST_LOGS) : chemin HÔTE des journaux nginx à analyser.",
    en: 'host_logs_path is missing (waf.yml or HOST_LOGS): HOST path of the nginx logs to analyse.',
  },
  invalid_config: {
    fr: 'config/waf.yml contient des erreurs.',
    en: 'config/waf.yml contains errors.',
  },
};

class WafRefusal extends Error {
  constructor(code, extra) {
    const m = REFUSALS[code];
    super(`${m.fr} / ${m.en}`);
    this.code = code; this.messageFr = m.fr; this.messageEn = m.en; this.details = extra || null;
  }
}

/** Leve WafRefusal si le conteneur ne peut pas etre demarre avec cette configuration. */
function assertStartable(r) {
  const b = r.blockers;
  if (b.includes('disabled')) throw new WafRefusal('disabled');
  if (b.includes('accept_limits')) throw new WafRefusal('accept_limits_required');
  if (b.includes('host_data_path')) throw new WafRefusal('host_data_path_required');
  if (b.includes('host_rules_path')) throw new WafRefusal('host_rules_path_required');
  if (b.includes('host_logs_path')) throw new WafRefusal('host_logs_path_required');
  if (b.includes('invalid')) throw new WafRefusal('invalid_config', r.errors);
}

function refusalResponse(res, e) {
  return send(res, 400, { error: e.message, code: e.code, messageFr: e.messageFr, messageEn: e.messageEn, ...(e.details ? { details: e.details } : {}) });
}

// ─── Cycle de vie du conteneur ───────────────────────────────────────────────
async function containerStatus(name) {
  const r = await dockerCall('GET', `/containers/${encodeURIComponent(name)}/json`);
  // status 0 : demon injoignable — a distinguer d'un conteneur absent.
  if (r.status === 0)   return { exists: false, running: false, name, dockerUnavailable: true, error: r.error };
  if (r.status === 404) return { exists: false, running: false, name };
  if (r.status !== 200) return { exists: false, running: false, name, error: `HTTP ${r.status}` };
  return {
    exists: true, running: r.body?.State?.Running === true, status: r.body?.State?.Status || 'unknown',
    image: r.body?.Config?.Image || '', started: r.body?.State?.StartedAt || '', name,
  };
}

/**
 * (Re)cree et demarre le conteneur. Les sources de montage sont des chemins HOTE :
 * un chemin interne au dashboard ferait creer un dossier vide par le demon.
 */
async function startWaf(r) {
  assertStartable(r);
  const c = r.config;
  const spec = WC.buildContainerSpec(c, { token: getWafToken(), network: cfg.NGINX_NETWORK || 'nginx-net', tz: process.env.TZ, shipperToken: c.shipperUrl ? getShipperToken() : undefined });
  const name = c.containerName;
  await dockerCall('POST',   `/containers/${encodeURIComponent(name)}/stop`).catch(() => {});
  await dockerCall('DELETE', `/containers/${encodeURIComponent(name)}?force=true`).catch(() => {});
  const create = await dockerCall('POST', `/containers/create?name=${encodeURIComponent(name)}`, spec);
  if (create.status !== 201) throw new Error(`Create failed: ${create.status} ${JSON.stringify(create.body)}`);
  const start = await dockerCall('POST', `/containers/${encodeURIComponent(name)}/start`);
  if (start.status !== 204 && start.status !== 304) throw new Error(`Start failed: ${start.status}`);
  return { ok: true, name, binds: spec.HostConfig.Binds };
}

async function stopWaf(r) {
  await dockerCall('POST', `/containers/${encodeURIComponent(r.config.containerName)}/stop?t=10`);
  return { ok: true };
}

/**
 * Redemarre le conteneur (docker restart : image et montages conserves) puis
 * attend que son API reponde. Un redemarrage dont l'API ne revient jamais est
 * signale comme un echec.
 */
async function restartWaf({ graceSeconds = 10, waitHealthy = true, healthTimeoutMs = 60_000, pollMs = 1_000 } = {}) {
  const r = resolveConfig();
  if (!r.config.enable) return { ok: false, skipped: true, code: 'disabled' };
  const st = await containerStatus(r.config.containerName);
  if (st.dockerUnavailable) throw new Error(`Docker injoignable : ${st.error || 'socket indisponible'}`);
  if (!st.exists) throw new Error(`Conteneur « ${st.name} » absent : demarrez-le depuis la page WAF emule`);
  const grace = Math.max(1, Math.min(120, Math.floor(Number(graceSeconds)) || 10));
  const d = await dockerCall('POST', `/containers/${encodeURIComponent(st.name)}/restart?t=${grace}`);
  if (d.status !== 204 && d.status !== 304) throw new Error(`Redemarrage refuse par Docker : HTTP ${d.status}`);
  if (!waitHealthy) return { ok: true, healthy: null };
  const t0 = Date.now();
  while (Date.now() - t0 < healthTimeoutMs) {
    await new Promise(res => setTimeout(res, pollMs));
    const h = await wafApi('/api/health', 'GET', null, r);
    if (h && h.status === 200) return { ok: true, healthy: true, waitedMs: Date.now() - t0 };
  }
  return { ok: false, healthy: false, waitedMs: Date.now() - t0 };
}

/** `unless-stopped` ne relance qu'un conteneur deja connu de Docker : on le recree s'il manque. */
async function ensureContainerAtBoot() {
  const r = resolveConfig();
  if (r.blockers.length) return { skipped: r.blockers.includes('disabled') ? 'not enabled' : 'not startable', blockers: r.blockers };
  try {
    const st = await containerStatus(r.config.containerName);
    if (st.dockerUnavailable) return { skipped: 'docker unavailable', error: st.error };
    if (st.exists) return { skipped: 'already exists' };
    const pull = await docker.pullAndCheckUpdate(r.config.containerImage);
    if (!pull.ok) return { ok: false, error: `pull ${r.config.containerImage}: ${pull.error}` };
    await startWaf(r);
    console.log('[waf] Container recreated at boot (was missing while enabled)');
    return { ok: true, created: true };
  } catch (e) {
    console.warn('[waf] ensureContainerAtBoot error:', e.message || e);
    return { ok: false, error: e.message || String(e) };
  }
}

// ─── Appel de l'API du WAF ───────────────────────────────────────────────────
/**
 * Appelle l'API du conteneur. Retourne null quand il est injoignable (un WAF
 * arrete est un etat a afficher, pas une panne du dashboard).
 * @returns {Promise<{status:number, data:any, text:string}|null>}
 */
function wafApi(pathAndQuery, method = 'GET', bodyObj = null, resolved = null) {
  const r = resolved || resolveConfig();
  const body = bodyObj === null || bodyObj === undefined ? null : JSON.stringify(bodyObj);
  const headers = { 'X-WAF-Token': getWafToken(), 'User-Agent': cfg.HTTP_USER_AGENT, Accept: 'application/json' };
  if (body !== null) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = Buffer.byteLength(body); }
  return new Promise(resolve => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const req = http.request({
      hostname: r.config.containerName, port: r.config.port, path: pathAndQuery, method, timeout: 10_000, headers,
    }, res => {
      const chunks = []; let size = 0;
      res.on('data', d => {
        size += d.length;
        if (size > MAX_JSON) { req.destroy(); return finish({ status: 502, data: null, text: '' }); }
        chunks.push(d);
      });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let data = null;
        try { data = JSON.parse(text); } catch { /* texte brut (ex. /api/lists/ips) */ }
        finish({ status: res.statusCode, data, text });
      });
      res.on('error', () => finish(null));
    });
    req.on('error', () => finish(null));
    req.on('timeout', () => { req.destroy(); finish(null); });
    req.end(body !== null ? body : undefined);
  });
}

/**
 * IP d'une liste du WAF en texte brut (une par ligne), pour une source de blocklist
 * `type: waf`. Les lignes sont validees par l'appelant (parseIpLines).
 * @returns {Promise<{ok:true,text:string}|{ok:false,error:string}>}
 */
async function wafListIps(list) {
  if (list !== 'block' && list !== 'challenge') return { ok: false, error: 'liste inconnue' };
  const r = resolveConfig();
  if (!r.config.enable) return { ok: false, error: 'WAF emule desactive (waf.yml : enable: true)' };
  const res = await wafApi(`/api/lists/ips?list=${list}`, 'GET', null, r);
  if (!res) return { ok: false, error: 'WAF injoignable' };
  if (res.status !== 200) return { ok: false, error: `WAF : HTTP ${res.status}` };
  if (res.text.length > MAX_TEXT) return { ok: false, error: 'reponse trop volumineuse' };
  return { ok: true, text: res.text };
}

// ─── Vhosts : WAF + vhosts connus de la config nginx ─────────────────────────
function nginxVhostNames() {
  const names = new Set();
  try {
    for (const v of listVhostTargets({ sitesDir: cfg.DIR_SITES, upstreamDirs: [cfg.DIR_CONF, cfg.DIR_SITES] })) {
      if (!v.enabled) continue;
      for (const b of v.serverBlocks || []) {
        for (const n of b.serverNames || []) {
          if (n && n !== '_' && /^[A-Za-z0-9._-]{1,253}$/.test(n) && !n.startsWith('.')) names.add(n.toLowerCase());
        }
      }
    }
  } catch { /* repertoire absent */ }
  return [...names].sort();
}

function effectiveVhost(name, settings) {
  const o = (settings && settings.vhosts && settings.vhosts[name]) || {};
  const selected = settings && settings.vhostMode === 'selected';
  return {
    analyzed: settings ? (selected ? o.analyze === true : o.analyze !== false) : null,
    mode: o.mode || (settings && settings.mode) || 'observe',
    paranoia: o.paranoia || (settings && settings.paranoia) || 1,
  };
}

/** Vhosts vus par le WAF + vhosts nginx sans aucune ligne de log (seen:false). */
async function buildVhostList(r) {
  const [vh, st] = await Promise.all([wafApi('/api/vhosts', 'GET', null, r), wafApi('/api/settings', 'GET', null, r)]);
  if (!vh || vh.status !== 200 || !vh.data) return { reachable: false, vhosts: [], settings: null };
  const settings = st && st.status === 200 ? st.data : null;
  const seen = new Map((vh.data.vhosts || []).map(v => [String(v.name).toLowerCase(), { ...v, seen: true }]));
  for (const name of nginxVhostNames()) {
    if (seen.has(name)) continue;
    seen.set(name, { name, lines: 0, hits24h: 0, lastSeen: null, format: null, ...effectiveVhost(name, settings), seen: false });
  }
  return { reachable: true, vhosts: [...seen.values()].sort((a, b) => a.name.localeCompare(b.name)), settings };
}

// ─── Diagnostics ─────────────────────────────────────────────────────────────
function readNginxFiles() {
  const out = [];
  for (const dir of [cfg.DIR_CONF, cfg.DIR_SITES]) {
    for (const name of safeReadDir(dir)) {
      if (!/\.conf$/.test(name)) continue;
      const content = safeReadFile(path.join(dir, name));
      if (content) out.push({ name, content });
    }
  }
  return out;
}

function blocklistContext() {
  try {
    const bl = parseAndValidate(readFileOr(cfg.BLOCKLIST_CONFIG_FILE), readChallengeOverrides(cfg.CHALLENGE_CONFIG_FILE));
    return {
      blocklistEnabled: bl.settings.enable, challengeEnabled: bl.settings.challenge.enable,
      hasWafSource: bl.valid.some(s => s.type === 'waf' && s.enable),
    };
  } catch { return { blocklistEnabled: false, challengeEnabled: false, hasWafSource: false }; }
}

// ─── Dependances injectees (server.js) ───────────────────────────────────────
let refreshBlocklists = null;
let explainWafIps = null; // (ips, list) -> Map<ip,{state,sources,detail?}> (blocklists.explainWafIps)
function setDeps({ refreshBlocklists: rb, explainWafIps: ex } = {}) {
  if (typeof rb === 'function') refreshBlocklists = rb;
  if (typeof ex === 'function') explainWafIps = ex;
}

/** v12.70.3 : ajoute a chaque IP d une liste son etat d application par les Blocklists. */
function enrichLists(data, query) {
  if (!data || !Array.isArray(data.ips) || !explainWafIps) return data;
  const list = query && query.list;
  if (list !== 'block' && list !== 'challenge') return data;
  try {
    const ex = explainWafIps(data.ips.map(e => e.ip), list);
    return { ...data, ips: data.ips.map(e => ({ ...e, application: ex.get(e.ip) || null })) };
  } catch { return data; }
}

// ─── Routes ──────────────────────────────────────────────────────────────────
const INACTIVE = { reachable: false, enabled: false };

function register(router) {
  const readGuard = (session, res) => { if (!hasPerm(session, PERMS.VIEW_CONFIGS)) { httpLib.forbidden(res); return false; } return true; };
  const writeGuard = (session, res) => { if (!hasPerm(session, PERMS.DEPLOY)) { httpLib.forbidden(res); return false; } return true; };

  /** GET relaye : liste blanche de parametres, WAF injoignable = reponse degradee 200. */
  const proxyGet = (route, apiPath, schemaName, fallback, wrapKey, enrich) => {
    router.get(route, async ({ res, session, url }) => {
      if (!readGuard(session, res)) return;
      const q = schemaName ? WV.pickQuery(url.searchParams, WV.SCHEMAS[schemaName]) : { ok: true, value: {} };
      if (!q.ok) return httpLib.badRequest(res, q.error);
      const r = resolveConfig();
      if (!r.config.enable) return send(res, 200, { ...INACTIVE, ...fallback });
      const qs = WV.toQuery(q.value);
      const up = await wafApi(apiPath + (qs ? '?' + qs : ''), 'GET', null, r);
      if (!up) return send(res, 200, { reachable: false, enabled: true, ...fallback });
      if (up.status >= 400) return send(res, up.status, up.data || { error: `WAF: HTTP ${up.status}` });
      // wrapKey : la reponse du WAF est rangee sous cette cle (evite toute collision avec `reachable`/`enabled`).
      const data = enrich ? enrich(up.data, q.value) : up.data;
      return send(res, 200, { reachable: true, ...(wrapKey ? { [wrapKey]: data } : (data || {})) });
    });
  };

  /** Ecriture relayee : DEPLOY, corps valide, WAF injoignable = 503. */
  const proxyWrite = ({ route, method, apiPath, validate, event, summarize, after, wrapKey }) => {
    router[method.toLowerCase()](route, async ({ req, res, session }) => {
      if (!writeGuard(session, res)) return;
      const body = await parseBody(req, { limitBytes: 512 * 1024 });
      const v = validate ? validate(body) : { ok: true, value: {} };
      if (!v.ok) return httpLib.badRequest(res, v.error);
      const r = resolveConfig();
      if (!r.config.enable) return refusalResponse(res, new WafRefusal('disabled'));
      const up = await wafApi(apiPath, method, v.value, r);
      if (!up) return send(res, 503, { error: 'WAF unreachable', reachable: false });
      if (up.status < 400 && event) logEvent(event, summarize ? summarize(v.value, up.data) : {}, session.username);
      if (up.status < 400 && after) after(session.username);
      if (up.status < 400 && wrapKey) return send(res, up.status, { ok: true, [wrapKey]: up.data });
      return send(res, up.status, up.data || (up.status < 400 ? { ok: true } : { error: `WAF: HTTP ${up.status}` }));
    });
  };

  // ── Statut agrege : config + conteneur + /api/status du WAF ────────────────
  router.get('/api/waf/status', async ({ res, session }) => {
    if (!readGuard(session, res)) return;
    const r = resolveConfig();
    const c = r.config;
    const out = {
      configured: r.exists, enabled: c.enable, acceptLimits: c.acceptLimits,
      errors: r.errors, blockers: r.blockers.filter(b => b !== 'disabled'), configFile: cfg.WAF_CONFIG_FILE,
      config: {
        containerName: c.containerName, image: c.containerImage, port: c.port, crsVersion: c.crsVersion,
        hitRetentionDays: c.hitRetentionDays, logPattern: c.logPattern, wafLogPattern: c.wafLogPattern,
        hostDataPathSet: !!c.hostDataPath, hostRulesPathSet: !!c.hostRulesPath, hostLogsPathSet: !!c.hostLogsPath,
      },
    };
    if (!c.enable) return send(res, 200, { ...out, container: null, reachable: false, waf: null });
    const container = await containerStatus(c.containerName);
    const waf = await wafApi('/api/status', 'GET', null, r);
    return send(res, 200, { ...out, container, reachable: !!waf && waf.status === 200, waf: waf && waf.status === 200 ? waf.data : null });
  });

  // ── Reglages ───────────────────────────────────────────────────────────────
  proxyGet('/api/waf/settings', '/api/settings', null, { settings: null }, 'settings');
  proxyWrite({
    route: '/api/waf/settings', method: 'PUT', apiPath: '/api/settings', validate: WV.validateSettings,
    event: 'waf.settings_update', wrapKey: 'settings',
    summarize: (s) => ({ mode: s.mode, paranoia: s.paranoia, vhostMode: s.vhostMode, exceptions: (s.exceptions || []).length, disabledRules: (s.disabledRules || []).length }),
  });

  // ── Vhosts (WAF + config nginx) ───────────────────────────────────────────
  router.get('/api/waf/vhosts', async ({ res, session }) => {
    if (!readGuard(session, res)) return;
    const r = resolveConfig();
    if (!r.config.enable) return send(res, 200, { ...INACTIVE, vhosts: [] });
    const l = await buildVhostList(r);
    if (!l.reachable) return send(res, 200, { reachable: false, enabled: true, vhosts: [] });
    return send(res, 200, { reachable: true, vhosts: l.vhosts });
  });

  // ── Regles, hits, stats, listes, alertes ──────────────────────────────────
  proxyGet('/api/waf/rules', '/api/rules', 'rules', { total: 0, rules: [] });
  proxyGet('/api/waf/rules/categories', '/api/rules/categories', null, { categories: [] });
  proxyGet('/api/waf/hits', '/api/hits', 'hits', { total: 0, hits: [] });
  proxyGet('/api/waf/hits/stats', '/api/hits/stats', 'hitsStats', { requests: 0, topRules: [], topIps: [], timeline: [] });
  proxyGet('/api/waf/lists', '/api/lists', 'lists', { ips: [] }, null, enrichLists);
  proxyGet('/api/waf/alerts', '/api/alerts', 'alerts', { alerts: [] });
  proxyGet('/api/waf/custom-rules', '/api/custom-rules', null, { text: '' });

  // ── Actions ───────────────────────────────────────────────────────────────
  proxyWrite({ route: '/api/waf/simulate', method: 'POST', apiPath: '/api/simulate', validate: WV.validateSimulate });
  proxyWrite({
    route: '/api/waf/lists/unlist', method: 'POST', apiPath: '/api/lists/unlist', validate: WV.validateUnlist,
    event: 'waf.unlist', summarize: (b) => ({ ip: b.ip, list: b.list }),
    after: afterListChange, // la source de blocklist se rafraichit tout de suite, sans attendre le cycle
  });
  proxyWrite({
    route: '/api/waf/alerts/ack', method: 'POST', apiPath: '/api/alerts/ack', validate: WV.validateAck,
    event: 'waf.alerts_ack', summarize: (b) => ({ count: b.ids.length }),
  });
  proxyWrite({
    route: '/api/waf/rules/update', method: 'POST', apiPath: '/api/rules/update', validate: WV.validateRulesUpdate,
    event: 'waf.rules_update', summarize: (b) => ({ version: b.version || 'default' }),
  });
  proxyWrite({ route: '/api/waf/engine/reload', method: 'POST', apiPath: '/api/engine/reload', validate: null, event: 'waf.engine_reload' });
  proxyWrite({
    route: '/api/waf/custom-rules', method: 'PUT', apiPath: '/api/custom-rules', validate: WV.validateCustomRules,
    event: 'waf.custom_rules_update', summarize: (b) => ({ chars: b.text.length }), // le contenu n'est jamais journalise
  });

  // ── Diagnostics ───────────────────────────────────────────────────────────
  router.get('/api/waf/diagnostics', async ({ res, session }) => {
    if (!readGuard(session, res)) return;
    const r = resolveConfig();
    if (!r.config.enable) return send(res, 200, { ...INACTIVE, advice: [] });
    const [st, l] = await Promise.all([wafApi('/api/status', 'GET', null, r), buildVhostList(r)]);
    const status = st && st.status === 200 ? st.data : null;
    const advice = WD.buildDiagnostics({
      status, vhosts: l.vhosts, settings: l.settings,
      nginx: WD.scanNginxLogging(readNginxFiles()), lists: blocklistContext(),
    });
    return send(res, 200, { reachable: !!status, enabled: true, advice });
  });

  // ── Conteneur ─────────────────────────────────────────────────────────────
  router.post('/api/waf/container/start', async ({ res, session }) => {
    if (!writeGuard(session, res)) return;
    const r = resolveConfig();
    try {
      assertStartable(r);
      const pull = await docker.pullAndCheckUpdate(r.config.containerImage);
      if (!pull.ok) return httpLib.serverError(res, new Error(`Pull de l'image ${r.config.containerImage} echoue : ${pull.error}`));
      const result = await startWaf(r);
      logEvent('waf.start', `Conteneur ${r.config.containerName} (re)demarre`, session.username);
      return send(res, 200, { ok: true, name: result.name });
    } catch (e) {
      if (e instanceof WafRefusal) return refusalResponse(res, e);
      return httpLib.serverError(res, e);
    }
  });

  router.post('/api/waf/container/stop', async ({ res, session }) => {
    if (!writeGuard(session, res)) return;
    const r = resolveConfig();
    if (!r.config.enable) return refusalResponse(res, new WafRefusal('disabled'));
    try {
      await stopWaf(r);
      logEvent('waf.stop', `Conteneur ${r.config.containerName} arrete`, session.username);
      return send(res, 200, { ok: true });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/waf/container/restart', async ({ res, session }) => {
    if (!writeGuard(session, res)) return;
    const r = resolveConfig();
    if (!r.config.enable) return refusalResponse(res, new WafRefusal('disabled'));
    try {
      const result = await restartWaf();
      logEvent('waf.restart', `Conteneur ${r.config.containerName} redemarre`, session.username);
      return send(res, 200, result);
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/waf/image/update', async ({ res, session }) => {
    if (!writeGuard(session, res)) return;
    const r = resolveConfig();
    if (!r.config.enable) return refusalResponse(res, new WafRefusal('disabled'));
    const out = await lifecycle.legacyImageUpdate('waf');
    logEvent('waf.image_update', `Image ${r.config.containerImage} ${out.updated ? 'updated' : 'already up to date'}${out.recreated ? ', container recreated' : ''}`, session.username);
    return send(res, 200, out);
  });
}

/** Rafraichit la blocklist apres une action qui change les listes (deslistage). */
function afterListChange(actor) {
  if (!refreshBlocklists) return;
  Promise.resolve(refreshBlocklists({ analyzerOnly: true, manual: true, actor })).catch(() => {});
}

/** Le WAF émulé est-il activé dans config/waf.yml ? (utilisé par Intelligence pour savoir s'il faut lire ses alertes) */
function isEnabled() {
  try { return !!resolveConfig().config.enable; } catch { return false; }
}

// ─── Cycle de vie uniforme (#104/#105) ───────────────────────────────────────
lifecycle.register({
  id: 'waf', label: 'WAF émulé', page: 'wafemu',
  enabled: () => !!resolveConfig().config.enable,
  containerName: () => resolveConfig().config.containerName,
  image: () => resolveConfig().config.containerImage,
  create: () => startWaf(resolveConfig()),
  mapError: (e) => (e instanceof WafRefusal ? { status: 400, body: { error: e.message, code: e.code, messageFr: e.messageFr, messageEn: e.messageEn, ...(e.details ? { details: e.details } : {}) } } : null),
});

module.exports = {
  isEnabled, register, setDeps, resolveConfig, startWaf, stopWaf, restartWaf, containerStatus, ensureContainerAtBoot,
  wafApi, wafListIps, buildVhostList, nginxVhostNames, assertStartable, WafRefusal, afterListChange,
};
