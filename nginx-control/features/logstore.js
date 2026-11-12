'use strict';
/**
 * Journal centralise (log store) — v12.80.0.
 *
 *  1. LECTURE : proxy en lecture seule de l'API du log store (recherche, fiche IP, statistiques) avec le
 *     jeton `read`. L'hote vient de config/logstore.yml, jamais d'une requete ; chaque parametre est valide
 *     (lib/logstore-query.js) ; aucune redirection n'est suivie ; reponse bornee ; le jeton ne quitte pas
 *     le serveur (ni navigateur, ni journaux, ni reponses).
 *  2. ENVOI : cycle de vie du conteneur shipper (seul point de sortie vers le log store), sur le modele du
 *     WAF et du challenge : demarrer / arreter / mettre a jour l'image / recreer au demarrage.
 *
 * Lectures : PERMS.VIEW_LOGS ; actions qui modifient (conteneur) : PERMS.DEPLOY.
 * La logique pure est dans lib/logstore-settings.js, lib/logstore-query.js et lib/shipper-container.js.
 */
const fs    = require('fs');
const http  = require('http');
const https = require('https');

const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const lifecycle = require('../lib/container-lifecycle');
const events  = require('../lib/events');
const LS      = require('../lib/logstore-settings');
const LSC     = require('../lib/logstore-config');
const LQ      = require('../lib/logstore-query');
const SC      = require('../lib/shipper-container');
const { getShipperToken } = require('../lib/shipper-token');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { dockerCall } = docker;
const { logEvent } = events;

const MAX_RESPONSE = 8 * 1024 * 1024;

function readFileOr(f, def = '') { try { return fs.readFileSync(f, 'utf8'); } catch { return def; } }

/** Configuration effective, relue a chaque appel (logstore.yml est editable a chaud). */
function resolveConfig() {
  return LS.normalizeLogstoreConfig(readFileOr(cfg.LOGSTORE_CONFIG_FILE), {
    readToken: cfg.LOGSTORE_READ_TOKEN, sinkToken: cfg.LOGSINK_TOKEN,
    defaultLogsPath: cfg.HOST_LOGS, defaultImage: cfg.SHIPPER_DEFAULT_IMAGE, instanceId: cfg.INSTANCE_ID,
  });
}

/**
 * GET sur le log store. HTTPS ou HTTP selon l'URL validee ; AUCUNE redirection (le jeton ne doit jamais
 * partir ailleurs) ; reponse bornee. Ne renvoie jamais le jeton ni l'URL complete dans une erreur.
 * @returns {Promise<{status:number, body?:any, error?:string}>}
 */
function storeGet(config, pathAndQuery) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(config.url + pathAndQuery); } catch { return resolve({ status: 0, error: 'bad_url' }); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({
      protocol: u.protocol, hostname: u.hostname, port: u.port || undefined, path: u.pathname + u.search, method: 'GET',
      timeout: config.timeoutSeconds * 1000,
      headers: { Authorization: `Bearer ${config.token}`, Accept: 'application/json', 'User-Agent': cfg.HTTP_USER_AGENT },
    }, (up) => {
      const chunks = []; let size = 0; let over = false;
      up.on('data', (d) => { size += d.length; if (size > MAX_RESPONSE) { over = true; up.destroy(); } else chunks.push(d); });
      up.on('close', () => {
        if (over) return resolve({ status: 0, error: 'too_large' });
        if (up.statusCode >= 300 && up.statusCode < 400) return resolve({ status: up.statusCode, error: 'redirect_refused' });
        let body = null;
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* corps non JSON */ }
        resolve({ status: up.statusCode, body });
      });
      up.on('error', () => resolve({ status: 0, error: 'unreachable' }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, error: 'timeout' }); });
    req.on('error', () => resolve({ status: 0, error: 'unreachable' }));
    req.end();
  });
}

/** Traduit une reponse du log store en reponse du dashboard, sans transmettre de detail sensible. */
function relay(res, r) {
  if (r.error) return send(res, 502, { error: r.error });
  if (r.status === 200 && r.body) return send(res, 200, r.body);
  if (r.status === 401 || r.status === 403) return send(res, 502, { error: 'token_rejected' });
  if (r.status === 429) return send(res, 429, { error: 'rate_limited' });
  if (r.status === 400 && r.body && r.body.error) return send(res, 400, { error: 'bad_request', detail: String(r.body.detail || '').slice(0, 200) });
  return send(res, 502, { error: 'store_error', status: r.status });
}

// ─── Conteneur shipper ───────────────────────────────────────────────────────

async function containerStatus(name) {
  const res = await dockerCall('GET', `/containers/${encodeURIComponent(name)}/json`);
  if (res.status === 0)   return { exists: false, running: false, dockerUnavailable: true, error: res.error };
  if (res.status === 404) return { exists: false, running: false };
  if (res.status !== 200) return { exists: false, running: false, error: `HTTP ${res.status}` };
  const st = res.body?.State || {};
  return {
    exists: true, running: st.Running === true, status: st.Status, started: st.StartedAt,
    health: st.Health?.Status || null, image: res.body?.Config?.Image,
  };
}

/** /status du shipper (reseau Docker, jeton local). Aucun secret dans la reponse du shipper. */
function shipperStatus(name) {
  return new Promise((resolve) => {
    const req = http.request({
      host: name, port: LS.SHIPPER_PORT, path: '/status', method: 'GET', timeout: 3000,
      headers: { Authorization: `Bearer ${getShipperToken()}`, 'User-Agent': cfg.HTTP_USER_AGENT },
    }, (up) => {
      let buf = '';
      up.on('data', (d) => { buf += d; if (buf.length > 1_000_000) up.destroy(); });
      up.on('close', () => {
        if (up.statusCode !== 200) return resolve({ unavailable: up.statusCode === 401 ? 'token' : 'unreachable' });
        try { resolve({ data: JSON.parse(buf) }); } catch { resolve({ unavailable: 'unreachable' }); }
      });
      up.on('error', () => resolve({ unavailable: 'unreachable' }));
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve({ unavailable: 'unreachable' }));
    req.end();
  });
}

const REFUSALS = {
  disabled: { fr: "L'envoi vers le log store n'est pas activé (config/logstore.yml : shipper_enable: true).", en: 'Shipping to the log store is not enabled (config/logstore.yml: shipper_enable: true).' },
  sink_url: { fr: 'shipper_sink_url (ou url) manquant dans logstore.yml : adresse du log store.', en: 'shipper_sink_url (or url) is missing in logstore.yml: log store address.' },
  sink_token: { fr: "Jeton d'envoi manquant : variable LOGSINK_TOKEN ou shipper_sink_token (jeton `write` de cette instance).", en: 'Write token missing: LOGSINK_TOKEN variable or shipper_sink_token (this instance\'s `write` token).' },
  host_logs_path: { fr: 'shipper_host_logs_path manquant (ou HOST_LOGS) : chemin HÔTE des journaux nginx.', en: 'shipper_host_logs_path is missing (or HOST_LOGS): HOST path of the nginx logs.' },
  host_data_path: { fr: "shipper_host_data_path manquant : chemin HÔTE du dossier d'état (positions de lecture, tampon disque) ; sans lui tout est perdu à chaque recréation.", en: 'shipper_host_data_path is missing: HOST path of the state folder (read offsets, disk buffer); without it everything is lost whenever the container is recreated.' },
  image: { fr: 'Aucune image : shipper_image ou SHIPPER_DEFAULT_IMAGE.', en: 'No image: shipper_image or SHIPPER_DEFAULT_IMAGE.' },
  instance: { fr: 'Identifiant d\'instance manquant : instance dans logstore.yml.', en: 'Instance identifier missing: instance in logstore.yml.' },
  invalid: { fr: 'logstore.yml contient des valeurs invalides (voir la liste des erreurs).', en: 'logstore.yml contains invalid values (see the error list).' },
};

class Refusal extends Error {
  constructor(code) { super(REFUSALS[code]?.fr || code); this.code = code; this.refusal = REFUSALS[code] || { fr: code, en: code }; }
}

function assertStartable(r) {
  if (r.shipperBlockers.length) throw new Refusal(r.shipperBlockers[0]);
}

/** #110 : adresse (réseau Docker) et jeton de l'analyseur pour l'attribution du nom de liste ; vide si l'analyseur n'est pas configuré. */
function analyzerLookupOpts() {
  try {
    const a = require('./analyzer');
    const c = a.getAnalyzerCfg();
    if (!c || c.enabled === false) return {};
    const name = (c.container_name) || 'ngx-analyzer';
    return { analyzerUrl: `http://${name}:${c.port || 9100}`, analyzerToken: require('../lib/analyzer-token').getAnalyzerToken() };
  } catch { return {}; }
}

/** #114 : chemin hote des bases GeoIP (celui de l'analyseur) pour l'enrichissement pays du shipper. */
function shipperGeoipOpts() {
  try {
    const p = require('./analyzer').getAnalyzerCfg()?.host_geoip_path;
    return typeof p === 'string' && p.startsWith('/') ? { geoipPath: p } : {};
  } catch { return {}; }
}

async function startShipper(r) {
  assertStartable(r);
  const c = r.config;
  const spec = SC.buildShipperSpec(c, { localToken: getShipperToken(), network: cfg.NGINX_NETWORK, tz: process.env.TZ, ...analyzerLookupOpts(), ...shipperGeoipOpts() });
  await dockerCall('POST', `/containers/${encodeURIComponent(c.shipperName)}/stop`).catch(() => {});
  await dockerCall('DELETE', `/containers/${encodeURIComponent(c.shipperName)}?force=true`).catch(() => {});
  const create = await dockerCall('POST', `/containers/create?name=${encodeURIComponent(c.shipperName)}`, spec);
  if (create.status !== 201) throw new Error(`Create failed: ${create.status}`);
  const start = await dockerCall('POST', `/containers/${encodeURIComponent(c.shipperName)}/start`);
  if (start.status !== 204 && start.status !== 304) throw new Error(`Start failed: ${start.status}`);
  return true;
}

async function stopShipper(name) {
  await dockerCall('POST', `/containers/${encodeURIComponent(name)}/stop`);
  await dockerCall('DELETE', `/containers/${encodeURIComponent(name)}?force=true`);
}

/** `unless-stopped` ne relance qu'un conteneur deja connu de Docker : on le recree s'il manque. */
async function ensureContainerAtBoot() {
  const r = resolveConfig();
  if (!r.config.shipperEnable || r.shipperBlockers.length) return { skipped: 'not enabled or incomplete' };
  try {
    const st = await containerStatus(r.config.shipperName);
    if (st.dockerUnavailable) return { skipped: 'docker unavailable', error: st.error };
    if (st.exists) return { skipped: 'already exists' };
    await docker.pullAndCheckUpdate(r.config.shipperImage);
    await startShipper(r);
    console.log(`[logstore] Conteneur ${r.config.shipperName} recree au demarrage (absent alors qu'active)`);
    return { ok: true, created: true };
  } catch (e) {
    console.warn('[logstore] ensureContainerAtBoot :', e.message || e);
    return { ok: false, error: e.message || String(e) };
  }
}

// ─── Routes ──────────────────────────────────────────────────────────────────

function register(router) {
  const readGuard = (session, res) => { if (hasPerm(session, PERMS.VIEW_LOGS)) return true; httpLib.forbidden(res); return false; };
  const deployGuard = (session, res) => { if (hasPerm(session, PERMS.DEPLOY)) return true; httpLib.forbidden(res); return false; };

  // #63 : formulaire de configuration (administrateur). Aucun jeton n'est renvoye (tokenSet / sinkTokenSet seulement).
  const configEnv = () => ({
    readToken: cfg.LOGSTORE_READ_TOKEN, sinkToken: cfg.LOGSINK_TOKEN,
    defaultLogsPath: cfg.HOST_LOGS, defaultImage: cfg.SHIPPER_DEFAULT_IMAGE, instanceId: cfg.INSTANCE_ID,
  });
  router.get('/api/logstore/config', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return httpLib.forbidden(res);
    const r = resolveConfig();
    return send(res, 200, LSC.formView({ config: r.config, errors: r.errors, text: readFileOr(cfg.LOGSTORE_CONFIG_FILE), env: configEnv() }));
  });
  router.put('/api/logstore/config', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.MANAGE_USERS)) return httpLib.forbidden(res);
    const body = await httpLib.parseBody(req, { limitBytes: 64 * 1024 });
    const r = LSC.buildConfig(body, readFileOr(cfg.LOGSTORE_CONFIG_FILE), configEnv());
    if (!r.ok) return send(res, 400, { error: 'invalid_config', errors: r.errors });
    const tmp = cfg.LOGSTORE_CONFIG_FILE + '.tmp';
    fs.writeFileSync(tmp, r.yaml, { mode: 0o600 });
    fs.renameSync(tmp, cfg.LOGSTORE_CONFIG_FILE);
    logEvent('logstore.config_saved', 'Configuration du journal centralise enregistree (formulaire)', session.username);
    return send(res, 200, { ok: true });
  });

  // Etat agrege : configuration (sans secret), disponibilite du log store, conteneur et /status du shipper.
  router.get('/api/logstore/status', async ({ res, session }) => {
    if (!readGuard(session, res)) return;
    const r = resolveConfig();
    const c = r.config;
    const out = {
      configFile: cfg.LOGSTORE_CONFIG_FILE, errors: r.errors,
      read: { enabled: c.enable, blockers: r.readBlockers, url: c.url, tokenSet: !!c.token },
      shipper: {
        enabled: c.shipperEnable, blockers: r.shipperBlockers, name: c.shipperName, image: c.shipperImage,
        sinkUrl: c.sinkUrl, sinkTokenSet: !!c.sinkToken, instance: c.instance, localUrl: LS.localShipperUrl(c),
        hostLogsPathSet: !!c.shipperHostLogsPath, hostDataPathSet: !!c.shipperHostDataPath,
      },
    };
    const jobs = [];
    if (!r.readBlockers.length) {
      jobs.push(storeGet(c, '/v1/health').then((h) => {
        out.store = h.status === 200 && h.body ? { reachable: true, ...h.body }
          : { reachable: false, error: h.error || (h.status === 401 || h.status === 403 ? 'token_rejected' : `HTTP ${h.status}`) };
      }));
    }
    if (c.shipperEnable) {
      jobs.push(containerStatus(c.shipperName).then(async (st) => {
        out.shipper.container = st;
        if (st.running) {
          const s = await shipperStatus(c.shipperName);
          out.shipper.status = s.data || null;
          if (s.unavailable) out.shipper.statusError = s.unavailable;
        }
      }));
    }
    await Promise.all(jobs);
    return send(res, 200, out);
  });

  // Requetes de lecture : chemin fixe, parametres a liste blanche.
  const readRoute = (route, kind) => router.get(route, async ({ res, session, url }) => {
    if (!readGuard(session, res)) return;
    const r = resolveConfig();
    if (r.readBlockers.length) return send(res, 409, { error: 'not_configured', blockers: r.readBlockers });
    const q = LQ.buildRequest(kind, url.searchParams, undefined, { instance: r.config.instance });
    if (q.error) return httpLib.badRequest(res, q.error);
    const out = await storeGet(r.config, q.path);
    // #89 : le dashboard ne montre que SON instance ; la vue multi-instances est celle du Hub.
    if (kind === 'instances' && out.status === 200 && out.body && Array.isArray(out.body.instances) && r.config.instance) {
      out.body = { ...out.body, instances: out.body.instances.filter((i) => i && i.id === r.config.instance) };
    }
    return relay(res, out);
  });
  // #65 : visits et top au-dela de 31 jours : tranches interrogees a la suite (le log store refuse > 31 j), puis fusion.
  const statsRoute = (route, kind) => router.get(route, async ({ res, session, url }) => {
    if (!readGuard(session, res)) return;
    const r = resolveConfig();
    if (r.readBlockers.length) return send(res, 409, { error: 'not_configured', blockers: r.readBlockers });
    const plan = LQ.planWindows(url.searchParams);
    if (plan && plan.error) return httpLib.badRequest(res, plan.error);
    if (!plan) {
      const q = LQ.buildRequest(kind, url.searchParams, undefined, { instance: r.config.instance });
      if (q.error) return httpLib.badRequest(res, q.error);
      return relay(res, await storeGet(r.config, q.path));
    }
    const bodies = [];
    for (const chunk of plan.chunks) { // sequentiel : une seule requete a la fois vers le log store
      const q = LQ.buildRequest(kind, LQ.chunkParams(url.searchParams, chunk), undefined, { instance: r.config.instance });
      if (q.error) return httpLib.badRequest(res, q.error);
      const out = await storeGet(r.config, q.path);
      if (out.status !== 200 || !out.body) return relay(res, out);
      bodies.push(out.body);
    }
    const lim = Number(url.searchParams.get('limit')) || 20;
    return send(res, 200, kind === 'visits' ? LQ.mergeVisits(bodies) : LQ.mergeTop(bodies, url.searchParams.get('dimension'), Math.min(100, lim)));
  });
  readRoute('/api/logstore/events', 'events');
  statsRoute('/api/logstore/visits', 'visits');
  statsRoute('/api/logstore/top', 'top');
  readRoute('/api/logstore/security', 'security');
  readRoute('/api/logstore/instances', 'instances');

  router.get('/api/logstore/ip', async ({ res, session, url }) => {
    if (!readGuard(session, res)) return;
    const r = resolveConfig();
    if (r.readBlockers.length) return send(res, 409, { error: 'not_configured', blockers: r.readBlockers });
    const q = LQ.buildRequest('ip', url.searchParams, url.searchParams.get('ip'), { instance: r.config.instance });
    if (q.error) return httpLib.badRequest(res, q.error);
    return relay(res, await storeGet(r.config, q.path));
  });

  // ── Conteneur shipper ──
  router.post('/api/logstore/shipper/start', async ({ res, session }) => {
    if (!deployGuard(session, res)) return;
    const r = resolveConfig();
    try {
      assertStartable(r);
      const pull = await docker.pullAndCheckUpdate(r.config.shipperImage);
      if (!pull.ok) return httpLib.serverError(res, new Error(`Pull de l'image ${r.config.shipperImage} echoue : ${pull.error}`));
      await startShipper(r);
      logEvent('logstore.shipper.start', `conteneur shipper ${r.config.shipperName} (re)demarre`, session.username);
      return send(res, 200, { ok: true, name: r.config.shipperName });
    } catch (e) {
      if (e instanceof Refusal) return send(res, 409, { error: 'refused', code: e.code, ...e.refusal });
      return httpLib.serverError(res, e);
    }
  });

  router.post('/api/logstore/shipper/stop', async ({ res, session }) => {
    if (!deployGuard(session, res)) return;
    const r = resolveConfig();
    try {
      await stopShipper(r.config.shipperName);
      logEvent('logstore.shipper.stop', `conteneur shipper ${r.config.shipperName} arrete`, session.username);
      return send(res, 200, { ok: true });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/logstore/shipper/image/update', async ({ res, session }) => {
    if (!deployGuard(session, res)) return;
    const r = resolveConfig();
    if (!r.config.shipperEnable) return send(res, 409, { error: 'refused', code: 'disabled', ...REFUSALS.disabled });
    const out = await lifecycle.legacyImageUpdate('shipper');
    logEvent('logstore.shipper.image_update', `Image ${r.config.shipperImage} ${out.updated ? 'mise a jour' : 'deja a jour'}${out.recreated ? ', conteneur recree' : ''}`, session.username);
    return send(res, 200, out);
  });
}

// ─── Cycle de vie uniforme (#104/#105) ───────────────────────────────────────
lifecycle.register({
  id: 'shipper', label: 'Shipper de journaux', page: 'logstore',
  enabled: () => !!resolveConfig().config.shipperEnable,
  containerName: () => resolveConfig().config.shipperName,
  image: () => resolveConfig().config.shipperImage,
  create: async () => { const r = resolveConfig(); assertStartable(r); return startShipper(r); },
  mapError: (e) => (e instanceof Refusal ? { status: 409, body: { error: 'refused', code: e.code, ...e.refusal } } : null),
});

module.exports = {
  register, resolveConfig, storeGet, relay, containerStatus, shipperStatus, startShipper, stopShipper,
  ensureContainerAtBoot, assertStartable, Refusal, REFUSALS,
};
