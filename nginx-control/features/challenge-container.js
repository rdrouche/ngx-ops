'use strict';
/**
 * Conteneur du challenge navigateur, géré depuis le dashboard (v12.63.0) — même
 * modèle que error-pages / geoipupdate / analyzer : config/challenge.yml
 * (enable, image, réglages), démarrage = pull + (re)création, arrêt,
 * mise à jour de l'image, recréation au démarrage de l'hôte.
 *
 * Le moteur (builtin | anubis), l'upstream et donc le NOM du conteneur viennent
 * de config/blocklists.yml (challenge_engine / challenge_upstream) : le nom du
 * conteneur est l'hôte que nginx résout dans le DNS Docker, il ne doit jamais
 * diverger de celui du snippet généré. La logique pure est dans
 * lib/challenge-container.js.
 *
 * Secret : celui de config/challenge.yml s'il est fourni, sinon généré une fois
 * et conservé (base d'événements, volume /config) pour que les cookies déjà
 * délivrés survivent à une recréation du conteneur.
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');

const appCfg  = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const lifecycle = require('../lib/container-lifecycle');
const events  = require('../lib/events');
const CC      = require('../lib/challenge-container');
const { parseAndValidate } = require('../lib/blocklist-yaml');
const { readChallengeOverrides } = require('../lib/challenge-settings');
const blocklists = require('./blocklists');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;
const { dockerCall } = docker;
const { logEvent } = events;

const SECRET_STATE_KEY = 'challenge_container_secrets';

function readFileOr(f, def = '') { try { return fs.readFileSync(f, 'utf8'); } catch { return def; } }

/** Appel HTTP interne vers le conteneur builtin (reseau Docker ; ces routes refusent tout X-Real-IP). */
function internalCall(path, method = 'GET', { json = true } = {}) {
  const r = resolve();
  if (r.engine !== 'builtin') return Promise.resolve({ unavailable: 'engine' });
  const m = /^([a-z0-9][a-z0-9.-]*)(?::(\d{1,5}))?$/i.exec(String(r.upstream || ''));
  if (!m) return Promise.resolve({ unavailable: 'upstream' });
  return new Promise((resolveP) => {
    const req = http.request({ host: m[1], port: m[2] || 80, path, method, timeout: 3000,
      headers: { 'User-Agent': appCfg.HTTP_USER_AGENT } }, (up) => {
      let buf = '';
      up.on('data', d => { buf += d; if (buf.length > 2_000_000) up.destroy(); });
      up.on('end', () => {
        if (up.statusCode !== 200) return resolveP({ unavailable: 'unreachable' });
        if (!json) return resolveP({ text: buf });
        try { resolveP({ data: JSON.parse(buf) }); } catch { resolveP({ unavailable: 'unreachable' }); }
      });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolveP({ unavailable: 'unreachable' }));
    req.end();
  });
}
const internalJson = (path, method) => internalCall(path, method);

/** Historique des blocages automatiques depuis le numero de sequence `since` (alertes Intelligence). */
async function challengeBanEvents(since, limit = 100) {
  const r = await internalCall(`/bans?since=${Math.max(0, parseInt(since, 10) || 0)}&limit=${Math.min(200, Math.max(1, limit | 0))}`);
  if (r.unavailable) return { ok: false, error: r.unavailable };
  return { ok: true, events: (r.data && r.data.events) || [], latest: r.data && r.data.latest != null ? r.data.latest : null };
}

/** IP bloquees automatiquement (source de blocklist `type: challenge`). */
async function challengeListIps() {
  const r = await internalCall('/blocklist', 'GET', { json: false });
  if (r.unavailable) return { ok: false, error: r.unavailable === 'engine' ? 'moteur builtin requis' : 'conteneur challenge injoignable' };
  return { ok: true, text: r.text };
}

/** Toute la configuration utile, relue à chaque appel (les fichiers sont éditables à chaud). */
function resolve() {
  const parsed = CC.parseChallengeConfig(readFileOr(appCfg.CHALLENGE_CONFIG_FILE));
  // ENV (NC_*) > config/challenge.yml > défaut
  const withEnv = CC.applyEnv(parsed.config, {
    secret: appCfg.NC_SECRET, difficultyBits: appCfg.NC_DIFFICULTY_BITS, cookieHours: appCfg.NC_COOKIE_HOURS,
    goodbots: appCfg.NC_GOODBOTS, goodbotsExtra: appCfg.NC_GOODBOTS_EXTRA, language: appCfg.NC_LANG,
  });
  const config = withEnv.config;
  const errors = [...parsed.errors, ...withEnv.errors];
  const bl = parseAndValidate(readFileOr(appCfg.BLOCKLIST_CONFIG_FILE), readChallengeOverrides(appCfg.CHALLENGE_CONFIG_FILE));
  const ch = bl.settings.challenge;
  const engine = ch.engine;
  const upstream = ch.upstreamEffective;
  return {
    config, errors, engine, upstream, challengeEnabled: ch.enable,
    name: CC.containerNameFor(upstream, engine),
    image: CC.imageFor(config, engine, { challengeImage: appCfg.CHALLENGE_DEFAULT_IMAGE, anubisImage: appCfg.ANUBIS_DEFAULT_IMAGE }),
  };
}

/**
 * Secret effectif : ENV NC_SECRET > yml > généré et conservé (comme SESSION_SECRET,
 * dans .generated-secrets.json). Anubis exige 64 caractères hexadécimaux.
 */
function secretFor(r) {
  const given = r.config.secret;
  if (given) {
    if (r.engine === 'anubis' && !/^[0-9a-fA-F]{64}$/.test(given)) {
      throw new Error('secret : Anubis attend une clé de 64 caractères hexadécimaux (openssl rand -hex 32)');
    }
    return given;
  }
  const key = `challengeSecret_${r.engine}`;
  const stored = appCfg.readGeneratedSecrets()[key];
  if (stored) return stored;
  const value = crypto.randomBytes(32).toString('hex');
  appCfg.persistGeneratedSecret(key, value);
  console.log(`[challenge] Secret ${r.engine} généré et conservé dans ${appCfg.GENERATED_SECRETS_FILE}`);
  return value;
}

async function containerStatus(name) {
  const res = await dockerCall('GET', `/containers/${encodeURIComponent(name)}/json`);
  if (res.status === 0)   return { exists: false, running: false, dockerUnavailable: true, error: res.error };
  if (res.status === 404) return { exists: false, running: false };
  if (res.status !== 200) return { exists: false, running: false, error: `HTTP ${res.status}` };
  return {
    exists: true, running: res.body?.State?.Running === true, status: res.body?.State?.Status,
    started: res.body?.State?.StartedAt, image: res.body?.Config?.Image,
    engine: res.body?.Config?.Labels?.['nginx-dashboard.engine'] || null,
  };
}

async function startContainer(r) {
  const spec = CC.buildContainerSpec({
    engine: r.engine, image: r.image, network: appCfg.NGINX_NETWORK, upstream: r.upstream,
    config: r.config, secret: secretFor(r),
    shipperToken: r.config.shipperUrl ? require('../lib/shipper-token').getShipperToken() : undefined,
  });
  await dockerCall('POST', `/containers/${encodeURIComponent(r.name)}/stop`).catch(() => {});
  await dockerCall('DELETE', `/containers/${encodeURIComponent(r.name)}?force=true`).catch(() => {});
  const create = await dockerCall('POST', `/containers/create?name=${encodeURIComponent(r.name)}`, spec);
  if (create.status !== 201) throw new Error(`Create failed: ${create.status} ${JSON.stringify(create.body)}`);
  const start = await dockerCall('POST', `/containers/${encodeURIComponent(r.name)}/start`);
  if (start.status !== 204 && start.status !== 304) throw new Error(`Start failed: ${start.status}`);
  // v12.74.1 : le conteneur tourne -> fin de la pause, snippets nginx regeneres (actifs).
  if (blocklists.isChallengePaused()) {
    blocklists.setChallengePaused(false);
    blocklists.applyChallengeFiles({ actor: 'challenge-start' }).catch(e => console.warn('[challenge] apply apres demarrage:', e.message));
  }
  return true;
}

async function stopContainer(name) {
  await dockerCall('POST', `/containers/${encodeURIComponent(name)}/stop`);
  await dockerCall('DELETE', `/containers/${encodeURIComponent(name)}?force=true`);
}

/** `unless-stopped` ne relance qu'un conteneur déjà connu de Docker : on le recrée s'il manque. */
async function ensureContainerAtBoot() {
  const r = resolve();
  if (!r.config.enable) return { skipped: 'not enabled' };
  try {
    const st = await containerStatus(r.name);
    if (st.dockerUnavailable) return { skipped: 'docker unavailable', error: st.error };
    if (st.exists) return { skipped: 'already exists' };
    await docker.pullAndCheckUpdate(r.image);
    await startContainer(r);
    console.log(`[challenge] Container ${r.name} recreated at boot (was missing while enabled)`);
    return { ok: true, created: true };
  } catch (e) {
    console.warn('[challenge] ensureContainerAtBoot error:', e.message || e);
    return { ok: false, error: e.message || String(e) };
  }
}

// ─── Routes ──────────────────────────────────────────────────────────────────
function register(router) {
  router.get('/api/challenge/status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const r = resolve();
    const out = {
      enabled: r.config.enable, challengeEnabled: r.challengeEnabled, engine: r.engine,
      name: r.name, image: r.image, upstream: r.upstream, errors: r.errors,
      configFile: appCfg.CHALLENGE_CONFIG_FILE, paused: blocklists.isChallengePaused(),
    };
    if (r.config.enable) out.container = await containerStatus(r.name);
    // v12.65.0 : vue complete de la page « Challenge HTTP »
    const ch = blocklists.computeChallengeFiles();
    const fileState = blocklists.getChallengeFilesState();
    out.settings = {
      engine: ch.challenge.engine, upstream: ch.challenge.upstreamEffective, resolver: ch.challenge.resolver,
      exemptPathRegex: ch.challenge.exemptPathRegex, exemptUaRegex: ch.challenge.exemptUaRegex, failOpen: ch.challenge.failOpen, whitelist: ch.challenge.whitelist,
      goodbots: r.config.goodbots, goodbotsExtra: r.config.goodbotsExtra,
      difficultyBits: r.config.difficultyBits, cookieHours: r.config.cookieHours,
      profiles: ch.challenge.profiles.map(pr => ({ name: pr.name, mode: pr.mode, file: pr.file, exemptPathRegex: pr.exemptPathRegex, exemptUaRegex: pr.exemptUaRegex })),
    };
    out.blocklistEnabled = ch.settings.enable;
    out.files = fileState.files;
    out.ips = { count: fileState.ips.length, sample: fileState.ips.slice(0, 100) };
    return send(res, 200, out);
  });

  // v12.68.0 : statistiques d'efficacite (compteurs agreges du conteneur builtin,
  // jamais d'IP). Lues en HTTP sur le reseau Docker interne (/stats n'est pas
  // routee par nginx et refuse toute requete portant X-Real-IP).
  router.get('/api/challenge/stats', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const hours = Math.min(Math.max(parseInt(url.searchParams.get('hours') || '24', 10) || 24, 1), 720);
    const r = await internalJson(`/stats?hours=${hours}`);
    if (r.unavailable) return send(res, 200, { available: false, reason: r.unavailable });
    return send(res, 200, { available: true, ...r.data });
  });

  // v12.73.0 : analyse des IP qui echouent au challenge + blocages automatiques actifs.
  router.get('/api/challenge/offenders', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const q = new URLSearchParams({
      hours: String(Math.min(Math.max(parseInt(url.searchParams.get('hours') || '24', 10) || 24, 1), 168)),
      min: String(Math.min(Math.max(parseInt(url.searchParams.get('min') || '3', 10) || 3, 1), 100000)),
      limit: String(Math.min(Math.max(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 1), 500)),
      neverSolved: url.searchParams.get('neverSolved') === '0' ? '0' : '1',
    });
    const [o, b] = await Promise.all([internalJson(`/offenders?${q}`), internalJson('/bans')]);
    if (o.unavailable) return send(res, 200, { available: false, reason: o.unavailable });
    return send(res, 200, { available: true, ...o.data, bans: (b.data && b.data.bans) || [] });
  });

  // Leve un blocage automatique (le prochain cycle des blocklists retire l'IP de nginx).
  router.post('/api/challenge/unban', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await httpLib.parseBody(req, { limitBytes: 1024 });
    const ip = String(body.ip || '').trim();
    if (!/^[0-9A-Fa-f:.]{2,45}$/.test(ip)) return httpLib.badRequest(res, 'invalid ip');
    const r = await internalJson(`/unban?ip=${encodeURIComponent(ip)}`, 'POST');
    if (r.unavailable) return send(res, 502, { error: r.unavailable });
    logEvent('challenge.unban', `Blocage automatique leve pour ${ip}`, session.username);
    blocklists.refreshBlocklists({ manual: false, analyzerOnly: true }).catch(() => {});
    return send(res, 200, { ok: true, removed: !!(r.data && r.data.removed) });
  });

  // Regenere les fichiers nginx du challenge (independant de la blocklist).
  router.post('/api/challenge/apply', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    try {
      const result = await blocklists.applyChallengeFiles({ actor: session.username });
      return send(res, 200, result);
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/challenge/container/start', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const r = resolve();
    if (!r.config.enable) return httpLib.badRequest(res, 'challenge is not enabled in challenge.yml');
    if (r.errors.length) return httpLib.badRequest(res, r.errors.join(' ; '));
    try {
      const pull = await docker.pullAndCheckUpdate(r.image);
      if (!pull.ok) return httpLib.serverError(res, new Error(`Pull de l'image ${r.image} echoue : ${pull.error}`));
      await startContainer(r);
      logEvent('challenge.start', `challenge container ${r.name} (${r.engine}) (re)started`, session.username);
      return send(res, 200, { ok: true, name: r.name });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/challenge/container/stop', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const r = resolve();
    try {
      await stopContainer(r.name);
      // v12.74.1 : snippets nginx vides + reload, sinon les vhosts protégés répondent 5xx (auth_request sans upstream).
      blocklists.setChallengePaused(true);
      const applied = await blocklists.applyChallengeFiles({ actor: session.username }).catch(e => ({ ok: false, error: e.message }));
      logEvent('challenge.stop', `challenge container ${r.name} stopped; nginx snippets emptied (ok=${applied.ok})`, session.username);
      return send(res, 200, { ok: true, nginx: applied });
    } catch (e) { return httpLib.serverError(res, e); }
  });

  router.post('/api/challenge/image/update', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const r = resolve();
    if (!r.config.enable) return httpLib.badRequest(res, 'challenge is not enabled in challenge.yml');
    const out = await lifecycle.legacyImageUpdate('challenge');
    logEvent('challenge.image_update', `Image ${r.image} ${out.updated ? 'updated' : 'already up to date'}${out.recreated ? ', container recreated' : ''}`, session.username);
    return send(res, 200, out);
  });
}

// ─── Cycle de vie uniforme (#104) ────────────────────────────────────────────
lifecycle.register({
  id: 'challenge', label: 'Challenge', page: 'challenge',
  enabled: () => !!resolve().config.enable,
  containerName: () => resolve().name,
  image: () => resolve().image,
  create: async () => {
    const r = resolve();
    if (r.errors.length) throw lifecycle.httpError(400, 'invalid_config', r.errors.join(' ; '));
    const pull = await docker.pullAndCheckUpdate(r.image);
    if (!pull.ok) throw new Error(`Pull de l'image ${r.image} echoue : ${pull.error}`);
    return startContainer(r);
  },
});

module.exports = { register, resolve, challengeListIps, challengeBanEvents, secretFor, startContainer, containerStatus, ensureContainerAtBoot };
