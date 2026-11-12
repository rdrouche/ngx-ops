'use strict';
/**
 * Assemblage de l'application (testable sans écouter de port) :
 *   createApp({ config, key, log? }) → { server, ctx, handle, start(), stop() }
 */
const http = require('node:http');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { loadConfig, APP_VERSION, API_PREFIX } = require('./config');
const { createLogger } = require('./logger');
const { openStore } = require('./store');
const { Router } = require('./router');
const { HttpError, sendJson, readJson, serveStatic } = require('./http');
const { applySecurityHeaders, RateLimiter, makeList, clientIp } = require('./security');
const { createSessionStore } = require('./sessions');
const { safeEqual } = require('./crypto');
const { hasPerm, PERMS } = require('./perms');
const { loadFeatures } = require('./features');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const FEATURES_DIR = path.join(__dirname, '..', 'features');
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function reply(status, json, headers) { return { __reply: true, status, json, headers }; }

async function createApp({ config = loadConfig(), key, log, dbFile, banner } = {}) {
  if (!key) throw new Error('clé maîtresse requise');
  const logger = log || createLogger(config.log.level);
  const db = await openStore(config, { file: dbFile });
  const router = new Router();
  const limiter = new RateLimiter();
  const trusted = makeList(config.server.trusted_proxies);
  const sessions = createSessionStore(db, { ttlMs: config.server.session_ttl_minutes * 60_000 });
  const services = new Map();
  const cleanups = [];

  /** Journal d'audit : ne rejette jamais (un échec d'écriture est journalisé, sans interrompre la requête). */
  const audit = async (actor, action, target, ip, detail) => {
    try {
      await db.run('INSERT INTO audit(ts,actor,action,target,ip,detail) VALUES (?,?,?,?,?,?)',
        [Date.now(), actor || null, action, target || null, ip || null, detail ? JSON.stringify(detail).slice(0, 1000) : null]);
    } catch (e) { logger.error('écriture audit', { err: e }); }
  };

  const ctx = {
    config, db, key, router, limiter, sessions, services, audit, reply, perms: PERMS, hasPerm,
    log: logger, version: APP_VERSION, banner: banner || ((text) => process.stdout.write(text + '\n')), onStop: (fn) => cleanups.push(fn),
    HttpError, readJson,
  };
  const features = await loadFeatures(ctx, FEATURES_DIR);
  ctx.features = features;

  const allowedOrigins = new Set();
  if (config.server.public_base_url) { try { allowedOrigins.add(new URL(config.server.public_base_url).host); } catch { /* ignoré */ } }

  function originOk(req) {
    const origin = req.headers.origin;
    if (!origin) return true; // clients non-navigateur ; le CSRF token reste exigé pour les routes authentifiées
    try {
      const host = new URL(origin).host;
      return host === req.headers.host || allowedOrigins.has(host);
    } catch { return false; }
  }

  async function dispatchApi(req, res, url, reqId) {
    const m = router.match(req.method, url.pathname);
    if (!m) throw new HttpError(404, 'Route inconnue', 'not_found');
    if (m.methodNotAllowed) throw new HttpError(405, 'Méthode non autorisée', 'method_not_allowed');
    const { route, params } = m;
    const o = route.opts;
    const ip = clientIp(req, trusted);

    if (!SAFE_METHODS.has(req.method) && !originOk(req)) throw new HttpError(403, 'Origine refusée', 'bad_origin');

    let session = null;
    if (o.auth) {
      session = await sessions.fromRequest(req);
      if (!session) throw new HttpError(401, 'Authentification requise', 'unauthenticated');
      if (!o.states.includes(session.state)) {
        if (session.state === 'mfa') throw new HttpError(401, 'Code MFA requis', 'mfa_required');
        if (session.state === 'pwchange') throw new HttpError(403, 'Changement du mot de passe obligatoire', 'password_change_required');
        if (session.state === 'enroll') throw new HttpError(403, 'Activation du MFA obligatoire', 'mfa_enrollment_required');
        throw new HttpError(403, 'Session non autorisée', 'forbidden');
      }
      if (!SAFE_METHODS.has(req.method) && o.csrf !== false) {
        if (!safeEqual(req.headers['x-csrf-token'] || '', session.csrf)) throw new HttpError(403, 'Jeton CSRF invalide', 'bad_csrf');
      }
      if (o.perm && !hasPerm(session, o.perm)) throw new HttpError(403, 'Permission insuffisante', 'forbidden');
    }
    if (o.rate) {
      const r = limiter.hit(`${o.rate.key}:${ip}`, o.rate.max, o.rate.windowMs);
      if (!r.allowed) throw new HttpError(429, 'Trop de requêtes', 'rate_limited');
    }

    let body = {};
    if (['POST', 'PATCH', 'PUT'].includes(req.method)) {
      const hasBody = (req.headers['content-length'] && req.headers['content-length'] !== '0') || req.headers['transfer-encoding'];
      if (hasBody && !o.raw) body = await readJson(req); // o.raw : la route lit elle-même le flux (envoi d'archives)
    }
    const query = Object.fromEntries(url.searchParams);
    const out = await route.handler({ req, res, params, query, body, session, ip, url, reqId });
    if (res.headersSent || res.writableEnded) return;
    if (out && out.__reply) sendJson(res, out.status, out.json, out.headers);
    else sendJson(res, 200, out === undefined ? { ok: true } : out);
  }

  async function handle(req, res) {
    const reqId = randomBytes(6).toString('hex');
    res.setHeader('X-Request-Id', reqId);
    let url;
    try { url = new URL(req.url, 'http://hub.local'); } catch { res.writeHead(400); return res.end(); }
    const isApi = url.pathname.startsWith('/api/') || url.pathname === '/healthz';
    applySecurityHeaders(res, { api: isApi, hsts: config.server.cookie_secure });
    try {
      if (isApi) return await dispatchApi(req, res, url, reqId);
      if (!['GET', 'HEAD'].includes(req.method)) throw new HttpError(405, 'Méthode non autorisée', 'method_not_allowed');
      const rel = url.pathname === '/' ? '/index.html' : url.pathname;
      if (serveStatic(PUBLIC_DIR, rel, req, res)) return;
      throw new HttpError(404, 'Introuvable', 'not_found');
    } catch (e) {
      if (res.headersSent) { res.end(); return; }
      if (e instanceof HttpError) {
        const headers = e.status === 429 ? { 'Retry-After': '60' } : {};
        if (isApi) return sendJson(res, e.status, { error: { code: e.code, message: e.message } }, headers);
        res.writeHead(e.status, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(e.message);
      }
      logger.error('erreur interne', { reqId, path: url.pathname, err: e });
      return sendJson(res, 500, { error: { code: 'internal', message: 'Erreur interne', request_id: reqId } });
    }
  }

  const server = http.createServer((req, res) => { handle(req, res); });
  // Les envois d'archives (push de sauvegardes) sont longs : délai plus large uniquement si la feature est active.
  server.requestTimeout = config.backups.enabled && config.features.backups !== false ? config.backups.upload_timeout_s * 1000 : 30_000;
  server.headersTimeout = 15_000;
  server.keepAliveTimeout = 5_000;

  const purgeTimer = setInterval(() => { sessions.purgeExpired().catch((e) => logger.warn('purge sessions', { err: e })); }, 10 * 60_000);
  purgeTimer.unref();

  return {
    server, ctx, handle,
    start() {
      return new Promise((resolve) => {
        server.listen(config.server.port, config.server.host, () => {
          logger.info('NGX Ops Hub démarré', { version: APP_VERSION, api: API_PREFIX, port: server.address().port, features: features.map((f) => f.name) });
          resolve(server.address());
        });
      });
    },
    stop() {
      clearInterval(purgeTimer); limiter.stop();
      for (const fn of cleanups) { try { fn(); } catch { /* arrêt best-effort */ } }
      return new Promise((resolve) => { server.close(async () => { try { await db.close(); } catch { /* déjà fermée */ } resolve(); }); server.closeAllConnections?.(); });
    },
  };
}

module.exports = { createApp, reply };
