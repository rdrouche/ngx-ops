'use strict';
/**
 * Santé (ticket #74).
 *
 *   GET /health       PUBLIC, sans session : { "status": "ok|degraded|down" } — 200 (ok, degraded) ou 503 (down).
 *                     Désactivable : HEALTH_PUBLIC=false → 404. Mis en cache 5 s. À restreindre au niveau du
 *                     reverse proxy (allow / deny) si besoin : voir README, « Santé ».
 *   GET /api/health   PRIVÉ (permission view_metrics) : états par composant, sans aucun détail technique.
 *
 * Réutilise les API de statut existantes (callInternal) : même source de vérité que l'interface.
 */
const auth = require('../lib/auth');
const httpLib = require('../lib/http');
const health = require('../lib/health');
const { callInternal } = require('../lib/hub-internal');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;

let deps = { fetchVTS: async () => null };
let routerRef = null;
function setDeps(d) { Object.assign(deps, d || {}); }

const TTL_MS = 5000;
let cache = { at: 0, value: null, pending: null };
const ALLOW = new Set(health.SOURCES.map((s) => s[1]));

async function compute() {
  const vts = await Promise.race([deps.fetchVTS().catch(() => null), new Promise((r) => setTimeout(() => r(null), 3000))]);
  const paths = [...ALLOW];
  const results = {};
  if (routerRef) {
    await Promise.all(paths.map(async (p) => { results[p] = await callInternal(routerRef, p, { allow: ALLOW, timeoutMs: 4000 }); }));
  }
  return health.evaluate({ nginxUp: !!vts, results });
}

/** Partagé par les deux routes ; les appels simultanés attendent le même calcul. */
async function getHealth(now = Date.now()) {
  if (cache.value && now - cache.at < TTL_MS) return cache.value;
  if (!cache.pending) {
    cache.pending = compute().then((v) => { cache = { at: Date.now(), value: v, pending: null }; return v; })
      .catch(() => { cache.pending = null; return { status: 'down', components: { dashboard: 'ok', nginx: 'unknown' } }; });
  }
  return cache.pending;
}

const publicEnabled = () => String(process.env.HEALTH_PUBLIC ?? 'true').toLowerCase() !== 'false';

/** Appelé par server.js avant la session. Retourne true si la requête est traitée. */
async function maybeHandle(req, res, pathname) {
  if (pathname !== '/health') return false;
  if (req.method !== 'GET' && req.method !== 'HEAD') { send(res, 405, { error: 'Method not allowed' }, 'application/json', { Allow: 'GET, HEAD' }); return true; }
  if (!publicEnabled()) { send(res, 404, { error: 'Not found' }); return true; }
  const h = await getHealth();
  const v = health.publicView(h.status);
  send(res, v.code, v.body, 'application/json', { 'Cache-Control': 'no-store' });
  return true;
}

function register(router) {
  routerRef = router;
  router.get('/api/health', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_METRICS)) return httpLib.forbidden(res);
    const h = await getHealth();
    return send(res, 200, { status: h.status, components: h.components, generated_at: new Date().toISOString() }, 'application/json', { 'Cache-Control': 'no-store' });
  });
}

function _reset() { cache = { at: 0, value: null, pending: null }; }

module.exports = { register, setDeps, maybeHandle, getHealth, _reset };
