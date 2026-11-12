'use strict';
/**
 * Redis optionnel (v12.78.0) — état de la connexion, côté dashboard et côté analyzer.
 *
 *   GET /api/redis/status   (admin)
 *
 * Redis n'est jamais requis : sans REDIS_URL la route répond { enabled:false } et rien d'autre
 * ne change. Le mot de passe (REDIS_PASSWORD) n'est jamais renvoyé ; l'adresse est affichée
 * sans identifiants.
 */
const cfg = require('../lib/config');
const auth = require('../lib/auth');
const httpLib = require('../lib/http');
const { createClient } = require('../lib/redis-lite');

const { PERMS, hasPerm } = auth;
const { send } = httpLib;

let deps = { analyzerApi: null };
function setDeps(d) { Object.assign(deps, d || {}); }

let client = null, clientErr = '';
function getClient() {
  if (client || clientErr) return client;
  try {
    client = createClient(process.env.REDIS_URL || '', { password: process.env.REDIS_PASSWORD || '', timeoutMs: 2000 });
  } catch (e) { clientErr = String(e.message || e); }
  return client;
}

async function status() {
  const out = { enabled: false, prefix: process.env.REDIS_PREFIX || cfg.INSTANCE_ID || 'ngx' };
  const c = getClient();
  if (clientErr) return { ...out, enabled: true, ok: false, error: clientErr };
  if (!c) return out;
  const info = await c.info();
  out.enabled = true; out.addr = c.redacted();
  Object.assign(out, info);
  if (deps.analyzerApi) {
    try {
      const r = await deps.analyzerApi('/api/status');
      out.analyzer = r?.data?.redis || null;
    } catch { out.analyzer = null; }
  }
  return out;
}

function register(router) {
  router.get('/api/redis/status', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    return send(res, 200, await status());
  });
}

module.exports = { register, setDeps, status };
