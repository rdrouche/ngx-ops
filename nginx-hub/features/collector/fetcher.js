'use strict';
/**
 * Requête sortante vers un dashboard : GET <base>/api/hub/v1/summary (lecture seule).
 * Garde-fous : HTTPS (sauf dev), DNS validé à la connexion, AUCUNE redirection suivie, délai global borné,
 * taille bornée, certificat toujours vérifié, code d'erreur normalisé (jamais de message brut / token dans last_error).
 */
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const fs = require('node:fs');
const { guardedLookup, parseInstanceUrl } = require('../../lib/security');
const { sanitizeSummary } = require('./summary-schema');
const { APP_VERSION, API_PREFIX } = require('../../lib/config');

const SUMMARY_PATH = API_PREFIX + '/summary'; // contrat dashboard : GET /api/hub/v1/summary

class FetchError extends Error {
  constructor(code) { super(code); this.code = code; }
}

const TLS_CODES = new Set(['CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_NOT_YET_VALID', 'ERR_SSL_WRONG_VERSION_NUMBER']);

function mapNetError(err) {
  if (err instanceof FetchError) return err;
  const c = err && err.code;
  if (c === 'HUB_PRIVATE_ADDRESS') return new FetchError('private_address');
  if (c && c.startsWith('HUB_')) return new FetchError('blocked_address');
  if (c === 'ENOTFOUND' || c === 'EAI_AGAIN') return new FetchError('dns');
  if (TLS_CODES.has(c) || /^ERR_SSL|^ERR_TLS/.test(c || '')) return new FetchError('tls');
  if (c === 'ETIMEDOUT') return new FetchError('timeout');
  return new FetchError('connection');
}

let cachedCa = null;
function caBundle(file) {
  if (!file) return undefined;
  if (!cachedCa || cachedCa.file !== file) cachedCa = { file, ca: [...tls.rootCertificates, fs.readFileSync(file, 'utf8')] };
  return cachedCa.ca;
}

/**
 * GET JSON générique (résumé et modules du contrat) avec toutes les garde-fous ci-dessus.
 * @param {{baseUrl:string, token:string}} target
 * @param {object} config configuration complète
 * @param {{path:string, query?:object, maxBytes?:number, timeoutMs?:number, parse?:Function}} opt
 * @returns {Promise<{data:any, latencyMs:number}>}
 */
function fetchJson(target, config, opt) {
  return new Promise((resolve, reject) => {
    const policy = config.security;
    const c = config.collector;
    const parsed = parseInstanceUrl(target.baseUrl, policy); // revalidé à CHAQUE collecte (la politique a pu changer)
    if (!parsed.ok) return reject(new FetchError('blocked_url'));
    const u = new URL(parsed.url + opt.path);
    for (const [k, v] of Object.entries(opt.query || {})) u.searchParams.set(k, String(v));
    const maxBytes = opt.maxBytes || c.max_response_bytes;
    const lib = u.protocol === 'https:' ? https : http;
    const started = Date.now();
    let settled = false;
    const done = (fn, v) => { if (settled) return; settled = true; clearTimeout(deadline); fn(v); };

    const req = lib.request({
      protocol: u.protocol,
      hostname: u.hostname.replace(/^\[|\]$/g, ''),
      port: u.port || undefined,
      path: u.pathname + u.search,
      method: 'GET',
      agent: false,
      lookup: guardedLookup(policy),
      ca: u.protocol === 'https:' ? caBundle(policy.extra_ca_file) : undefined,
      rejectUnauthorized: true,
      headers: {
        ...(target.bearer ? { Authorization: 'Bearer ' + target.token } : { 'X-Hub-Token': target.token }),
        Accept: 'application/json',
        'User-Agent': `NGX-Ops-Hub/${APP_VERSION}`,
        'Accept-Encoding': 'identity',
      },
    }, (res) => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400) { res.resume(); return done(reject, new FetchError('redirect_refused')); }
      if (status === 403) { // 403 {"error":"expose_ips_disabled"} : module d'IP demandé alors que le dashboard ne les expose pas
        const b = []; let n = 0;
        res.on('data', (d) => { n += d.length; if (n <= 4096) b.push(d); });
        res.on('end', () => done(reject, new FetchError(/expose_ips_disabled/.test(Buffer.concat(b).toString('utf8')) ? 'ips_disabled' : 'auth_failed')));
        res.on('error', (e) => done(reject, mapNetError(e)));
        return undefined;
      }
      if (status === 401) { res.resume(); return done(reject, new FetchError('auth_failed')); }
      if (status === 429) { res.resume(); return done(reject, new FetchError('rate_limited')); }
      if (status === 404) { res.resume(); return done(reject, new FetchError('not_supported')); }
      if (status < 200 || status >= 300) { res.resume(); return done(reject, new FetchError('http_' + status)); }
      if (!/json/i.test(String(res.headers['content-type'] || ''))) { res.resume(); return done(reject, new FetchError('bad_content_type')); }
      const declared = Number(res.headers['content-length']);
      if (Number.isFinite(declared) && declared > maxBytes) { res.resume(); return done(reject, new FetchError('too_large')); }
      const chunks = []; let size = 0;
      res.on('data', (d) => {
        size += d.length;
        if (size > maxBytes) { done(reject, new FetchError('too_large')); req.destroy(); return; }
        chunks.push(d);
      });
      res.on('end', () => {
        try {
          const raw = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          done(resolve, { data: opt.parse ? opt.parse(raw) : raw, latencyMs: Date.now() - started });
        } catch (e) { done(reject, new FetchError(e.code === 'bad_schema' ? 'bad_schema' : 'bad_json')); }
      });
      res.on('error', (e) => done(reject, mapNetError(e)));
    });

    const deadline = setTimeout(() => { done(reject, new FetchError('timeout')); req.destroy(); }, opt.timeoutMs || c.timeout_ms);
    req.on('error', (e) => done(reject, mapNetError(e)));
    req.end();
  });
}

/** Résumé (schéma 1) : GET /api/hub/v1/summary, assaini strictement. */
async function fetchSummary(target, config) {
  const { data, latencyMs } = await fetchJson(target, config, { path: SUMMARY_PATH, parse: sanitizeSummary });
  return { summary: data, latencyMs };
}

module.exports = { fetchJson, fetchSummary, FetchError, caBundle, mapNetError };
