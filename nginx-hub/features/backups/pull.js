'use strict';
/**
 * Récupération (pull) d'une sauvegarde : GET <base>/api/hub/v1/backup/manifest puis /backup/archive.
 * Mêmes garde-fous que la collecte du résumé : HTTPS, DNS validé à la connexion, AUCUNE redirection suivie,
 * certificat vérifié, délais et tailles bornés. Le jeton de pull (X-Hub-Token) est distinct du jeton de résumé.
 */
const http = require('node:http');
const https = require('node:https');
const { guardedLookup, parseInstanceUrl } = require('../../lib/security');
const { APP_VERSION, API_PREFIX } = require('../../lib/config');
const { FetchError, caBundle, mapNetError } = require('../collector/fetcher');
const { receiveToFile } = require('./ingest');

const MANIFEST_MAX = 256 * 1024;

/**
 * @param {object} o { baseUrl, token, route:'manifest'|'archive', config, tmp?, maxBytes?, timeoutMs }
 * @returns {Promise<{headers:object, json?:object, sha256?:string, size?:number}>}
 */
function backupGet(o) {
  return new Promise((resolve, reject) => {
    const policy = o.config.security;
    const parsed = parseInstanceUrl(o.baseUrl, policy);
    if (!parsed.ok) return reject(new FetchError('blocked_url'));
    const u = new URL(`${parsed.url}${API_PREFIX}/backup/${o.route}`);
    const lib = u.protocol === 'https:' ? https : http;
    let settled = false;
    const done = (fn, v) => { if (settled) return; settled = true; clearTimeout(deadline); fn(v); };
    const req = lib.request({
      protocol: u.protocol, hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || undefined, path: u.pathname, method: 'GET',
      agent: false, lookup: guardedLookup(policy), ca: u.protocol === 'https:' ? caBundle(policy.extra_ca_file) : undefined, rejectUnauthorized: true,
      headers: { 'X-Hub-Token': o.token, Accept: o.route === 'manifest' ? 'application/json' : 'application/octet-stream', 'User-Agent': `NGX-Ops-Hub/${APP_VERSION}`, 'Accept-Encoding': 'identity' },
    }, (res) => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400) { res.resume(); return done(reject, new FetchError('redirect_refused')); }
      if (status === 401 || status === 403) { res.resume(); return done(reject, new FetchError('auth_failed')); }
      if (status === 404) { res.resume(); return done(reject, new FetchError('not_supported')); }
      if (status === 429) { res.resume(); return done(reject, new FetchError('rate_limited')); }
      if (status < 200 || status >= 300) { res.resume(); return done(reject, new FetchError('http_' + status)); }
      const declared = Number(res.headers['content-length']);
      const max = o.route === 'manifest' ? MANIFEST_MAX : o.maxBytes;
      if (Number.isFinite(declared) && declared > max) { res.resume(); return done(reject, new FetchError('too_large')); }
      if (o.route === 'manifest') {
        if (!/json/i.test(String(res.headers['content-type'] || ''))) { res.resume(); return done(reject, new FetchError('bad_content_type')); }
        const chunks = []; let size = 0;
        res.on('data', (d) => { size += d.length; if (size > max) { done(reject, new FetchError('too_large')); req.destroy(); } else chunks.push(d); });
        res.on('end', () => { try { done(resolve, { headers: res.headers, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); } catch { done(reject, new FetchError('bad_json')); } });
        res.on('error', (e) => done(reject, mapNetError(e)));
        return undefined;
      }
      receiveToFile(res, o.tmp, { maxBytes: max })
        .then((r) => done(resolve, { headers: res.headers, ...r }))
        .catch((e) => done(reject, e.code === 'too_large' ? new FetchError('too_large') : mapNetError(e)));
      return undefined;
    });
    const deadline = setTimeout(() => { done(reject, new FetchError('timeout')); req.destroy(); }, o.timeoutMs);
    req.on('error', (e) => done(reject, mapNetError(e)));
    req.end();
  });
}

module.exports = { backupGet };
