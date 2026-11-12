'use strict';
/**
 * Appel INTERNE d'une route GET du dashboard (v12.78.0) — réutilise les gestionnaires existants,
 * donc la même source de vérité que l'interface, sans dupliquer leur logique.
 *
 * Garde-fous : uniquement GET ; uniquement les chemins d'une liste blanche fournie par l'appelant
 * (lib/hub-modules.js) ; session synthétique en lecture (rôle « admin » interne, jamais exposée) ;
 * délai borné ; réponse JSON uniquement. Aucun accès réseau : le gestionnaire est appelé en mémoire.
 */
const { EventEmitter } = require('events');

const SESSION = Object.freeze({ username: 'ngx-hub', role: 'admin', name: 'NGX Ops Hub (interne)', internal: true });

function fakeRes() {
  const r = new EventEmitter();
  r.headersSent = false; r.statusCode = 200; r.chunks = [];
  r.writeHead = (code) => { r.statusCode = code; r.headersSent = true; return r; };
  r.setHeader = () => r; r.getHeader = () => undefined; r.removeHeader = () => r;
  r.write = (c) => { r.chunks.push(Buffer.from(c)); return true; };
  r.end = (c) => { if (c) r.chunks.push(Buffer.from(c)); r.finished = true; r.emit('finish'); };
  return r;
}

/** @returns {Promise<{status:number, json:any}>} ; json = null si la réponse n'est pas du JSON. */
async function callInternal(router, pathWithQuery, { timeoutMs = 10_000, allow } = {}) {
  const url = new URL(pathWithQuery, 'http://internal.invalid');
  if (!url.pathname.startsWith('/api/')) return { status: 400, json: null };
  if (allow && !allow.has(url.pathname)) return { status: 403, json: null };
  const handler = router.match('GET', url.pathname);
  if (!handler) return { status: 404, json: null };
  const res = fakeRes();
  const req = Object.assign(new EventEmitter(), { method: 'GET', url: url.pathname + url.search, headers: { host: 'internal.invalid' }, socket: { remoteAddress: '127.0.0.1' } });
  let timer;
  const run = Promise.resolve(handler({ req, res, session: SESSION, url, pathname: url.pathname, clientIp: '127.0.0.1' }));
  const timeout = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('timeout')), timeoutMs); });
  try { await Promise.race([run, timeout]); } catch (e) { return { status: e.message === 'timeout' ? 504 : 500, json: null }; } finally { clearTimeout(timer); }
  let json = null;
  try { json = JSON.parse(Buffer.concat(res.chunks).toString('utf8')); } catch { /* non JSON */ }
  return { status: res.statusCode, json };
}

module.exports = { callInternal, SESSION };
