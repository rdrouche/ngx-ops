'use strict';
/**
 * v12.75.0 — URL publique (sans API) des listes de blocage.
 *
 *   GET /public/blocklist.txt                    (public_token vide : publique, sans jeton)
 *   GET /public/blocklist/<source>.txt
 *   GET /public/<token>/blocklist.txt            (public_token defini)
 *   GET /public/<token>/blocklist/<source>.txt
 *
 * Reponse text/plain : un commentaire d'en-tete puis une IP/CIDR par ligne (consommable par curl,
 * ipset, fail2ban, un autre NGX Ops en source `url`). Reglages dans config/blocklists.yml
 * (public_enable, public_token, public_sources). Desactive par defaut ; toute erreur = 404 neutre
 * (ne revele ni l'existence de la fonction ni du jeton). Lecture seule, aucune ecriture.
 * Limites : 60 requetes / minute / IP, ETag + 304, jeton compare a temps constant.
 */
const crypto = require('crypto');
const blocklists = require('./blocklists');

const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 60;
const hits = new Map();

function rateLimited(ip) {
  const now = Date.now();
  const h = hits.get(ip) || { start: now, n: 0 };
  if (now - h.start > RATE_WINDOW_MS) { h.start = now; h.n = 0; }
  h.n++;
  hits.set(ip, h);
  if (hits.size > 5000) for (const [k, v] of hits) if (now - v.start > RATE_WINDOW_MS) hits.delete(k);
  return h.n > RATE_MAX;
}

function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function notFound(res) {
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' });
  res.end('Not found\n');
  return true;
}

/** @returns {boolean} true si la requete a ete traitee */
function maybeHandle(req, res, pathname, ip) {
  if (!pathname.startsWith('/public/')) return false;
  if (req.method !== 'GET' && req.method !== 'HEAD') return notFound(res);
  let pub;
  try { pub = blocklists.getPublicSettings(); } catch { return notFound(res); }
  if (!pub || !pub.enable) return notFound(res);
  if (rateLimited(ip)) {
    res.writeHead(429, { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '60', 'Cache-Control': 'no-store' });
    res.end('Too many requests\n');
    return true;
  }
  let rest = pathname.slice('/public/'.length);
  if (pub.token) {
    const i = rest.indexOf('/');
    const given = i === -1 ? rest : rest.slice(0, i);
    if (!safeEq(given, pub.token)) return notFound(res);
    rest = i === -1 ? '' : rest.slice(i + 1);
  }
  let name;
  if (rest === 'blocklist.txt') name = 'all';
  else {
    const m = rest.match(/^blocklist\/([A-Za-z0-9_.-]{1,64})\.txt$/);
    if (!m) return notFound(res);
    name = m[1];
  }
  const r = blocklists.getPublicIps(name);
  if (!r.ok) return notFound(res);
  const body = `# NGX Ops — liste de blocage (${name}) — ${r.ips.length} entree(s)\n# sources: ${r.sources.join(', ')}\n# une IP ou un CIDR par ligne\n${r.ips.join('\n')}${r.ips.length ? '\n' : ''}`;
  const etag = '"' + crypto.createHash('sha256').update(r.ips.join('\n')).digest('hex').slice(0, 24) + '"';
  const headers = {
    'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'public, max-age=300', 'ETag': etag, 'X-Robots-Tag': 'noindex',
  };
  if (req.headers['if-none-match'] === etag) { res.writeHead(304, headers); res.end(); return true; }
  res.writeHead(200, { ...headers, 'Content-Length': Buffer.byteLength(body) });
  res.end(req.method === 'HEAD' ? undefined : body);
  return true;
}

// Pas de routes /api : servi en amont (server.js) sans session. register() existe pour les tests de routage.
function register() {}

module.exports = { register, maybeHandle, _resetRate: () => hits.clear() };
