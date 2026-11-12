'use strict';
/**
 * Sécurité transverse : en-têtes HTTP, limiteur de débit, IP client (proxys de confiance),
 * validation d'URL d'instance et garde SSRF (résolution DNS contrôlée, adresses internes bloquées).
 */
const net = require('node:net');
const dns = require('node:dns');

// ───────────────────────── En-têtes ─────────────────────────
const CSP = [
  "default-src 'self'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:",
  "font-src 'self'", "connect-src 'self'", "object-src 'none'", "base-uri 'none'",
  "form-action 'self'", "frame-ancestors 'none'",
].join('; ');

function applySecurityHeaders(res, { api = false, hsts = true } = {}) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (hsts) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (api) res.setHeader('Cache-Control', 'no-store');
}

// ───────────────────────── Limiteur de débit ─────────────────────────
class RateLimiter {
  constructor() { this.hits = new Map(); this.timer = setInterval(() => this.gc(), 60_000); this.timer.unref(); }
  /** @returns {{allowed:boolean, retryAfter:number}} */
  hit(key, max, windowMs, now = Date.now()) {
    const arr = (this.hits.get(key) || []).filter((t) => now - t < windowMs);
    if (arr.length >= max) { this.hits.set(key, arr); return { allowed: false, retryAfter: Math.ceil((windowMs - (now - arr[0])) / 1000) }; }
    arr.push(now); this.hits.set(key, arr);
    return { allowed: true, retryAfter: 0 };
  }
  reset(key) { this.hits.delete(key); }
  gc(now = Date.now()) { for (const [k, arr] of this.hits) if (!arr.length || now - arr[arr.length - 1] > 3_600_000) this.hits.delete(k); }
  stop() { clearInterval(this.timer); }
}

// ───────────────────────── Plages d'adresses ─────────────────────────
function makeList(cidrs) {
  const bl = new net.BlockList();
  for (const c of cidrs) {
    const [addr, bits] = String(c).split('/');
    const fam = net.isIPv6(addr) ? 'ipv6' : net.isIPv4(addr) ? 'ipv4' : null;
    if (!fam) throw new Error('CIDR invalide : ' + c);
    if (bits === undefined) bl.addAddress(addr, fam); else bl.addSubnet(addr, Number(bits), fam);
  }
  return bl;
}

// Toujours bloquées (métadonnées cloud, multicast, réservées…), non contournables par config.
const ALWAYS_BLOCKED = makeList(['0.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4', '::/128', 'fe80::/10', 'ff00::/8']);
// Réseaux privés/loopback : autorisés seulement si allow_private_networks ou allowed_cidrs.
const PRIVATE = makeList(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '100.64.0.0/10', '::1/128', 'fc00::/7']);

/** Convertit ::ffff:a.b.c.d (ou forme hexadécimale) en IPv4 pour appliquer les mêmes règles. */
function unmapV4(ip) {
  if (!net.isIPv6(ip)) return ip;
  const m = ip.toLowerCase().match(/^(?:0:0:0:0:0:ffff:|::ffff:)(.+)$/);
  if (!m) return ip;
  if (net.isIPv4(m[1])) return m[1];
  const g = m[1].split(':');
  if (g.length === 2) {
    const n = (parseInt(g[0], 16) << 16) | parseInt(g[1], 16);
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  return ip;
}

/** @returns {string|null} raison du blocage, ou null si l'adresse est autorisée */
function blockedReason(ipRaw, policy = {}) {
  const ip = unmapV4(ipRaw);
  const fam = net.isIPv6(ip) ? 'ipv6' : net.isIPv4(ip) ? 'ipv4' : null;
  if (!fam) return 'invalid_address';
  if (ALWAYS_BLOCKED.check(ip, fam)) return 'blocked_address';
  if (PRIVATE.check(ip, fam)) {
    if (policy.allow_private_networks) return null;
    if (policy.allowed_cidrs && policy.allowed_cidrs.length && makeList(policy.allowed_cidrs).check(ip, fam)) return null;
    return 'private_address';
  }
  return null;
}

/** Fonction `lookup` pour http(s).request : résout puis valide TOUTES les adresses (anti DNS-rebinding). */
function guardedLookup(policy) {
  return (hostname, options, cb) => {
    const callback = typeof options === 'function' ? options : cb;
    dns.lookup(hostname, { all: true }, (err, addrs) => {
      if (err) return callback(err);
      for (const a of addrs) {
        const reason = blockedReason(a.address, policy);
        if (reason) { const e = new Error(reason); e.code = 'HUB_' + reason.toUpperCase(); return callback(e); }
      }
      const first = addrs[0];
      if (options && options.all) return callback(null, addrs);
      return callback(null, first.address, first.family);
    });
  };
}

/**
 * Valide et normalise l'URL de base d'une instance.
 * @returns {{ok:true,url:string,host:string}|{ok:false,error:string}}
 */
function parseInstanceUrl(raw, policy = {}) {
  let u;
  try { u = new URL(String(raw || '').trim()); } catch { return { ok: false, error: 'URL invalide' }; }
  const httpsOk = u.protocol === 'https:';
  const httpOk = u.protocol === 'http:' && policy.allow_insecure_http;
  if (!httpsOk && !httpOk) return { ok: false, error: 'HTTPS obligatoire' };
  if (u.username || u.password) return { ok: false, error: 'identifiants dans l\'URL interdits' };
  if (u.search || u.hash) return { ok: false, error: 'paramètres/fragment interdits' };
  if (!u.hostname || u.hostname.length > 253) return { ok: false, error: 'nom d\'hôte invalide' };
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    const reason = blockedReason(host, policy);
    if (reason) return { ok: false, error: 'adresse non autorisée (' + reason + ')' };
  }
  if (/\.(?:internal|local)$/i.test(host) && !policy.allow_private_networks) {
    return { ok: false, error: 'nom interne non autorisé (allow_private_networks=false)' };
  }
  const pathname = u.pathname.replace(/\/+$/, '');
  return { ok: true, url: u.origin + pathname, host };
}

// ───────────────────────── IP client ─────────────────────────
function clientIp(req, trustedList) {
  const remote = unmapV4(req.socket.remoteAddress || '');
  if (trustedList && remote && trustedList.check(remote, net.isIPv6(remote) ? 'ipv6' : 'ipv4')) {
    const real = String(req.headers['x-real-ip'] || '').trim();
    if (net.isIP(real)) return real;
  }
  return remote;
}

module.exports = { applySecurityHeaders, RateLimiter, makeList, blockedReason, guardedLookup, parseInstanceUrl, clientIp, unmapV4, CSP };
