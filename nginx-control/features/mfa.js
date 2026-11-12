'use strict';
/**
 * MFA : TOTP (QR code) + clés de sécurité WebAuthn (YubiKey) + codes de secours.
 *
 *  - Avant session  : startChallenge() / maybeHandle() — routes /auth/mfa*
 *                     (appelées depuis server.js, comme le login).
 *  - Après session  : register(router) — /api/mfa/* (auto-service + reset admin).
 *
 * Un compte sans MFA se connecte comme avant (aucune régression). Les jetons
 * d'API (Bearer : agents, déploiement, certsync) ne passent pas par le login
 * et ne sont donc pas concernés.
 */
const crypto = require('crypto');
const auth = require('../lib/auth');
const httpLib = require('../lib/http');
const store = require('../lib/mfa-store');
const totp = require('../lib/totp');
const wa = require('../lib/webauthn');
const { mfaPage } = require('../lib/mfa-page');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;

const PENDING_TTL_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const pending = new Map();      // token → {username, ip, exp, attempts, challenge}
const enroll = new Map();       // username → {secret?, challenge?, exp}
let logEvent = () => {};
function setEventLogger(fn) { if (typeof fn === 'function') logEvent = fn; }

function gc() {
  const now = Date.now();
  for (const [k, v] of pending) if (v.exp < now) pending.delete(k);
  for (const [k, v] of enroll) if (v.exp < now) enroll.delete(k);
}
setInterval(gc, 60 * 1000).unref();

// ── Contexte WebAuthn (rpId / origins) ──────────────────────────────────────
function rpContext(req) {
  const fwd = (req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  const host = (fwd || req.headers.host || 'localhost').toLowerCase();
  const rpId = process.env.MFA_RP_ID || host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  const envOrigins = (process.env.MFA_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  const origins = envOrigins.length ? envOrigins : [`${auth.isRequestHttps(req) ? 'https' : 'http'}://${host}`];
  return { rpId, origins };
}

// ── Cookie de login en attente ──────────────────────────────────────────────
function pendingCookie(token, req, clear = false) {
  return `ngx_mfa=${clear ? '' : token}; HttpOnly; SameSite=Strict; Path=/auth; Max-Age=${clear ? 0 : 300}` +
         (auth.isRequestHttps(req) ? '; Secure' : '');
}
function getPending(req) {
  const t = auth.parseCookies(req).ngx_mfa;
  const p = t && pending.get(t);
  if (!p || p.exp < Date.now()) return null;
  return { token: t, p };
}
function lang(req) { return auth.parseCookies(req).ngx_lang === 'fr' ? 'fr' : 'en'; }
function msg(l, fr, en) { return l === 'fr' ? fr : en; }

/** Appelé par server.js après un mot de passe valide si le compte a un MFA. */
function startChallenge(req, res, user, ip) {
  const token = crypto.randomBytes(32).toString('hex');
  pending.set(token, { username: user.username, ip, exp: Date.now() + PENDING_TTL_MS, attempts: 0, challenge: null });
  res.writeHead(302, { 'Set-Cookie': pendingCookie(token, req), 'Location': '/auth/mfa' });
  res.end();
}

function finishLogin(req, res, token, p, method) {
  pending.delete(token);
  auth.clearLoginFailures(p.ip, p.username);
  const user = auth.findUser ? auth.findUser(p.username) : auth.getUsers().find(u => u.username === p.username);
  if (!user || user.disabled) { res.writeHead(302, { 'Location': '/auth/login', 'Set-Cookie': pendingCookie('', req, true) }); return res.end(); }
  const sess = auth.createSession(user, p.ip);
  logEvent('auth.mfa.ok', { username: p.username, ip: p.ip, method }, 'auth');
  res.writeHead(302, { 'Set-Cookie': [auth.setCookieHeader(sess, req), pendingCookie('', req, true)], 'Location': '/' });
  return res.end();
}

function fail(req, p, token, why) {
  p.attempts += 1;
  auth.recordLoginFailure(p.ip, p.username);
  logEvent('auth.mfa.failed', { username: p.username, ip: p.ip, reason: why }, 'auth');
  if (p.attempts >= MAX_ATTEMPTS) pending.delete(token);
}

function renderPage(req, res, p, error, recovery) {
  const st = store.status(p.username);
  const html = mfaPage({ error, lang: lang(req), hasTotp: st.totp, hasKeys: st.keys.length > 0, recovery: !!recovery });
  return send(res, 200, html, 'text/html');
}

async function maybeHandle(req, res, pathname, ip) {
  if (!pathname.startsWith('/auth/mfa')) return false;
  const l = lang(req);
  const cur = getPending(req);
  if (!cur) {
    if (req.method === 'GET' && pathname === '/auth/mfa') { res.writeHead(302, { Location: '/auth/login' }); res.end(); return true; }
    send(res, 401, { error: msg(l, 'Session de connexion expirée', 'Login session expired') });
    return true;
  }
  const { token, p } = cur;

  if (pathname === '/auth/mfa' && req.method === 'GET') {
    const url = new URL(req.url, 'http://x');
    renderPage(req, res, p, '', url.searchParams.get('recovery') === '1');
    return true;
  }

  if (req.method !== 'POST') { send(res, 405, { error: 'Method not allowed' }); return true; }
  if (!auth.loginOriginAllowed(req)) { httpLib.forbidden(res, 'Origin invalide'); return true; }
  const rate = auth.checkLoginRate(ip, p.username);
  if (rate.blocked) {
    send(res, 429, { error: msg(l, 'Trop de tentatives', 'Too many attempts') }, 'application/json', { 'Retry-After': String(rate.retryAfterSec) });
    return true;
  }

  if (pathname === '/auth/mfa') {
    const body = await httpLib.readRawBody(req, { limitBytes: 2 * 1024 });
    const params = new URLSearchParams(body);
    const mode = params.get('mode') === 'recovery' ? 'recovery' : 'totp';
    const code = (params.get('code') || '').trim();
    if (mode === 'recovery') {
      if (store.useRecovery(p.username, code)) { finishLogin(req, res, token, p, 'recovery'); return true; }
    } else {
      const u = store.getUser(p.username);
      if (u.totp && u.totp.enabled) {
        const ctr = totp.verify(u.totp.secret, code, { lastCounter: u.totp.lastCounter ?? -1 });
        if (ctr !== null) {
          store.update(p.username, (x) => { x.totp.lastCounter = ctr; return x; });
          finishLogin(req, res, token, p, 'totp'); return true;
        }
      }
    }
    fail(req, p, token, mode);
    if (!pending.has(token)) { res.writeHead(302, { 'Location': '/auth/login', 'Set-Cookie': pendingCookie('', req, true) }); res.end(); return true; }
    renderPage(req, res, p, msg(l, 'Code invalide', 'Invalid code'), mode === 'recovery');
    return true;
  }

  if (pathname === '/auth/mfa/webauthn/options') {
    const u = store.getUser(p.username);
    if (!u.webauthn.length) { send(res, 400, { error: 'no key' }); return true; }
    p.challenge = crypto.randomBytes(32).toString('base64url');
    send(res, 200, { publicKey: {
      challenge: p.challenge, rpId: rpContext(req).rpId, timeout: 60000, userVerification: 'discouraged',
      allowCredentials: u.webauthn.map(k => ({ id: k.id })),
    } });
    return true;
  }

  if (pathname === '/auth/mfa/webauthn/verify') {
    let b;
    try { b = await parseBody(req, { limitBytes: 16 * 1024 }); } catch { send(res, 400, { error: 'bad body' }); return true; }
    const u = store.getUser(p.username);
    const cred = u.webauthn.find(k => k.id === b.id);
    if (!cred || !p.challenge) { fail(req, p, token, 'webauthn'); send(res, 200, { ok: false, error: msg(l, 'Clé inconnue', 'Unknown key') }); return true; }
    const challenge = p.challenge; p.challenge = null;
    try {
      const ctx = rpContext(req);
      const counter = wa.verifyAssertion(b, cred, { challenge, origins: ctx.origins, rpId: ctx.rpId });
      store.update(p.username, (x) => { const k = x.webauthn.find(z => z.id === cred.id); if (k) k.counter = counter; return x; });
    } catch (e) {
      fail(req, p, token, 'webauthn:' + e.message);
      send(res, 200, { ok: false, error: msg(l, 'Clé refusée', 'Key rejected') });
      return true;
    }
    pending.delete(token);
    auth.clearLoginFailures(p.ip, p.username);
    const user = auth.findUser(p.username);
    if (!user || user.disabled) { send(res, 200, { ok: false, error: 'disabled' }); return true; }
    const sess = auth.createSession(user, p.ip);
    logEvent('auth.mfa.ok', { username: p.username, ip: p.ip, method: 'webauthn' }, 'auth');
    send(res, 200, { ok: true }, 'application/json', { 'Set-Cookie': [auth.setCookieHeader(sess, req), pendingCookie('', req, true)] });
    return true;
  }

  send(res, 404, { error: 'Not found' });
  return true;
}

// ── API authentifiée ────────────────────────────────────────────────────────
function needPassword(session, password) {
  return !!(password && auth.verifyCredentials(session.username, String(password)));
}

function register(router) {
  router.get('/api/mfa/status', async ({ res, session }) => {
    if (!session || !session.username) return httpLib.forbidden(res);
    return send(res, 200, store.status(session.username));
  });

  router.post('/api/mfa/totp/setup', async ({ req, res, session }) => {
    if (!session || !session.username) return httpLib.forbidden(res);
    const secret = totp.generateSecret();
    enroll.set(session.username, { ...(enroll.get(session.username) || {}), secret, exp: Date.now() + 10 * 60 * 1000 });
    return send(res, 200, { secret, uri: totp.otpauthUri({ secret, account: session.username }) });
  });

  router.post('/api/mfa/totp/confirm', async ({ req, res, session }) => {
    if (!session || !session.username) return httpLib.forbidden(res);
    const b = await parseBody(req, { limitBytes: 2048 });
    const e = enroll.get(session.username);
    if (!e || !e.secret) return send(res, 400, { error: 'no pending setup' });
    const ctr = totp.verify(e.secret, b.code);
    if (ctr === null) return send(res, 400, { error: 'invalid code' });
    let codes = null;
    store.update(session.username, (u) => {
      u.totp = { secret: e.secret, enabled: true, lastCounter: ctr, createdAt: new Date().toISOString() };
      if (!u.recovery || !u.recovery.length) { const r = store.newRecoveryCodes(); codes = r.codes; u.recovery = r.hashes; }
      return u;
    });
    enroll.delete(session.username);
    logEvent('auth.mfa.enabled', { username: session.username, method: 'totp' }, 'auth');
    return send(res, 200, { ok: true, recoveryCodes: codes });
  });

  router.post('/api/mfa/totp/disable', async ({ req, res, session }) => {
    if (!session || !session.username) return httpLib.forbidden(res);
    const b = await parseBody(req, { limitBytes: 2048 });
    if (!needPassword(session, b.password)) return send(res, 403, { error: 'bad password' });
    store.update(session.username, (u) => { u.totp = null; return u; });
    logEvent('auth.mfa.disabled', { username: session.username, method: 'totp' }, 'auth');
    return send(res, 200, { ok: true });
  });

  router.post('/api/mfa/webauthn/options', async ({ req, res, session }) => {
    if (!session || !session.username) return httpLib.forbidden(res);
    const u = store.getUser(session.username);
    if (u.webauthn.length >= store.MAX_KEYS) return send(res, 400, { error: 'too many keys' });
    const challenge = crypto.randomBytes(32).toString('base64url');
    enroll.set(session.username, { ...(enroll.get(session.username) || {}), challenge, exp: Date.now() + 10 * 60 * 1000 });
    const ctx = rpContext(req);
    return send(res, 200, { publicKey: {
      challenge, rp: { name: 'NGX Ops', id: ctx.rpId },
      user: { id: crypto.createHash('sha256').update(session.username).digest('base64url'), name: session.username, displayName: session.name || session.username },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      timeout: 60000, attestation: 'none',
      authenticatorSelection: { residentKey: 'discouraged', userVerification: 'discouraged' },
      excludeCredentials: u.webauthn.map(k => ({ type: 'public-key', id: k.id })),
    } });
  });

  router.post('/api/mfa/webauthn/register', async ({ req, res, session }) => {
    if (!session || !session.username) return httpLib.forbidden(res);
    const b = await parseBody(req, { limitBytes: 32 * 1024 });
    const e = enroll.get(session.username);
    if (!e || !e.challenge) return send(res, 400, { error: 'no pending registration' });
    const challenge = e.challenge; delete e.challenge;
    let reg;
    try {
      const ctx = rpContext(req);
      reg = wa.verifyRegistration(b, { challenge, origins: ctx.origins, rpId: ctx.rpId });
    } catch (err) { return send(res, 400, { error: 'registration failed: ' + err.message }); }
    const name = String(b.name || 'Security key').replace(/[^\p{L}\p{N} _.\-]/gu, '').slice(0, 40) || 'Security key';
    let codes = null, dup = false;
    store.update(session.username, (u) => {
      if (u.webauthn.some(k => k.id === reg.credentialId)) { dup = true; return u; }
      u.webauthn.push({ id: reg.credentialId, name, publicKeyPem: reg.publicKeyPem, alg: reg.alg, counter: reg.counter, createdAt: new Date().toISOString() });
      if (!u.recovery || !u.recovery.length) { const r = store.newRecoveryCodes(); codes = r.codes; u.recovery = r.hashes; }
      return u;
    });
    if (dup) return send(res, 409, { error: 'already registered' });
    logEvent('auth.mfa.enabled', { username: session.username, method: 'webauthn' }, 'auth');
    return send(res, 200, { ok: true, recoveryCodes: codes });
  });

  router.post('/api/mfa/webauthn/delete', async ({ req, res, session }) => {
    if (!session || !session.username) return httpLib.forbidden(res);
    const b = await parseBody(req, { limitBytes: 2048 });
    if (!needPassword(session, b.password)) return send(res, 403, { error: 'bad password' });
    store.update(session.username, (u) => { u.webauthn = u.webauthn.filter(k => k.id !== b.id); return u; });
    logEvent('auth.mfa.disabled', { username: session.username, method: 'webauthn' }, 'auth');
    return send(res, 200, { ok: true });
  });

  router.post('/api/mfa/recovery/regenerate', async ({ req, res, session }) => {
    if (!session || !session.username) return httpLib.forbidden(res);
    const b = await parseBody(req, { limitBytes: 2048 });
    if (!needPassword(session, b.password)) return send(res, 403, { error: 'bad password' });
    if (!store.isEnabled(session.username)) return send(res, 400, { error: 'mfa not enabled' });
    const r = store.newRecoveryCodes();
    store.update(session.username, (u) => { u.recovery = r.hashes; return u; });
    return send(res, 200, { ok: true, recoveryCodes: r.codes });
  });

  // Administration : état MFA des comptes + réinitialisation (perte de téléphone/clé).
  router.get('/api/mfa/users', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    const users = (auth.getUsers() || []).map(u => ({ username: u.username, ...store.status(u.username) }));
    return send(res, 200, { users });
  });
  router.post('/api/mfa/admin/reset', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    const b = await parseBody(req, { limitBytes: 2048 });
    const target = String(b.username || '');
    if (!/^[A-Za-z0-9._@-]{1,64}$/.test(target)) return send(res, 400, { error: 'bad username' });
    const db = store.load();
    delete db.users[target]; store.save(db);
    logEvent('auth.mfa.reset', { username: target, by: session.username }, 'auth');
    return send(res, 200, { ok: true });
  });
}

const isEnabledFor = (u) => store.isEnabled(u);
module.exports = { isEnabledFor, register, maybeHandle, startChallenge, setEventLogger, rpContext, _pending: pending };
