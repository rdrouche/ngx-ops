'use strict';
/**
 * Feature auth : connexion mot de passe + TOTP, sessions, changement de mot de passe, enrôlement MFA.
 * Messages d'erreur génériques (pas d'énumération de comptes), verrouillage progressif, rotation de session.
 */
const { API_PREFIX, APP_VERSION } = require('../../lib/config');
const { verifyPassword, DUMMY_HASH } = require('../../lib/crypto');
const { verifyTotp, generateSecret, otpauthUri } = require('../../lib/totp');
const { cookieString } = require('../../lib/http');
const { ROLES } = require('../../lib/perms');
const { createUsers, checkPassword } = require('./users');
const { ensureBootstrapAdmin } = require('./bootstrap');

module.exports = {
  name: 'auth',
  version: '1',
  async register(ctx) {
    const { router, config, sessions, audit, HttpError, reply } = ctx;
    const users = createUsers(ctx.db, ctx.key);
    ctx.services.set('users', users);
    await ensureBootstrapAdmin({ users, config, banner: ctx.banner, log: ctx.log, env: process.env });
    const secure = config.server.cookie_secure;
    const A = `${API_PREFIX}/auth`;
    const sec = config.security;

    const startSession = async (user, state, ip) => {
      const s = await sessions.create({ userId: user.id, state, ip });
      return { s, cookie: cookieString(sessions.COOKIE, s.sid, { maxAge: s.maxAgeSec, secure }) };
    };
    const describe = (session, user) => ({
      state: session.state,
      csrf: session.csrf,
      user: { username: session.username, role: session.role },
      mfa_enabled: !!(user ? user.mfa_enabled : session.mfaEnabled),
      mfa_policy: sec.mfa_policy,
      perms: session.state === 'active' ? ROLES[session.role] || [] : [],
      ui: { default_theme: config.ui.default_theme, default_language: config.ui.default_language, dashboard_deeplink_path: config.ui.dashboard_deeplink_path },
      version: APP_VERSION,
    });
    /** État de session après authentification par mot de passe. */
    const nextState = (user) => (user.mfa_enabled ? 'mfa' : (sec.mfa_policy === 'required' ? 'enroll' : 'active'));
    const fail = () => new HttpError(401, 'Identifiants invalides', 'invalid_credentials');

    router.post(`${A}/login`, { auth: false, rate: { key: 'login', max: 20, windowMs: 5 * 60_000 } }, async ({ body, ip }) => {
      const username = String(body.username || '').slice(0, 64);
      const password = String(body.password || '').slice(0, 300);
      const user = await users.getByName(username);
      if (!user || user.disabled || users.isLocked(user)) {
        verifyPassword(password, DUMMY_HASH); // égalise le temps de réponse
        await audit(username, 'login.failed', null, ip, { reason: !user ? 'unknown' : 'locked_or_disabled' });
        throw fail();
      }
      if (!verifyPassword(password, user.pass_hash)) {
        const locked = await users.recordFailure(user, sec.login_max_failures, sec.login_lock_minutes);
        await audit(username, locked ? 'login.locked' : 'login.failed', null, ip);
        throw fail();
      }
      await users.recordSuccess(user.id);
      const state = user.must_change_password ? 'pwchange' : nextState(user);
      const { s, cookie } = await startSession(user, state, ip);
      await audit(username, state === 'active' ? 'login.ok' : 'login.password_ok', null, ip, { state });
      return reply(200, describe({ state, csrf: s.csrf, username: user.username, role: user.role }, user), { 'Set-Cookie': cookie });
    });

    router.post(`${A}/mfa/verify`, { states: ['mfa'], rate: { key: 'mfa', max: 15, windowMs: 5 * 60_000 } }, async ({ body, session, ip }) => {
      const user = await users.getById(session.userId);
      const secret = users.getMfaSecret(user);
      const r = secret ? verifyTotp(secret, body.code, { lastStep: user.mfa_last_step }) : { ok: false };
      if (!r.ok) {
        const locked = await users.recordFailure(user, sec.login_max_failures, sec.login_lock_minutes);
        await audit(user.username, locked ? 'mfa.locked' : 'mfa.failed', null, ip);
        if (locked) await sessions.destroyAllForUser(user.id);
        throw new HttpError(401, 'Code invalide', 'invalid_code');
      }
      await users.recordSuccess(user.id);
      await users.updateMfaStep(user.id, r.step);
      await sessions.destroy(session.idHash); // rotation : l'identifiant « en attente » est détruit
      const { s, cookie } = await startSession(user, 'active', ip);
      await audit(user.username, 'login.ok', null, ip);
      return reply(200, describe({ state: 'active', csrf: s.csrf, username: user.username, role: user.role }, user), { 'Set-Cookie': cookie });
    });

    router.get(`${A}/me`, { states: ['active', 'mfa', 'enroll', 'pwchange'] }, async ({ session }) => describe(session));

    router.post(`${A}/logout`, { states: ['active', 'mfa', 'enroll', 'pwchange'] }, async ({ session, ip }) => {
      await sessions.destroy(session.idHash);
      await audit(session.username, 'logout', null, ip);
      return reply(200, { ok: true }, { 'Set-Cookie': cookieString(sessions.COOKIE, '', { maxAge: 0, secure }) });
    });

    router.post(`${A}/mfa/enroll`, { states: ['active', 'enroll'], rate: { key: 'mfa-enroll', max: 10, windowMs: 10 * 60_000 } }, async ({ session, ip }) => {
      const user = await users.getById(session.userId);
      if (user.mfa_enabled) throw new HttpError(409, 'MFA déjà activé (réinitialisation par un administrateur via la CLI)', 'mfa_already_enabled');
      const secret = generateSecret();
      await users.beginMfaEnrollment(user.id, secret);
      await audit(user.username, 'mfa.enroll_started', null, ip);
      return { secret, otpauth_uri: otpauthUri(secret, user.username) };
    });

    router.post(`${A}/mfa/confirm`, { states: ['active', 'enroll'], rate: { key: 'mfa-confirm', max: 10, windowMs: 10 * 60_000 } }, async ({ body, session, ip }) => {
      const user = await users.getById(session.userId);
      if (user.mfa_enabled) throw new HttpError(409, 'MFA déjà activé', 'mfa_already_enabled');
      const secret = users.getMfaSecret(user);
      if (!secret) throw new HttpError(409, 'Aucun enrôlement en cours', 'no_enrollment');
      const r = verifyTotp(secret, body.code, { lastStep: 0 });
      if (!r.ok) throw new HttpError(401, 'Code invalide', 'invalid_code');
      await users.enableMfa(user.id, r.step);
      await sessions.destroyAllForUser(user.id);
      const { s, cookie } = await startSession(user, 'active', ip);
      await audit(user.username, 'mfa.enabled', null, ip);
      return reply(200, describe({ state: 'active', csrf: s.csrf, username: user.username, role: user.role }, { ...user, mfa_enabled: 1 }), { 'Set-Cookie': cookie });
    });

    router.post(`${A}/password`, { states: ['active', 'enroll', 'pwchange'], rate: { key: 'pw', max: 10, windowMs: 10 * 60_000 } }, async ({ body, session, ip }) => {
      const user = await users.getById(session.userId);
      if (!verifyPassword(String(body.current || ''), user.pass_hash)) throw new HttpError(401, 'Mot de passe actuel incorrect', 'invalid_credentials');
      const bad = checkPassword(body.next);
      if (bad) throw new HttpError(400, bad, 'weak_password');
      if (body.next === body.current) throw new HttpError(400, 'le nouveau mot de passe doit être différent', 'weak_password');
      await users.setPassword(user.id, body.next);
      await sessions.destroyAllForUser(user.id);
      const target = session.state === 'pwchange' ? nextState(user) : session.state;
      const { s, cookie } = await startSession(user, target, ip);
      await audit(user.username, 'password.changed', null, ip);
      return reply(200, describe({ state: target, csrf: s.csrf, username: user.username, role: user.role }, user), { 'Set-Cookie': cookie });
    });
  },
};
