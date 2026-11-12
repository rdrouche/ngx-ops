'use strict';
/**
 * Routes generiques du cycle de vie des conteneurs (#104, #105) — voir lib/container-lifecycle.js.
 *  - GET  /api/managed-containers/overview        statut + retard d'image de chaque conteneur declare
 *  - GET  /api/managed-containers/status?id=      statut d'un conteneur
 *  - POST /api/managed-containers/action          { id, action } : start|restart|recreate|check|update|stop|down
 *  - POST /api/managed-containers/update-all      { image, apply } : un pull par image, recree les conteneurs en retard
 * Permission : deploiement (comme les routes historiques de chaque integration, qui restent en place).
 */
const httpLib = require('../lib/http');
const auth = require('../lib/auth');
const events = require('../lib/events');
const lifecycle = require('../lib/container-lifecycle');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;

function fail(res, id, e) {
  const d = id && lifecycle.get(id);
  const mapped = d && typeof d.mapError === 'function' ? d.mapError(e) : null;
  if (mapped) return send(res, mapped.status, mapped.body);
  if (e && e.status && e.code) return send(res, e.status, { error: e.code, message: e.message });
  return httpLib.serverError(res, e);
}

function register(router) {
  router.get('/api/managed-containers/overview', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    try { return send(res, 200, { containers: await lifecycle.overview() }); } catch (e) { return fail(res, null, e); }
  });

  router.get('/api/managed-containers/status', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const d = lifecycle.get(url.searchParams.get('id'));
    if (!d) return httpLib.badRequest(res, 'unknown id');
    try {
      return send(res, 200, await lifecycle.status(d));
    } catch (e) { return fail(res, d.id, e); }
  });

  router.post('/api/managed-containers/action', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const id = body && typeof body.id === 'string' ? body.id : '';
    if (!lifecycle.get(id)) return httpLib.badRequest(res, 'unknown id');
    try {
      const r = await lifecycle.act(id, body.action);
      events.logEvent(`container.${body.action}`, `${id} : ${body.action}${r.recreated ? ' (recree)' : ''}${r.noop ? ' (sans effet)' : ''}`, session.username);
      return send(res, 200, r);
    } catch (e) { return fail(res, id, e); }
  });

  router.post('/api/managed-containers/update-all', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.DEPLOY)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const image = body && typeof body.image === 'string' && body.image.length <= 300 ? body.image : undefined;
    try {
      const r = await lifecycle.updateAll({ image, apply: body && body.apply === true });
      if (body && body.apply === true) events.logEvent('container.update_all', `${image || 'toutes les images'} : ${r.groups.map((g) => g.results.filter((x) => x.recreated).map((x) => x.id).join('+') || '-').join(' ; ')}`, session.username);
      return send(res, 200, r);
    } catch (e) { return fail(res, null, e); }
  });
}

module.exports = { register };
