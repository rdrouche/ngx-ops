'use strict';
/**
 * Visibilite des elements de menu optionnels (WAF, GoDNS, ...) — voir
 * lib/menu-visibility.js pour la logique de resolution (env > menu.yml >
 * defaut) et config/menu.yml pour les reglages persistes.
 *
 * Une seule route, en lecture seule, exposee a TOUS les roles authentifies
 * (permission VIEW_CONFIGS, que viewer/operator/admin possedent tous les
 * trois) — contrairement a features/system-info.js (ADMIN uniquement, la
 * configuration complete du dashboard), un viewer a lui aussi besoin de
 * savoir quels elements du menu afficher ou masquer au chargement de la
 * page (public/index.html#checkOptionalFeatures()).
 */
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const { resolveMenuVisibility, getMenuForm, saveMenuForm } = require('../lib/menu-visibility');
const { logEvent } = require('../lib/events');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;

function register(router) {
  router.get('/api/menu-visibility', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    try {
      const visibility = await resolveMenuVisibility();
      return send(res, 200, visibility);
    } catch (e) {
      return httpLib.serverError(res, e);
    }
  });

  // v12.72.0 : formulaire "Menu" (page Systeme) — admin uniquement. Ecrit
  // config/menu.yml (meme fichier que l'edition manuelle, qui reste valable).
  router.get('/api/menu-config', async ({ res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    return send(res, 200, { items: getMenuForm() });
  });
  router.post('/api/menu-config/save', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.ADMIN)) return httpLib.forbidden(res);
    const body = await parseBody(req, { limitBytes: 16 * 1024 });
    try {
      const r = saveMenuForm(body.values);
      if (!r.ok) return httpLib.badRequest(res, r.error);
      logEvent('menu.config_saved', `Menu mis a jour (${r.written.length} reglage(s))`, session.username);
      return send(res, 200, { ok: true, written: r.written, items: getMenuForm() });
    } catch (e) {
      return httpLib.serverError(res, e);
    }
  });
}

module.exports = { register };
