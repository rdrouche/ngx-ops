'use strict';
/**
 * Feature logstore (#62) : le Hub lit les AGRÉGATS du log store (pull, lecture seule, jeton `read`).
 * Pas de logs bruts, pas d'IP : voir model.js. Désactivée par défaut (logstore.enabled + url + HUB_LOGSTORE_TOKEN).
 *   GET /api/hub/v1/logstore/status                       configuration (sans appel sortant)
 *   GET /api/hub/v1/logstore/overview?hours=&instance=    visites, sécurité, tops, instances (cache logstore.cache_s)
 *   GET /api/hub/v1/logstore/explorer/events?…            recherche de logs bruts (#107, opt-in logstore.explorer.enabled, admin)
 *   GET /api/hub/v1/logstore/explorer/top?dimension=&…      classement (règles, chemins, UA, pays…) pour la vue attaques (#107, idem)
 *   GET /api/hub/v1/logstore/explorer/campaigns?hours=&min_ips=  signatures d'attaque vues depuis plusieurs IP (#107, idem, ≤ 7 j)
 *   GET /api/hub/v1/logstore/explorer/ip?ip=&hours=       fiche d'une IP, toutes instances et sites (#107, idem)
 */
const { API_PREFIX } = require('../../lib/config');
const { parseInstanceUrl } = require('../../lib/security');
const { readToken, fetchParts, fetchCorrelation } = require('./client');
const { shapeIps, union, merge } = require('./correlation');
const { shapeOverview, INSTANCE_RE } = require('./model');
const { fetchEvents, fetchIpHistory, fetchTop, fetchCampaigns } = require('./client');
const { buildEventsQuery, buildTopQuery, buildCampaignsQuery, shapeCampaigns, shapeEvents, shapeIpHistory, shapeTop, validIpKey } = require('./explorer');
const net = require('node:net');

const P = API_PREFIX;
const MAX_CACHE = 64;

module.exports = {
  name: 'logstore',
  version: '1',
  register(ctx) {
    const { config, router, perms } = ctx;
    const ls = config.logstore;
    const token = readToken();
    const url = ls.url ? parseInstanceUrl(ls.url, config.security) : { ok: false };
    const state = () => ({ enabled: ls.enabled === true, configured: ls.enabled === true && !!token && url.ok === true });
    const cache = new Map();

    router.get(`${P}/logstore/status`, { perm: perms.VIEW }, async () => {
      const s = state();
      return { ...s, host: s.configured ? url.host : null, hours: ls.hours, indicators: s.configured && ls.indicators.enabled, explorer: s.configured && ls.explorer.enabled,
        problem: !s.enabled ? null : !ls.url ? 'url_missing' : !url.ok ? 'url_invalid' : !token ? 'token_missing' : null };
    });

    // #62 : corrélation par IP (log store + indicateurs des dashboards). Opt-in, admin seulement, rien n'est stocké ni journalisé (compteurs dans l'audit).
    const corr = { at: 0, body: null };
    router.get(`${P}/logstore/correlation`, { perm: perms.INDICATORS_VIEW, rate: { key: 'logstore-correlation', max: 20, windowMs: 60_000 } }, async ({ session, ip }) => {
      if (!state().configured || !ls.indicators.enabled) throw new ctx.HttpError(404, 'Corrélation par IP (log store) désactivée (logstore.indicators.enabled)', 'not_found');
      let body = Date.now() - corr.at < ls.cache_s * 1000 ? corr.body : null;
      if (!body) {
        const { raws, errors } = await fetchCorrelation({ config: { ...config, logstore: { ...ls, url: url.url } }, token });
        const lsItems = union(raws.map(shapeIps));
        const modules = ctx.services.get('modules'); // facultatif : feature désactivée = pas d'indicateurs de dashboards
        let dashItems = []; try { dashItems = modules && modules.indicatorItems ? await modules.indicatorItems() : []; } catch { dashItems = []; }
        const items = merge(dashItems, lsItems, { limit: ls.indicators.limit });
        body = { items, window_hours: ls.indicators.hours, generated_at: Date.now(), partial: errors.length > 0, errors, dashboards: dashItems.length, logstore: lsItems.length };
        if (raws.length) { corr.at = Date.now(); corr.body = body; } // cache mémoire court, jamais en base
      }
      await ctx.audit(session.username, 'logstore.correlation.view', null, ip, { count: body.items.length }); // jamais d'adresse dans l'audit
      return body;
    });

    // #107 : explorateur (logs bruts, IP). Relais sans stockage, opt-in, admin, débit limité ; l'audit ne reçoit jamais de valeur de filtre ni d'adresse.
    const EXPLORER_ERR = { auth_failed: 'Jeton du log store refusé', timeout: 'Le log store ne répond pas à temps', rate_limited: 'Le log store limite le débit, réessayez', too_large: 'Réponse du log store trop volumineuse' };
    const explorerOn = () => {
      if (!state().configured || ls.explorer.enabled !== true) throw new ctx.HttpError(404, 'Explorateur de logs (log store) désactivé (logstore.explorer.enabled)', 'not_found');
    };
    const explorerFail = (e) => {
      if (e && e.code === 'bad_filter') throw new ctx.HttpError(400, `Filtre invalide : ${e.field}`, 'bad_filter');
      throw new ctx.HttpError(502, EXPLORER_ERR[e && e.code] || (/^http_4\d\d$/.test((e && e.code) || '') ? 'Requête refusée par le log store' : 'Log store injoignable ou en erreur'), 'logstore_error');
    };
    const rateEv = { key: 'logstore-explorer', max: 60, windowMs: 60_000 };
    router.get(`${P}/logstore/explorer/events`, { perm: perms.INDICATORS_VIEW, rate: rateEv }, async ({ session, ip, query }) => {
      explorerOn();
      let built;
      try { built = buildEventsQuery(query, { maxLimit: 500, defaultLimit: ls.explorer.page_size }); } catch (e) { explorerFail(e); }
      let raw;
      try { raw = await fetchEvents({ config: { ...config, logstore: { ...ls, url: url.url } }, token, query: built.query }); } catch (e) { explorerFail(e); }
      const body = shapeEvents(raw, built.query.limit);
      await ctx.audit(session.username, 'logstore.explorer.search', null, ip, { filters: built.used, count: body.events.length });
      return { ...body, hours: Number.parseInt(built.query.since, 10), limit: built.query.limit };
    });
    router.get(`${P}/logstore/explorer/top`, { perm: perms.INDICATORS_VIEW, rate: rateEv }, async ({ session, ip, query }) => {
      explorerOn();
      let built;
      try { built = buildTopQuery(query); } catch (e) { explorerFail(e); }
      let raw;
      try { raw = await fetchTop({ config: { ...config, logstore: { ...ls, url: url.url } }, token, query: built.query }); } catch (e) { explorerFail(e); }
      const body = shapeTop(raw, built.dimension);
      await ctx.audit(session.username, 'logstore.explorer.top', null, ip, { filters: built.used, count: body.items.length });
      return { ...body, hours: Number.parseInt(built.query.since, 10) };
    });
    router.get(`${P}/logstore/explorer/campaigns`, { perm: perms.INDICATORS_VIEW, rate: rateEv }, async ({ session, ip, query }) => {
      explorerOn();
      let built;
      try { built = buildCampaignsQuery(query); } catch (e) { explorerFail(e); }
      let raw;
      try { raw = await fetchCampaigns({ config: { ...config, logstore: { ...ls, url: url.url } }, token, query: built.query }); } catch (e) { explorerFail(e); }
      const body = shapeCampaigns(raw);
      await ctx.audit(session.username, 'logstore.explorer.campaigns', null, ip, { filters: built.used, count: body.items.length });
      return { ...body, hours: Number.parseInt(built.query.since, 10) };
    });
    router.get(`${P}/logstore/explorer/ip`, { perm: perms.INDICATORS_VIEW, rate: rateEv }, async ({ session, ip, query }) => {
      explorerOn();
      const target = typeof query.ip === 'string' ? query.ip : '';
      if (!target || !(net.isIP(target) !== 0 || (validIpKey(target) && !target.includes('/')))) throw new ctx.HttpError(400, 'Filtre invalide : ip', 'bad_filter'); // pas de /24 : le chemin d'URL du log store n'en accepte pas
      let built;
      try { built = buildEventsQuery({ hours: query.hours, limit: query.limit, instance: query.instance }, { maxLimit: 500, defaultLimit: ls.explorer.page_size }); } catch (e) { explorerFail(e); }
      let raw;
      try { raw = await fetchIpHistory({ config: { ...config, logstore: { ...ls, url: url.url } }, token, ip: target, query: built.query }); } catch (e) { explorerFail(e); }
      const body = shapeIpHistory(raw, built.query.limit);
      await ctx.audit(session.username, 'logstore.explorer.ip', null, ip, { count: body.events.length, total: body.summary.total });
      return body;
    });

    router.get(`${P}/logstore/overview`, { perm: perms.VIEW, rate: { key: 'logstore-overview', max: 30, windowMs: 60_000 } }, async ({ query }) => {
      if (!state().configured) return { enabled: false };
      const hours = Math.min(744, Math.max(1, Number.parseInt(query.hours, 10) || ls.hours));
      const instance = query.instance ? String(query.instance) : '';
      if (instance && !INSTANCE_RE.test(instance)) throw new ctx.HttpError(400, 'Instance invalide', 'bad_instance');
      const key = `${hours}|${instance}`;
      const hit = cache.get(key);
      if (hit && Date.now() - hit.at < ls.cache_s * 1000) return hit.body;
      const { parts, errors } = await fetchParts({ config: { ...config, logstore: { ...ls, url: url.url } }, token, hours, instance });
      const failed = Object.keys(errors).length;
      const body = { enabled: true, generated_at: new Date().toISOString(), hours, instance: instance || null, partial: failed > 0, errors, ...shapeOverview(parts) };
      if (body.visits) { // un échec des visites (panne, jeton refusé) n'est jamais mis en cache
        if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value);
        cache.set(key, { at: Date.now(), body });
      }
      return body;
    });
  },
};
