'use strict';
/** Feature instances : inventaire (CRUD), rotation de token, rafraîchissement manuel, historique. */
const { API_PREFIX } = require('../../lib/config');
const { createInstancesRepo } = require('./repo');
const { validateInstanceInput } = require('./validate');
const { toDto } = require('./dto');

module.exports = {
  name: 'instances',
  version: '1',
  async register(ctx) {
    const { router, config, audit, HttpError, reply, perms } = ctx;
    const repo = createInstancesRepo(ctx.db, ctx.key);
    ctx.services.set('instances', repo);
    const B = `${API_PREFIX}/instances`;
    const policy = config.security;
    const load = async (id) => {
      const n = Number(id);
      const row = Number.isInteger(n) ? await repo.get(n) : null;
      if (!row) throw new HttpError(404, 'Instance inconnue', 'not_found');
      return row;
    };
    /** Aide à la configuration du dashboard : seul le hash est à y déposer. */
    const tokenReveal = (t) => ({ token_once: t.token, token_sha256: repo.tokenSha256(t.token), token_generated: t.generated });

    router.get(B, { perm: perms.VIEW }, async () => ({ items: (await repo.list()).map((r) => toDto(r, config)) }));

    router.get(`${B}/:id`, { perm: perms.VIEW }, async ({ params }) => toDto(await load(params.id), config, { detail: true }));

    router.post(B, { perm: perms.INSTANCES_WRITE, rate: { key: 'inst-write', max: 60, windowMs: 60_000 } }, async ({ body, session, ip }) => {
      const v = validateInstanceInput(body, policy);
      if (!v.ok) throw new HttpError(400, v.error, 'invalid_input');
      const t = await repo.create(v.value);
      await audit(session.username, 'instance.create', v.value.name, ip, { id: t.id, url: v.value.url });
      return reply(201, { instance: toDto(await repo.get(t.id), config), ...tokenReveal(t) });
    });

    router.patch(`${B}/:id`, { perm: perms.INSTANCES_WRITE }, async ({ params, body, session, ip }) => {
      const row = await load(params.id);
      if (body.token !== undefined) throw new HttpError(400, 'utiliser /rotate-token pour changer le token', 'invalid_input');
      const v = validateInstanceInput(body, policy, { partial: true });
      if (!v.ok) throw new HttpError(400, v.error, 'invalid_input');
      await repo.update(row.id, v.value);
      await audit(session.username, 'instance.update', row.name, ip, { id: row.id, fields: Object.keys(v.value) });
      return toDto(await repo.get(row.id), config);
    });

    router.delete(`${B}/:id`, { perm: perms.INSTANCES_WRITE }, async ({ params, session, ip }) => {
      const row = await load(params.id);
      await repo.remove(row.id);
      await audit(session.username, 'instance.delete', row.name, ip, { id: row.id });
      return { ok: true };
    });

    router.post(`${B}/:id/rotate-token`, { perm: perms.INSTANCES_WRITE, rate: { key: 'inst-rotate', max: 20, windowMs: 60_000 } }, async ({ params, body, session, ip }) => {
      const row = await load(params.id);
      const v = validateInstanceInput({ name: row.name, url: row.base_url, token: body.token }, { ...policy, allow_insecure_http: true, allow_private_networks: true });
      if (!v.ok) throw new HttpError(400, v.error, 'invalid_input');
      const t = await repo.rotateToken(row.id, v.value.token);
      await audit(session.username, 'instance.rotate_token', row.name, ip, { id: row.id });
      return tokenReveal(t);
    });

    router.post(`${B}/:id/refresh`, { perm: perms.REFRESH, rate: { key: 'inst-refresh', max: 30, windowMs: 60_000 } }, async ({ params }) => {
      const row = await load(params.id);
      const collector = ctx.services.get('collector');
      if (!collector) throw new HttpError(503, 'Collecteur désactivé', 'collector_disabled');
      await collector.pollOne(row.id);
      return toDto(await repo.get(row.id), config, { detail: true });
    });

    router.get(`${B}/:id/history`, { perm: perms.VIEW }, async ({ params, query }) => {
      const row = await load(params.id);
      const range = repo.RANGES[query.range] ? query.range : '24h';
      return { range, points: await repo.history(row.id, range) };
    });
  },
};
