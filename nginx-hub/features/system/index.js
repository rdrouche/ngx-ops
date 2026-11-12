'use strict';
/** Feature system : sonde de santé publique minimale + métadonnées de version (authentifiées). */
const { APP_VERSION, API_VERSION, API_PREFIX, SUMMARY_SCHEMA_MAX } = require('../../lib/config');
const { schemaVersion } = require('../../lib/store');
const { createMaintenance } = require('../../lib/store/maintenance');

module.exports = {
  name: 'system',
  version: '1',
  register(ctx) {
    // Sonde publique : volontairement sans version ni détail (pas de fingerprinting).
    ctx.router.get('/healthz', { auth: false }, async () => {
      await ctx.db.get('SELECT 1 AS ok');
      return { status: 'ok' };
    });

    ctx.router.get(`${API_PREFIX}/version`, { perm: ctx.perms.VIEW }, async () => ({
      app: 'ngx-ops-hub',
      version: APP_VERSION,
      api: API_VERSION,
      summary_schema_max: SUMMARY_SCHEMA_MAX,
      db_schema: await schemaVersion(ctx.db),
      features: ctx.features.map((f) => f.name),
    }));

    // #96 : maintenance de la base (PostgreSQL : VACUUM ANALYZE ; SQLite : checkpoint, optimize, VACUUM, quick_check).
    const pg = (ctx.config.storage || {}).postgres || {};
    const hours = ctx.db.dialect === 'postgres' ? pg.maintenance_hours : (ctx.config.storage || {}).sqlite_maintenance_hours;
    const maint = createMaintenance({ db: ctx.db, logger: ctx.log, intervalMs: (Number(hours) || 0) * 3_600_000 });
    maint.start(ctx.onStop);
    ctx.services.set('maintenance', maint);

    ctx.router.get(`${API_PREFIX}/system/maintenance`, { perm: ctx.perms.MAINTENANCE }, async () => maint.status());
    ctx.router.post(`${API_PREFIX}/system/maintenance`, { perm: ctx.perms.MAINTENANCE, rate: { key: 'system-maintenance', max: 5, windowMs: 60_000 } }, async ({ session, ip }) => {
      if (!maint.supported) throw new ctx.HttpError(409, 'Maintenance non disponible pour ce stockage', 'unsupported');
      if ((await maint.status()).running) throw new ctx.HttpError(409, 'Maintenance déjà en cours', 'busy');
      await ctx.audit(session.username, 'system.maintenance.run', null, ip, null);
      maint.run('manual').catch(() => {}); // long : on ne l'attend pas, l'avancement se lit via GET
      return ctx.reply(202, { started: true });
    });
  },
};
