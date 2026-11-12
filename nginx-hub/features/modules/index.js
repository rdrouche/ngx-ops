'use strict';
/**
 * Feature modules (contrat dashboard 12.78.0) : alertes détaillées + 7 modules de données interrogés en pull, lecture seule.
 *  - alerts : rattrapage fiable par `sinceId` (order=asc, boucle), stockage par alerte, état « acquittée » rafraîchi ;
 *  - inventory / traffic / security / ops / monitoring / reports : dernier état conservé par (instance, module) ;
 *  - indicators (corrélation par IP) : OPT-IN explicite (modules.indicators.enabled) + expose_ips côté dashboard ;
 *    consultation réservée aux admins (données personnelles), jamais écrit dans les journaux ni l'audit.
 * Un module 404 est « absent » (désactivé côté dashboard : le Hub ne distingue pas) ; une partie en échec n'est jamais lue comme « zéro ».
 */
const { API_PREFIX } = require('../../lib/config');
const { fetchJson } = require('../collector/fetcher');
const { extractVhosts } = require('./vhosts');
const { createModulesRepo } = require('./repo');
const { clean, normAlert, normEnvelope } = require('./sanitize');
const { correlate } = require('./correlate');

const P = API_PREFIX;
const ALL = ['alerts', 'inventory', 'traffic', 'security', 'ops', 'monitoring', 'reports', 'indicators'];
const PARAMS = { traffic: { limit: 25 }, indicators: { limit: 500 } };
const parseJson = (s) => { try { return s ? JSON.parse(s) : null; } catch { return null; } };

module.exports = {
  name: 'modules',
  version: '1',
  depends: ['instances'],
  async register(ctx) {
    const { router, config, audit, HttpError, perms, log } = ctx;
    const cfg = config.modules;
    if (!cfg.enabled) return;
    const instances = ctx.services.get('instances');
    const repo = createModulesRepo(ctx.db);
    const wanted = () => [...cfg.list, ...(cfg.indicators.enabled ? ['indicators'] : [])];

    /** @returns {Promise<void>} ne rejette jamais : l'échec est enregistré par (instance, module). */
    async function pollModule(row, module) {
      const now = Date.now();
      const target = { baseUrl: row.base_url, token: instances.getToken(row) };
      try {
        if (module === 'alerts') return await pullAlerts(row, target, now);
        const { data } = await fetchJson(target, config, {
          path: `${P}/${module}`, query: { hours: cfg.hours, ...(PARAMS[module] || {}) }, maxBytes: cfg.max_module_bytes, timeoutMs: Math.max(config.collector.timeout_ms, 10_000),
        });
        const env = normEnvelope(data);
        if (!env) { const e = new Error('bad_json'); e.code = 'bad_json'; throw e; }
        const payload = JSON.stringify({ data: env.data });
        if (payload.length > cfg.max_module_bytes) { const e = new Error('too_large'); e.code = 'too_large'; throw e; }
        return await repo.saveOk(row.id, module, now, { expose: env.expose_ips, errors: env.errors, payload });
      } catch (e) {
        const code = (e && e.code && /^[a-z_0-9]+$/i.test(e.code)) ? e.code : 'connection';
        const status = code === 'not_supported' ? 'absent' : code === 'ips_disabled' ? 'ips_disabled' : 'error';
        await repo.saveFail(row.id, module, now, status, status === 'error' ? code : null);
        if (status === 'error') log.debug('module en échec', { instance: row.slug, module, reason: code });
        return undefined;
      }
    }

    async function pullAlerts(row, target, now) {
      let last = await repo.lastId(row.id);
      let reachable = null; let remoteTotal = null;
      const opt = (query) => ({ path: `${P}/alerts`, query, maxBytes: cfg.max_module_bytes, timeoutMs: Math.max(config.collector.timeout_ms, 10_000) });
      for (let i = 0; i < 10; i++) { // rattrapage : pas de perte au-delà de `limit`
        const { data } = await fetchJson(target, config, opt({ limit: cfg.alerts_batch, sinceId: last, order: 'asc' }));
        const list = Array.isArray(data && data.alerts) ? data.alerts.slice(0, cfg.alerts_batch) : [];
        reachable = data && typeof data.reachable === 'boolean' ? data.reachable : reachable;
        remoteTotal = Number.isFinite(data && data.total) ? data.total : remoteTotal;
        for (const a of list) {
          const n = normAlert(a, data.expose_ips === true);
          if (!n) continue;
          await repo.upsertAlert(row.id, n);
          if (n.remote_id > last) last = n.remote_id;
        }
        if (list.length < cfg.alerts_batch) break;
      }
      await repo.setLastId(row.id, last);
      try { // les acquittements arrivent après coup : on rafraîchit les acquittées récentes
        const { data } = await fetchJson(target, config, opt({ acked: 1, limit: 200, order: 'desc', since: now - 24 * 3600e3 }));
        for (const a of (Array.isArray(data && data.alerts) ? data.alerts : []).slice(0, 200)) if (Number.isInteger(a.id)) await repo.markAcked(row.id, a.id);
      } catch { /* non bloquant */ }
      await repo.saveOk(row.id, 'alerts', now, { expose: false, errors: {}, payload: JSON.stringify({ data: { reachable, total: remoteTotal, last_id: last } }) });
    }

    let running = false;
    /** Un passage : tout (instance, module) arrivé à échéance est interrogé, concurrence bornée. */
    async function tick() {
      if (running) return;
      running = true;
      try {
        const rows = (await instances.list()).filter((r) => r.enabled && r.status !== 'offline');
        const saved = new Map((await repo.fetchTimes()).map((r) => [`${r.instance_id}:${r.module}`, Number(r.fetched_at)]));
        const now = Date.now();
        const jobs = [];
        for (const r of rows) for (const m of wanted()) {
          const last = saved.get(`${r.id}:${m}`) || 0;
          if (now - last >= cfg.intervals_s[m] * 1000 * 0.9) jobs.push([r, m]);
        }
        let i = 0;
        const worker = async () => { while (i < jobs.length) { const [r, m] = jobs[i++]; await pollModule(r, m); } };
        await Promise.all(Array.from({ length: Math.min(cfg.concurrency, jobs.length) }, worker));
      } catch (e) { log.error('cycle modules', { err: e }); } finally { running = false; }
    }

    async function refresh(instanceId) {
      const row = await instances.get(instanceId);
      if (!row) return { ok: false, error: 'not_found' };
      await Promise.all(wanted().map((m) => pollModule(row, m)));
      return { ok: true };
    }

    async function purge() {
      try { const n = await repo.purgeAlerts(Date.now() - cfg.alerts_keep_days * 86400e3); if (n) log.info('purge alertes', { removed: n }); } catch (e) { log.error('purge alertes', { err: e }); }
    }

    const indicatorItems = async () => (cfg.indicators.enabled ? correlate(await repo.indicatorRows(), { maxAgeMs: cfg.intervals_s.indicators * 1000 * 3 }) : []);
    ctx.services.set('modules', { tick, refresh, pollModule, purge, repo, indicatorItems }); // indicatorItems : utilisé par la feature logstore (#62)

    // ---- API ------------------------------------------------------------------------------------------------------
    const canIps = (session) => ctx.hasPerm(session, perms.INDICATORS_VIEW);
    const loadInstance = async (id) => {
      const n = Number(id); const row = Number.isInteger(n) ? await instances.get(n) : null;
      if (!row) throw new HttpError(404, 'Instance inconnue', 'not_found');
      return row;
    };

    router.get(`${P}/instances/:id/modules`, { perm: perms.VIEW }, async ({ params }) => {
      const row = await loadInstance(params.id);
      return {
        enabled: wanted(), indicators_enabled: !!cfg.indicators.enabled,
        items: (await repo.rows(row.id)).map((r) => ({
          module: r.module, status: r.status, fetched_at: Number(r.fetched_at), last_ok_at: r.last_ok_at ? Number(r.last_ok_at) : null, error: r.error,
          expose_ips: !!r.expose_ips, parts_errors: parseJson(r.parts_errors) || {},
        })),
      };
    });

    router.get(`${P}/instances/:id/modules/:name`, { perm: perms.VIEW }, async ({ params, session }) => {
      if (!ALL.includes(params.name)) throw new HttpError(404, 'Module inconnu', 'not_found');
      if (params.name === 'indicators' && !canIps(session)) throw new HttpError(403, 'Permission insuffisante', 'forbidden');
      const row = await loadInstance(params.id);
      const m = await repo.row(row.id, params.name);
      if (!m) throw new HttpError(404, 'Module pas encore collecté', 'not_found');
      let data = (parseJson(m.payload) || {}).data ?? null;
      // sans droit « indicators:view », aucune IP ne sort, même si le dashboard en expose
      if (data && m.expose_ips && !canIps(session)) data = clean(data, false);
      const out = {
        module: m.module, status: m.status, fetched_at: Number(m.fetched_at), last_ok_at: m.last_ok_at ? Number(m.last_ok_at) : null, error: m.error,
        expose_ips: !!m.expose_ips && canIps(session), parts_errors: parseJson(m.parts_errors) || {}, data,
      };
      if (params.name === 'inventory' && data) { // liste normalisée des vhosts (voir vhosts.js), jointe au trafic quand il est connu
        const tr = await repo.row(row.id, 'traffic');
        out.derived = { vhosts: extractVhosts(data, tr ? (parseJson(tr.payload) || {}).data : null, parseJson(row.last_summary)?.top_vhosts) };
      }
      return out;
    });

    // Tous les vhosts de toutes les instances (un même vhost peut exister sur plusieurs instances). Mémo 20 s : l'analyse des charges utiles est coûteuse.
    let vhostCache = { at: 0, value: null };
    async function buildVhosts() {
      if (vhostCache.value && Date.now() - vhostCache.at < 20_000) return vhostCache.value;
      const inv = new Map((await repo.payloadsOf('inventory')).map((r) => [Number(r.instance_id), r]));
      const trf = new Map((await repo.payloadsOf('traffic')).map((r) => [Number(r.instance_id), r]));
      const sums = new Map((await repo.summaries()).map((r) => [Number(r.id), r]));
      const byName = new Map(); const missing = [];
      for (const [id, srow] of sums) {
        const i = inv.get(id); const tf = trf.get(id);
        const list = extractVhosts(i ? (parseJson(i.payload) || {}).data : null, tf ? (parseJson(tf.payload) || {}).data : null, parseJson(srow.last_summary)?.top_vhosts);
        if (!i) missing.push({ id, name: srow.name });
        for (const v of list) {
          const { name, ...rest } = v;
          const e = byName.get(name) || { name, instances: [], requests: 0, errors: 0, bytes: 0 };
          e.instances.push({ id, instance: srow.name, ...rest });
          e.requests += rest.requests || 0; e.errors += rest.errors || 0; e.bytes += rest.bytes || 0;
          byName.set(name, e);
        }
      }
      const items = [...byName.values()].map((e) => ({ ...e, instance_count: e.instances.length })).sort((a, b) => a.name.localeCompare(b.name));
      vhostCache = { at: Date.now(), value: { items, instances_total: sums.size, instances_missing: missing, generated_at: Date.now() } };
      return vhostCache.value;
    }
    router.get(`${P}/vhosts`, { perm: perms.VIEW }, async () => buildVhosts());

    router.post(`${P}/instances/:id/modules/refresh`, { perm: perms.REFRESH, rate: { key: 'mod-refresh', max: 10, windowMs: 60_000 } }, async ({ params }) => {
      const row = await loadInstance(params.id);
      return refresh(row.id);
    });

    router.get(`${P}/alerts`, { perm: perms.VIEW }, async ({ query, session }) => {
      const num = (v) => { const n = Number.parseInt(v, 10); return Number.isFinite(n) && n >= 0 ? n : 0; };
      const r = await repo.listAlerts({
        instance: num(query.instance) || null, severity: /^[a-z]{1,16}$/.test(query.severity || '') ? query.severity : null,
        type: /^[a-z0-9_.-]{1,40}$/i.test(query.type || '') ? query.type : null, acked: query.acked === '0' ? 0 : query.acked === '1' ? 1 : null,
        limit: Math.min(Math.max(num(query.limit) || 100, 1), 500), offset: num(query.offset),
      });
      const ips = canIps(session);
      return {
        total: r.total,
        items: r.items.map((a) => ({ ...a, acked: !!a.acked, evidence: parseJson(a.evidence), ips: ips ? parseJson(a.ips) || [] : undefined })),
        facets: (await repo.alertFacets()).map((f) => ({ severity: f.severity, type: f.type, acked: !!f.acked, n: Number(f.n) })),
      };
    });

    router.get(`${P}/indicators`, { perm: perms.INDICATORS_VIEW, rate: { key: 'indicators', max: 30, windowMs: 60_000 } }, async ({ session, ip }) => {
      if (!cfg.indicators.enabled) throw new HttpError(404, 'Corrélation par IP désactivée (modules.indicators.enabled)', 'not_found');
      const items = correlate(await repo.indicatorRows(), { maxAgeMs: cfg.intervals_s.indicators * 1000 * 3 });
      await audit(session.username, 'indicators.view', null, ip, { count: items.length }); // jamais d'adresse dans l'audit
      // diagnostic : état du module `indicators` par instance (permet de voir « expose_ips désactivé côté dashboard », 404, erreurs…)
      const sources = (await repo.moduleStatuses('indicators')).map((r) => ({ id: Number(r.id), name: r.name, status: r.status || 'pending', error: r.error || null }));
      return { items, window_hours: cfg.hours, generated_at: Date.now(), sources };
    });

    // ---- planification --------------------------------------------------------------------------------------------
    if (config.collector.enabled) {
      const first = setTimeout(tick, 2000); first.unref();
      const timer = setInterval(tick, 15_000); timer.unref();
      const ptimer = setInterval(purge, 3600e3); ptimer.unref();
      ctx.onStop(() => { clearTimeout(first); clearInterval(timer); clearInterval(ptimer); });
      log.info('modules actifs', { modules: wanted() });
    }
  },
};
