'use strict';
/**
 * Feature collector : interroge (pull) chaque instance activée à intervalle fixe, concurrence bornée,
 * met à jour l'état + la série temporelle, purge la rétention. Service exposé : ctx.services.get('collector').
 */
const { API_PREFIX } = require('../../lib/config');
const { fetchSummary } = require('./fetcher');
const { deriveHealth } = require('./summary-schema');

module.exports = {
  name: 'collector',
  version: '1',
  depends: ['instances'],
  async register(ctx) {
    const { config, log, router, perms } = ctx;
    const repo = ctx.services.get('instances');
    const c = config.collector;
    const inflight = new Map(); // id → Promise (évite deux collectes simultanées de la même instance)
    const stats = { started_at: null, last_cycle_at: null, last_cycle_ms: null, last_cycle_count: 0, cycles: 0, running: false };
    let timer = null; let purgeTimer = null; let stopped = false;

    async function doPoll(row) {
      const prev = row.consecutive_failures || 0;
      try {
        const token = repo.getToken(row);
        const { summary, latencyMs } = await fetchSummary({ baseUrl: row.base_url, token }, config);
        await repo.recordPoll(row.id, { status: deriveHealth(summary), ok: true, latencyMs, failures: 0, summary });
        return { ok: true };
      } catch (e) {
        const code = (e && e.code) || 'connection';
        const failures = prev + 1;
        const status = failures >= c.offline_after_failures ? 'offline' : (row.status === 'unknown' ? 'unknown' : row.status);
        await repo.recordPoll(row.id, { status, ok: false, latencyMs: null, failures, error: code });
        if (failures === c.offline_after_failures) log.warn('instance hors ligne', { instance: row.slug, reason: code });
        return { ok: false, error: code };
      }
    }

    function pollOne(id) {
      if (inflight.has(id)) return inflight.get(id);
      const p = (async () => {
        const row = await repo.get(id);
        return row ? doPoll(row) : { ok: false, error: 'not_found' };
      })().finally(() => inflight.delete(id));
      inflight.set(id, p);
      return p;
    }

    async function pollAll() {
      if (stats.running) return;
      stats.running = true;
      const t0 = Date.now();
      try {
        const rows = (await repo.list()).filter((r) => r.enabled);
        let i = 0;
        const worker = async () => { while (i < rows.length && !stopped) { const r = rows[i++]; await pollOne(r.id); } };
        await Promise.all(Array.from({ length: Math.min(c.concurrency, rows.length) }, worker));
        stats.last_cycle_count = rows.length;
      } catch (e) { log.error('cycle de collecte', { err: e }); } finally {
        stats.running = false; stats.cycles += 1; stats.last_cycle_at = Date.now(); stats.last_cycle_ms = Date.now() - t0;
      }
    }

    async function purge() {
      try { const r = await repo.purge(c.retention_days); if (r.samples || r.audit) log.info('purge rétention', r); } catch (e) { log.error('purge', { err: e }); }
    }

    ctx.services.set('collector', { pollOne, pollAll, purge, stats: () => ({ ...stats, interval_s: c.interval_seconds, concurrency: c.concurrency, retention_days: c.retention_days }) });

    router.get(`${API_PREFIX}/collector/status`, { perm: perms.COLLECTOR_STATUS }, () => ctx.services.get('collector').stats());

    if (c.enabled) {
      stats.started_at = Date.now();
      setTimeout(() => { if (!stopped) pollAll(); }, 500).unref();
      timer = setInterval(pollAll, c.interval_seconds * 1000); timer.unref();
      purgeTimer = setInterval(purge, 3600e3); purgeTimer.unref();
      log.info('collecteur actif', { interval_s: c.interval_seconds, concurrency: c.concurrency, retention_days: c.retention_days });
    }
    ctx.onStop(() => { stopped = true; clearInterval(timer); clearInterval(purgeTimer); });
  },
};
