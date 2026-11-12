'use strict';
/** Feature overview : agrégats globaux calculés à partir de l'inventaire (aucune requête sortante). */
const { API_PREFIX } = require('../../lib/config');
const { parseJson } = require('../instances/dto');

module.exports = {
  name: 'overview',
  version: '1',
  depends: ['instances'],
  register(ctx) {
    const repo = ctx.services.get('instances');

    ctx.router.get(`${API_PREFIX}/overview`, { perm: ctx.perms.VIEW }, async () => {
      const rows = await repo.list();
      const counts = { total: rows.length, online: 0, degraded: 0, offline: 0, unknown: 0, disabled: 0 };
      const totals = { vhosts: 0, requests: 0, errors: 0, bytes: 0, humans: 0, robots: 0, blocked: 0, alerts_active: 0, alerts_critical: 0, connections: 0, mfa_accounts: 0 };
      const countries = new Map();
      const certs = [];
      const versions = {};
      const alerts = [];
      for (const r of rows) {
        if (!r.enabled) { counts.disabled++; continue; }
        counts[r.status] = (counts[r.status] || 0) + 1;
        const s = parseJson(r.last_summary, null);
        if (!s || r.status === 'offline') continue;
        totals.vhosts += s.vhosts.count; totals.requests += s.traffic_24h.requests || 0; totals.errors += s.traffic_24h.errors || 0;
        totals.bytes += s.traffic_24h.bytes || 0; totals.connections += s.nginx.connections || 0; totals.mfa_accounts += (s.mfa && s.mfa.accounts) || 0;
        totals.humans += s.traffic_24h.humans; totals.robots += s.traffic_24h.robots;
        totals.blocked += s.traffic_24h.blocked; totals.alerts_active += s.alerts.active; totals.alerts_critical += s.alerts.critical;
        const v = s.instance.version || 'inconnue';
        versions[v] = (versions[v] || 0) + 1;
        for (const c of s.top_countries || []) countries.set(c.country, (countries.get(c.country) || 0) + c.requests);
        for (const c of s.certs_expiring || []) certs.push({ instance_id: r.id, instance: r.name, name: c.name, days_left: c.days_left, not_after: c.not_after });
        for (const a of s.alerts.items) alerts.push({ instance_id: r.id, instance: r.name, ...a });
      }
      const rank = { critical: 0, warning: 1, info: 2 };
      alerts.sort((a, b) => rank[a.severity] - rank[b.severity] || String(b.since).localeCompare(String(a.since)));
      certs.sort((a, b) => (a.days_left ?? 1e9) - (b.days_left ?? 1e9));
      const top_countries = [...countries].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([country, requests]) => ({ country, requests }));
      const bk = ctx.services.get('backups'); // feature optionnelle : absente si désactivée
      return { counts, totals, versions, alerts: alerts.slice(0, 30), certs_expiring: certs.slice(0, 20), top_countries, backups: bk ? await bk.overview() : null };
    });
  },
};
