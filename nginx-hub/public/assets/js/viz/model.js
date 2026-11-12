// Modèles de données des vues graphiques (ticket #67) : fonctions PURES, sans DOM ni i18n (testables sous Node).
// Elles lisent la forme réelle des parties de modules du contrat Hub v1 et tolèrent tout manque (parties absentes, séries vides).
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const n0 = (v) => num(v) ?? 0;
const list = (v, ...keys) => {
  if (Array.isArray(v)) return v;
  if (isObj(v)) for (const k of keys) if (Array.isArray(v[k])) return v[k];
  return [];
};
const pct = (a, b) => (b > 0 ? Math.round((a / b) * 1000) / 10 : null);
const byDesc = (key) => (a, b) => (b[key] || 0) - (a[key] || 0);

/** Garde les `n` premiers éléments et regroupe le reste dans une entrée `other` (si demandée). */
export function topN(items, n, key = 'value') {
  const s = [...items].sort(byDesc(key));
  return { top: s.slice(0, n), rest: s.slice(n).reduce((a, x) => a + (x[key] || 0), 0), restCount: Math.max(0, s.length - n) };
}

/** Série horaire {hour:s|ms} → points {t:ms, …} triés. */
export function hourlyPoints(rows, keys) {
  return list(rows, 'series', 'points', 'data')
    .map((r) => {
      const raw = num(r.hour ?? r.t ?? r.ts ?? r.time);
      if (raw === null) return null;
      const p = { t: raw < 1e12 ? raw * 1000 : raw };
      for (const k of keys) p[k] = n0(r[k]);
      return p;
    })
    .filter(Boolean)
    .sort((a, b) => a.t - b.t);
}

// ───────────────────────── Sécurité ─────────────────────────
const state = (ok, off) => (off ? 'off' : ok ? 'ok' : 'warn');

export function securityModel(d = {}) {
  const bl = isObj(d.blocklists_status) ? d.blocklists_status : {};
  const hits = isObj(d.blocklists_hits) ? d.blocklists_hits : {};
  const cst = isObj(d.challenge_stats) ? d.challenge_stats : {};
  const cs = isObj(d.challenge_status) ? d.challenge_status : {};
  const cb = isObj(d.challenge_blocks) ? d.challenge_blocks : {};
  const ws = isObj(d.waf_status) ? d.waf_status : {};
  const waf = isObj(ws.waf) ? ws.waf : {};
  const cr = isObj(d.crowdsec_status) ? d.crowdsec_status : {};
  const al = isObj(d.alerts) ? d.alerts : {};

  const sources = list(bl.sources).filter(isObj).map((s) => ({
    name: String(s.name ?? '?'), type: s.type || null, count: n0(s.count), enable: s.enable !== false, action: s.action || null,
    error: s.lastError ? String(s.lastError) : null, detected: num(s.detectedCount), list: s.list || null,
  }));
  const rules = [];
  for (const s of list(bl.sources)) for (const r of list(s && s.byRule)) if (isObj(r)) rules.push({ key: String(r.key ?? r.id ?? ''), name: String(r.name ?? r.key ?? r.id), detected: n0(r.detectedCount), remediation: r.remediationType || (r.remediation ? 'block' : 'none') });
  rules.sort(byDesc('detected'));

  const tot = isObj(cst.total) ? cst.total : {};
  const steps = [['pages', n0(tot.pages)], ['started', n0(tot.started)], ['solved', n0(tot.solved)], ['failed', n0(tot.failed)]];
  const series = hourlyPoints(cst.series, ['pages', 'started', 'solved', 'failed']);

  const mapObj = (o) => Object.entries(isObj(o) ? o : {}).map(([key, value]) => ({ key, value: n0(value) })).sort(byDesc('value'));
  const stats = isObj(waf.stats24h) ? waf.stats24h : {};

  const components = [
    { id: 'blocklists', state: bl.enable === false ? 'off' : state(!sources.some((s) => s.enable && s.error), !Object.keys(bl).length), count: sources.filter((s) => s.enable).length, errors: sources.filter((s) => s.error).length },
    { id: 'challenge', state: cs.enabled === false || cs.challengeEnabled === false ? 'off' : (isObj(cs.container) && cs.container.running === false) ? 'err' : Object.keys(cs).length ? (list(cs.errors).length ? 'warn' : 'ok') : 'off', engine: cs.engine || null, paused: cs.paused === true },
    { id: 'waf', state: ws.configured === false || ws.enabled === false ? 'off' : (ws.reachable === false || (isObj(waf.engine) && waf.engine.ready === false)) ? 'err' : Object.keys(ws).length ? (list(ws.errors).length ? 'warn' : 'ok') : 'off', engine: isObj(waf.engine) ? waf.engine.name : null, rulesLoaded: isObj(waf.crs) ? num(waf.crs.rulesLoaded) : null, paranoia: isObj(waf.engine) ? num(waf.engine.paranoia) : null },
    { id: 'crowdsec', state: cr.configured === false || !Object.keys(cr).length ? 'off' : 'ok', decisions: list(isObj(d.crowdsec_decisions) ? d.crowdsec_decisions.decisions : null).length },
  ];

  return {
    components,
    kpis: {
      blockedIps: num(bl.totalUniqueIps), hits: num(hits.totalHits), hitIps: num(hits.uniqueHitIps),
      alerts: num(al.total), unacked: num(al.unacked),
      wafRequests: num(stats.requests), wafHits: num(stats.hits), wafIps: num(stats.ips),
      challengeStarted: n0(tot.started), challengeSolved: n0(tot.solved), challengeFailed: n0(tot.failed),
      solveRate: pct(n0(tot.solved), n0(tot.started)), bans: list(cb.bans).length, offenders: list(cb.offenders).length,
      challengedIps: isObj(cs.ips) ? num(cs.ips.count) : null,
    },
    alertsByType: mapObj(al.by_type), alertsBySeverity: mapObj(al.by_severity),
    hitsBySource: list(hits.bySource).filter(isObj).map((s) => ({ key: String(s.name), value: n0(s.hits) })).sort(byDesc('value')),
    topHitIps: list(hits.topIps).filter(isObj).map((s) => ({ key: String(s.ip), value: n0(s.count) })).sort(byDesc('value')),
    sources: sources.sort(byDesc('count')), rules,
    challenge: { steps, series, windowHours: num(cst.windowHours) },
    bans: list(cb.bans).filter(isObj), offenders: list(cb.offenders).filter(isObj), whitelist: list(bl.whitelist).length,
    waf: { rules: list(d.waf_top_rules, 'rules').filter(isObj), ips: list(d.waf_top_ips, 'ips').filter(isObj), series: list(d.waf_series, 'series').filter(isObj) },
  };
}

// ───────────────────────── Trafic ─────────────────────────
export function trafficModel(d = {}) {
  const vh = list(d.vhosts, 'vhosts', 'items').filter(isObj).map((v) => ({ name: String(v.vhost ?? '?'), requests: n0(v.requests), errors: n0(v.errors), bytes: n0(v.bytes) })).sort(byDesc('requests'));
  const cl = isObj(d.clients) ? d.clients : {};
  const cv = new Map(list(d.clients_by_vhost, 'vhosts').filter(isObj).map((v) => [String(v.vhost), v]));
  for (const v of vh) { const c = cv.get(v.name); v.bots = c ? n0(c.bots) : null; v.human = c ? n0(c.human) : null; }
  const countries = list(d.countries, 'countries', 'items').filter(isObj).map((c) => ({ code: String(c.country ?? '??'), requests: n0(c.requests), errors: n0(c.errors), bytes: n0(c.bytes) })).sort(byDesc('requests'));
  const totalReq = vh.reduce((a, v) => a + v.requests, 0);
  const totalErr = vh.reduce((a, v) => a + v.errors, 0);
  const totalBytes = vh.reduce((a, v) => a + v.bytes, 0);
  const cat = list(cl.byCategory).filter(isObj).map((c) => ({ key: String(c.category), value: n0(c.requests) })).sort(byDesc('value'));
  const clientsTotal = num(cl.total);
  return {
    kpis: { requests: totalReq || clientsTotal, errors: totalErr, errorRate: pct(totalErr, totalReq), bytes: totalBytes, countries: countries.length, vhosts: vh.length, bots: num(cl.bots), human: num(cl.human), humanRate: pct(n0(cl.human), n0(clientsTotal)) },
    vhosts: vh, countries, categories: cat,
    hourly: hourlyPoints(d.series_hourly, ['requests', 'errors', 'bytes']),
  };
}

// ───────────────────────── Inventaire ─────────────────────────
export function inventoryModel(d = {}) {
  const ng = isObj(d.nginx) ? d.nginx : null;
  const conn = ng && isObj(ng.connections) ? ng.connections : null;
  const certs = list(d.certificates, 'certificates').filter(isObj).map((c) => ({
    name: String(c.domain || c.name || '?'), file: String(c.name ?? ''), daysLeft: num(c.daysLeft), totalDays: num(c.totalDays), validTo: c.validTo || null,
    expired: c.expired === true, warning: c.warning === true, source: c.source || null, sans: list(c.sans).length, issuer: typeof c.issuer === 'string' ? (c.issuer.match(/O=([^\n]+)/) || [])[1] || null : null,
  })).sort((a, b) => (a.daysLeft ?? 1e9) - (b.daysLeft ?? 1e9));

  const files = list(d.vhosts, 'vhosts').filter(isObj);
  let blocks = 0; let ssl = 0; let redirects = 0; let monitored = 0; const kinds = {};
  for (const f of files) {
    for (const b of list(f.serverBlocks).filter(isObj)) {
      blocks++;
      if (b.ssl) ssl++;
      if (b.redirectsToHttps) redirects++;
      if (isObj(b.monitoring) && b.monitoring.enabled) monitored++;
      for (const l of list(b.locations).filter(isObj)) kinds[l.kind || 'other'] = (kinds[l.kind || 'other'] || 0) + 1;
    }
  }
  const cm = isObj(d.containers_managed) ? d.containers_managed : {};
  const containers = (Array.isArray(cm.containers) ? cm.containers : cm.container ? [cm.container] : []).filter(isObj)
    .map((c) => ({ name: String(c.name ?? '?'), running: c.running === true, status: c.status || null, image: c.image || null, started: c.started || null }));
  const agents = list(d.agents, 'agents').filter(isObj);

  return {
    nginx: ng ? { running: ng.running === true, version: ng.version || null, tls: ng.tls || null, conn: conn ? { active: n0(conn.active), reading: n0(conn.reading), writing: n0(conn.writing), waiting: n0(conn.waiting), requests: num(conn.requests), accepted: num(conn.accepted), handled: num(conn.handled) } : null } : null,
    certs, certSummary: isObj(d.certificates) && isObj(d.certificates.summary) ? d.certificates.summary : null,
    vhosts: { files: files.length, enabled: files.filter((f) => f.enabled !== false).length, blocks, ssl, redirects, monitored, kinds: Object.entries(kinds).map(([key, value]) => ({ key, value })).sort(byDesc('value')) },
    containers, agents: { total: agents.length, online: agents.filter((a) => a.online === true || a.status === 'online').length },
  };
}
