// Modèles Opérations et Rapports (ticket #67) : fonctions PURES. Formes issues des routes internes du dashboard :
// /api/scheduler/tasks, /api/scheduler/runs, /api/digest/history, /api/analyzer/rules, /api/analyzer/baseline*, /api/analyzer/exceptions.
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const n0 = (v) => num(v) ?? 0;
const list = (v, ...keys) => {
  if (Array.isArray(v)) return v;
  if (isObj(v)) for (const k of keys) if (Array.isArray(v[k])) return v[k];
  return [];
};
const OK = new Set(['ok', 'success', 'done']);
const taskState = (t) => {
  if (!t.enabled) return 'off';
  const s = String(t.lastStatus || '').toLowerCase();
  if (!s) return 'new';
  return OK.has(s) ? 'ok' : 'err';
};

export function opsModel(d = {}) {
  const tasks = list(d.scheduler_tasks, 'tasks').filter(isObj).map((t) => ({
    id: t.id, name: String(t.name ?? '?'), type: t.type || null, enabled: t.enabled !== false, schedule: t.scheduleText || t.cron || '',
    nextRun: num(t.nextRun), lastRunAt: num(t.lastRunAt), lastMessage: t.lastMessage ? String(t.lastMessage) : null,
    durationMs: num(t.lastDurationMs), runs: n0(t.runCount), running: t.running === true, state: taskState({ ...t, enabled: t.enabled !== false }),
  }));
  const runs = list(d.scheduler_runs, 'runs').filter(isObj).map((r) => ({ taskId: r.taskId, at: num(r.startedAt), durationMs: num(r.durationMs), ok: OK.has(String(r.status || '').toLowerCase()), message: r.message || null }));
  const digests = list(d.digests, 'digests').filter(isObj).map((x) => ({ id: x.id, at: num(x.generated_at ?? x.generatedAt), hours: num(x.period_hours ?? x.periodHours) })).filter((x) => x.at !== null).sort((a, b) => b.at - a.at);
  const upcoming = tasks.filter((t) => t.enabled && t.nextRun !== null).sort((a, b) => a.nextRun - b.nextRun);
  return {
    kpis: { tasks: tasks.length, enabled: tasks.filter((t) => t.enabled).length, failing: tasks.filter((t) => t.state === 'err').length, running: tasks.filter((t) => t.running).length, runsTotal: tasks.reduce((a, t) => a + t.runs, 0), digests: digests.length },
    tasks: tasks.sort((a, b) => (a.state === 'err' ? -1 : 0) - (b.state === 'err' ? -1 : 0) || a.name.localeCompare(b.name)),
    upcoming, runs, digests,
    states: ['ok', 'err', 'new', 'off'].map((key) => ({ key, value: tasks.filter((t) => t.state === key).length })),
  };
}

export function reportsModel(d = {}) {
  const rl = isObj(d.rules) ? d.rules : {};
  const builtins = list(rl.builtins).filter(isObj).map((r) => ({ key: String(r.key ?? r.id), id: r.id, enabled: r.enabled !== false, remediation: isObj(r.blocklist) && r.blocklist.remediation === true, remediationType: isObj(r.blocklist) ? r.blocklist.remediationType || null : null }));
  const custom = list(rl.custom).filter(isObj).map((r) => ({
    key: String(r.key ?? r.id), id: r.id, name: String(r.name ?? r.key ?? '?'), enabled: r.enabled !== false, severity: r.severity || null,
    windowMinutes: num(r.windowMinutes), minMatches: num(r.minMatches), scope: r.scope || null, minIps: num(r.minIps),
    remediation: isObj(r.blocklist) && r.blocklist.remediation === true, remediationType: isObj(r.blocklist) ? r.blocklist.remediationType || null : null,
  }));
  const bl = isObj(d.baseline) ? d.baseline : {};
  const baseline = (b) => (isObj(b) && ('daysElapsed' in b || 'learning' in b) ? {
    learning: b.learning === true, daysElapsed: n0(b.daysElapsed), daysRequired: n0(b.daysRequired), coverage: num(b.coverage),
    buckets: num(b.bucketsTracked), usable: num(b.bucketsUsable), keys: num(b.keysTracked), sporadic: num(b.sporadicKeys), vhosts: num(b.vhostsTracked),
  } : null);
  const exceptions = list(d.exceptions, 'exceptions').filter(isObj);
  return {
    kpis: { builtinsOn: builtins.filter((r) => r.enabled).length, builtins: builtins.length, customOn: custom.filter((r) => r.enabled).length, custom: custom.length, exceptions: exceptions.length, remediating: [...builtins, ...custom].filter((r) => r.enabled && r.remediation).length },
    builtins, custom, exceptions,
    baselines: [['vhost', baseline(bl)], ['country', baseline(d.baseline_country)], ['data', baseline(d.baseline_data)]].filter(([, b]) => b),
  };
}
