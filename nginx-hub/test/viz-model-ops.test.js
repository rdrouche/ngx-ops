'use strict';
// Modèles Opérations / Rapports (#67) : formes des routes internes du dashboard (scheduler, digest, règles, baseline).
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const load = () => import(path.join(__dirname, '..', 'public', 'assets', 'js', 'viz', 'model-ops.js'));

test('opsModel : états des tâches, prochaines exécutions, digests triés', async () => {
  const { opsModel } = await load();
  const m = opsModel({
    scheduler_tasks: { tasks: [
      { id: 1, name: 'b', enabled: true, lastStatus: 'ok', nextRun: 200, runCount: 3 },
      { id: 2, name: 'a', enabled: true, lastStatus: 'error', nextRun: 100, runCount: 2, running: true },
      { id: 3, name: 'c', enabled: false }, { id: 4, name: 'd', enabled: true }] },
    scheduler_runs: { runs: [{ taskId: 1, startedAt: 5, status: 'ok' }, { taskId: 2, startedAt: 6, status: 'error' }] },
    digests: { digests: [{ id: 1, generated_at: 10, period_hours: 24 }, { id: 2, generated_at: 20, period_hours: 24 }] },
  });
  assert.deepEqual(Object.fromEntries(m.states.map((s) => [s.key, s.value])), { ok: 1, err: 1, new: 1, off: 1 });
  assert.equal(m.kpis.failing, 1);
  assert.equal(m.kpis.running, 1);
  assert.equal(m.kpis.runsTotal, 5);
  assert.deepEqual(m.upcoming.map((t) => t.name), ['a', 'b']);
  assert.equal(m.tasks[0].state, 'err'); // échecs en tête
  assert.equal(m.digests[0].at, 20);
  assert.equal(m.runs[1].ok, false);
});

test('reportsModel : règles intégrées/personnalisées, remédiation, baselines', async () => {
  const { reportsModel } = await load();
  const m = reportsModel({
    rules: { builtins: [{ key: 'scan', enabled: true, blocklist: { remediation: true, remediationType: 'block' } }, { key: 'flood', enabled: false }], custom: [{ key: 'custom_101', id: 101, name: 'x', enabled: true, minMatches: 30, windowMinutes: 10, blocklist: { remediation: true, remediationType: 'challenge' } }] },
    exceptions: { exceptions: [{ vhost: 'a' }] },
    baseline: { learning: true, daysElapsed: 4, daysRequired: 14, coverage: 0.3 }, baseline_country: { learning: false, daysElapsed: 14, daysRequired: 14 }, baseline_data: { reachable: false },
  });
  assert.equal(m.kpis.builtinsOn, 1);
  assert.equal(m.kpis.remediating, 2);
  assert.equal(m.kpis.exceptions, 1);
  assert.deepEqual(m.baselines.map(([k]) => k), ['vhost', 'country']);
  assert.equal(m.custom[0].remediationType, 'challenge');
});

test('modèles ops/reports : entrées vides ou invalides sans exception', async () => {
  const { opsModel, reportsModel } = await load();
  for (const bad of [undefined, {}, { rules: 'x', scheduler_tasks: 3, baseline: [] }]) assert.doesNotThrow(() => { opsModel(bad); reportsModel(bad); });
});
