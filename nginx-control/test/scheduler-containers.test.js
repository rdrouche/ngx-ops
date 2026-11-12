'use strict';
// #111 : taches planifiees sur les conteneurs geres (options, resolution des groupes, execution, verification).
const assert = require('assert');
const lifecycle = require('../lib/container-lifecycle');
const SC = require('../lib/scheduler-containers');
const registry = require('../lib/scheduler-tasks');

let pass = 0, fail = 0;
async function check(name, fn) { try { await fn(); pass++; console.log('  PASS  ' + name); } catch (e) { fail++; console.log('  FAIL  ' + name + '\n        ' + e.message); } }

const mk = (id, image, enabled = true) => ({ id, label: id.toUpperCase(), enabled: () => enabled, containerName: () => `c-${id}`, image: () => image, create: async () => {} });
const A = mk('sx-a', 'reg/agent:1'), B = mk('sx-b', 'reg/agent:1'), C = mk('sx-c', 'reg/other:1'), D = mk('sx-d', 'reg/agent:1', false);
[A, B, C, D].forEach((d) => lifecycle.register(d));

(async () => {
  await check('options : chaque conteneur + un groupe par image partagee par >= 2 conteneurs actifs', () => {
    const o = SC.schedCtOptions();
    assert.ok(['sx-a', 'sx-b', 'sx-c', 'sx-d'].every((id) => o.some((x) => x.value === id)));
    const g = o.find((x) => x.value === 'group:reg/agent:1');
    assert.ok(g && /SX-A \+ SX-B/.test(g.label) && !/SX-D/.test(g.label), JSON.stringify(g));
    assert.ok(!o.some((x) => x.value === 'group:reg/other:1'));
  });
  await check('resolution : groupe = membres actifs, doublons fusionnes, inconnus signales', () => {
    const r = SC.schedCtResolve(['group:reg/agent:1', 'sx-a', 'sx-c', 'nope', 'group:reg/none:1', 42]);
    assert.deepStrictEqual(r.descs.map((d) => d.id), ['sx-a', 'sx-b', 'sx-c']);
    assert.deepStrictEqual(r.unknown, ['nope', 'group:reg/none:1']);
  });
  const engine = (st, act) => ({ status: async (d) => st[d.id] || { enabled: true, exists: true }, act: async (id, a) => act(id, a) });
  await check('restart : un par un, absent/desactive ignores, aucune creation implicite', async () => {
    const calls = [];
    const r = await SC.schedCtRun('restart', ['sx-a', 'sx-b', 'sx-c'], { engine: engine({ 'sx-b': { enabled: true, exists: false }, 'sx-c': { enabled: false, exists: true } }, (id, a) => { calls.push(id + ':' + a); return { ok: true }; }) });
    assert.deepStrictEqual(calls, ['sx-a:restart']);
    assert.strictEqual(r.status, 'ok'); assert.deepStrictEqual(r.skipped, ['SX-B', 'SX-C']);
  });
  await check('erreurs : une cible en echec n arrete pas les autres, statut error', async () => {
    const r = await SC.schedCtRun('update', ['sx-a', 'sx-b'], { engine: engine({}, (id) => { if (id === 'sx-a') throw Object.assign(new Error('x'), { code: 'busy' }); return { ok: true }; }) });
    assert.strictEqual(r.status, 'error'); assert.deepStrictEqual(r.done, ['SX-B']); assert.ok(/SX-A : busy/.test(r.message));
    const r2 = await SC.schedCtRun('update', ['sx-a'], { engine: engine({}, () => ({ ok: false, error: 'pull failed' })) });
    assert.strictEqual(r2.status, 'error');
  });
  await check('selection vide ou tout ignore : error / skipped', async () => {
    assert.strictEqual((await SC.schedCtRun('restart', [], { engine: engine({}, () => ({ ok: true })) })).status, 'error');
    const r = await SC.schedCtRun('restart', ['sx-a'], { engine: engine({ 'sx-a': { enabled: true, exists: false } }, () => { throw new Error('non appele'); }) });
    assert.strictEqual(r.status, 'skipped');
  });
  await check('verification : signale les mises a jour sans rien appliquer', async () => {
    const seen = [];
    const r = await SC.schedCtCheckAll({ descs: [A, B, C], engine: engine({ 'sx-c': { enabled: true, exists: false } }, (id, a) => { seen.push(id + ':' + a); return { ok: true, updateAvailable: id === 'sx-b' }; }) });
    assert.deepStrictEqual(seen, ['sx-a:check', 'sx-b:check']);
    assert.strictEqual(r.checked, 2); assert.deepStrictEqual(r.available, ['SX-B']);
  });
  await check('registre : 3 nouveaux types, parametres valides, liste dynamique branchee', () => {
    for (const id of ['containers_restart', 'containers_update', 'containers_check_updates']) assert.ok(registry.getType(id), id);
    const t = registry.getType('containers_restart');
    assert.deepStrictEqual(registry.validateParams(t, { targets: ['sx-a', 'sx-a'] }), { ok: true, value: { targets: ['sx-a'] } });
    assert.strictEqual(registry.validateParams(t, { targets: 'x' }).ok, true);
    const d = registry.describeTypes((n) => (n === 'managed_containers' ? SC.schedCtOptions() : [])).find((x) => x.id === 'containers_update');
    assert.ok(d.params[0].options.some((o) => o.value === 'sx-a'));
  });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
