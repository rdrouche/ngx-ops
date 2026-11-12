'use strict';
// Cycle de vie uniforme des conteneurs (#104) et mise a jour d'une image partagee (#105), sur un faux Docker.
const assert = require('assert');
const { createEngine } = require('../lib/container-lifecycle');

let fail = 0;
async function check(name, fn) { try { await fn(); console.log('  PASS  ' + name); } catch (e) { fail++; console.log('  FAIL  ' + name + '\n        ' + e.message); } }

/** Faux Docker : conteneurs { name, running, imageId, image } ; images { ref -> id } ; un pull peut faire evoluer un tag. */
function fakeDocker(state) {
  const calls = [];
  return {
    calls, state,
    async dockerCall(method, path) {
      calls.push(method + ' ' + path.replace(/\?.*/, ''));
      const m = path.match(/^\/containers\/([^/?]+)(?:\/(\w+))?/);
      const c = state.containers[decodeURIComponent(m[1])];
      if (method === 'GET') return c ? { status: 200, body: { State: { Running: c.running, Status: c.running ? 'running' : 'exited' }, Config: { Image: c.image }, Image: c.imageId, Created: 'c', } } : { status: 404 };
      if (method === 'DELETE') { delete state.containers[decodeURIComponent(m[1])]; return { status: 204 }; }
      if (!c) return { status: 404 };
      if (m[2] === 'start') c.running = true; if (m[2] === 'stop') c.running = false;
      return { status: 204 };
    },
    async getImageId(ref) { return state.images[ref] || null; },
    async pullAndCheckUpdate(ref) {
      const before = state.images[ref]; if (state.registry[ref]) state.images[ref] = state.registry[ref];
      return { ok: true, updated: before !== state.images[ref] };
    },
  };
}
function setup(over = {}) {
  const state = { containers: {}, images: { 'img:latest': 'sha-old' }, registry: {}, ...over };
  const dk = fakeDocker(state); const eng = createEngine(dk);
  const created = [];
  const mk = (id, name, image = 'img:latest', enabled = true) => eng.register({
    id, label: id, enabled: () => enabled, containerName: () => name, image: () => image,
    create: async () => { created.push(id); state.containers[name] = { running: true, image, imageId: state.images[image] }; },
  });
  return { state, dk, eng, created, mk };
}

(async () => {
  await check('start : absent -> cree ; arrete -> docker start ; en marche -> sans effet', async () => {
    const { state, eng, created, mk } = setup(); mk('a', 'ca');
    await eng.act('a', 'start'); assert.deepStrictEqual(created, ['a']);
    state.containers.ca.running = false; await eng.act('a', 'start'); assert.strictEqual(state.containers.ca.running, true); assert.strictEqual(created.length, 1);
    assert.strictEqual((await eng.act('a', 'start')).noop, true);
  });
  await check('restart : existant -> docker restart ; absent -> cree', async () => {
    const { dk, eng, created, mk, state } = setup(); mk('a', 'ca');
    await eng.act('a', 'restart'); assert.deepStrictEqual(created, ['a']);
    await eng.act('a', 'restart'); assert.ok(dk.calls.includes('POST /containers/ca/restart')); assert.strictEqual(created.length, 1);
  });
  await check('recreate : recree toujours ; stop garde le conteneur ; down le supprime', async () => {
    const { state, eng, created, mk } = setup(); mk('a', 'ca');
    await eng.act('a', 'recreate'); await eng.act('a', 'recreate'); assert.strictEqual(created.length, 2);
    await eng.act('a', 'stop'); assert.strictEqual(state.containers.ca.running, false); assert.ok(state.containers.ca);
    await eng.act('a', 'down'); assert.strictEqual(state.containers.ca, undefined);
    assert.strictEqual((await eng.act('a', 'down')).noop, true);
  });
  await check('desactive : start/recreate/update refuses (409), stop/down autorises', async () => {
    const { eng, mk } = setup(); mk('a', 'ca', 'img:latest', false);
    for (const a of ['start', 'restart', 'recreate', 'update', 'check']) await assert.rejects(eng.act('a', a), (e) => e.status === 409 && e.code === 'disabled');
    await eng.act('a', 'stop'); await eng.act('a', 'down');
  });
  await check('id / action inconnus, action concurrente refusee', async () => {
    const { eng, mk } = setup(); mk('a', 'ca');
    await assert.rejects(eng.act('zz', 'start'), (e) => e.status === 404);
    await assert.rejects(eng.act('a', 'exploser'), (e) => e.status === 400);
    const slow = createEngine(fakeDocker({ containers: {}, images: {}, registry: {} }));
    let release; slow.register({ id: 'b', enabled: () => true, containerName: () => 'cb', image: () => 'i', create: () => new Promise((r) => { release = r; }) });
    const p = slow.act('b', 'recreate');
    await assert.rejects(slow.act('b', 'recreate'), (e) => e.status === 409 && e.code === 'busy');
    release(); await p;
  });
  await check('#105 : 3 conteneurs sur la meme image, le 1er pull met a jour, les 3 sont recrees', async () => {
    const { state, eng, created, mk } = setup({ registry: { 'img:latest': 'sha-new' } });
    mk('analyzer', 'c1'); mk('waf', 'c2'); mk('shipper', 'c3');
    for (const n of ['c1', 'c2', 'c3']) state.containers[n] = { running: true, image: 'img:latest', imageId: 'sha-old' };
    const r1 = await eng.act('analyzer', 'update');
    assert.strictEqual(r1.recreated, true);
    // l'image locale est deja a jour (pull du 1er) : l'ancienne logique aurait repondu « deja a jour » ici
    const r2 = await eng.act('waf', 'update'); const r3 = await eng.act('shipper', 'update');
    assert.strictEqual(r2.recreated, true); assert.strictEqual(r3.recreated, true); assert.deepStrictEqual(created, ['analyzer', 'waf', 'shipper']);
    assert.strictEqual((await eng.act('waf', 'update')).recreated, false);
  });
  await check('check ne change rien et annonce la mise a jour', async () => {
    const { state, eng, created, mk } = setup({ registry: { 'img:latest': 'sha-new' } }); mk('a', 'ca');
    state.containers.ca = { running: true, image: 'img:latest', imageId: 'sha-old' };
    const r = await eng.act('a', 'check'); assert.strictEqual(r.updateAvailable, true); assert.strictEqual(created.length, 0);
  });
  await check('conteneur arrete en retard : supprime (le prochain start repart d une image a jour)', async () => {
    const { state, eng, mk } = setup({ registry: { 'img:latest': 'sha-new' } }); mk('a', 'ca');
    state.containers.ca = { running: false, image: 'img:latest', imageId: 'sha-old' };
    const r = await eng.act('a', 'update'); assert.strictEqual(r.removedStale, true); assert.strictEqual(state.containers.ca, undefined);
  });
  await check('overview : retard + pairs partageant l image ; updateAll : un seul pull', async () => {
    const { state, dk, eng, created, mk } = setup({ registry: { 'img:latest': 'sha-new' } });
    mk('a', 'c1'); mk('b', 'c2'); mk('c', 'c3', 'autre:1');
    state.images['autre:1'] = 'x';
    state.containers.c1 = { running: true, image: 'img:latest', imageId: 'sha-old' };
    state.containers.c2 = { running: true, image: 'img:latest', imageId: 'sha-old' };
    state.containers.c3 = { running: true, image: 'autre:1', imageId: 'x' };
    const ov = await eng.overview();
    assert.deepStrictEqual(ov.find((s) => s.id === 'a').peers, ['b']); assert.strictEqual(ov.find((s) => s.id === 'c').outdated, false);
    const dry = await eng.updateAll({ image: 'img:latest', apply: false });
    assert.strictEqual(created.length, 0); assert.deepStrictEqual(dry.groups[0].results.map((r) => r.outdated), [true, true]);
    state.images['img:latest'] = 'sha-old'; // simule un pull non encore effectue
    const all = await eng.updateAll({ image: 'img:latest', apply: true });
    assert.deepStrictEqual(created.sort(), ['a', 'b']); assert.ok(all.ok);
    assert.strictEqual(all.groups.length, 1);
  });
  await check('fournisseur dynamique : id « prefixe:cle », seuls les conteneurs existants sont listes', async () => {
    const { state, eng, created } = setup();
    state.containers['ga-site'] = { running: true, image: 'img:latest', imageId: 'sha-old' };
    eng.registerProvider('goaccess', {
      resolve: (k) => (/^(site|other)$/.test(k) ? { label: 'GA ' + k, enabled: () => true, containerName: () => 'ga-' + k, image: () => 'img:latest',
        create: async () => { created.push(k); state.containers['ga-' + k] = { running: true, image: 'img:latest', imageId: state.images['img:latest'] }; } } : null),
      list: async () => ['site'],
    });
    assert.strictEqual(eng.get('goaccess:nope'), null); assert.strictEqual(eng.get('goaccess:site').id, 'goaccess:site');
    assert.strictEqual(eng.get('inconnu:site'), null); assert.strictEqual(eng.get('goaccess:../x'), null);
    const ov = await eng.overview(); assert.deepStrictEqual(ov.map((s) => s.id), ['goaccess:site']);
    await eng.act('goaccess:other', 'start'); assert.deepStrictEqual(created, ['other']);
    state.images['img:latest'] = 'sha-new';
    const r = await eng.updateAll({ image: 'img:latest', apply: true });
    assert.ok(r.groups[0].results.some((x) => x.id === 'goaccess:site' && x.recreated));
  });
  await check('Docker injoignable -> 503', async () => {
    const eng = createEngine({ async dockerCall() { return { status: 0, error: 'ENOENT' }; }, async getImageId() { return null; }, async pullAndCheckUpdate() { return { ok: false }; } });
    eng.register({ id: 'a', enabled: () => true, containerName: () => 'x', image: () => 'i', create: async () => {} });
    await assert.rejects(eng.act('a', 'start'), (e) => e.status === 503);
  });
  await check('register : descripteur invalide refuse', () => {
    const eng = createEngine({});
    assert.throws(() => eng.register({ id: 'A!' })); assert.throws(() => eng.register({ id: 'ok' }));
  });
  console.log('\n' + (fail ? fail + ' FAIL' : 'tous les tests passent'));
  process.exit(fail ? 1 : 0);
})();
