'use strict';
// #110 lot 3 : decisions CrowdSec -> log store (donnees pures + un passage complet avec dependances simulees).
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const CS = require('../lib/crowdsec-ship');
const ship = require('../features/crowdsec-ship');

let pass = 0, fail = 0;
async function check(name, fn) { try { await fn(); pass++; console.log('  PASS  ' + name); } catch (e) { fail++; console.log('  FAIL  ' + name + '\n        ' + e.message); } }

const NOW = Date.parse('2026-11-12T10:00:00Z');
const D = (o = {}) => ({ id: 10, origin: 'crowdsec', type: 'ban', scope: 'Ip', value: '203.0.113.9', scenario: 'crowdsecurity/http-probing', duration: '3h59m', created_at: '2026-11-12T09:50:00Z', ...o });

(async () => {
  await check('decision locale -> evenement crowdsec/blocked avec scenario et IP', () => {
    const e = CS.csShipEvent(D(), NOW);
    assert.strictEqual(e.source, 'crowdsec'); assert.strictEqual(e.action, 'blocked');
    assert.strictEqual(e.ip, '203.0.113.9'); assert.strictEqual(e.rule, 'crowdsecurity/http-probing');
    assert.strictEqual(e.ts, '2026-11-12T09:50:00.000Z');
    assert.deepStrictEqual(e.extra, { type: 'ban', origin: 'crowdsec', decision_id: 10, duration: '3h59m' });
  });
  await check('captcha -> challenged ; autre type -> logged', () => {
    assert.strictEqual(CS.csShipEvent(D({ type: 'captcha' }), NOW).action, 'challenged');
    assert.strictEqual(CS.csShipEvent(D({ type: 'throttle' }), NOW).action, 'logged');
  });
  await check('CAPI, listes, simulees, vides et non-objets ignorees', () => {
    for (const x of [D({ origin: 'CAPI' }), D({ origin: 'lists' }), D({ simulated: true }), D({ value: '' }), null, 'x']) assert.strictEqual(CS.csShipEvent(x, NOW), null);
  });
  await check('portee non-IP : pas d IP, valeur dans extra', () => {
    const e = CS.csShipEvent(D({ scope: 'Range', value: '198.51.100.0/24' }), NOW);
    assert.strictEqual(e.ip, undefined); assert.strictEqual(e.extra.scope, 'range'); assert.strictEqual(e.extra.value, '198.51.100.0/24');
  });
  await check('sans created_at : horodatage = maintenant ; champs longs bornes', () => {
    const e = CS.csShipEvent(D({ created_at: undefined, scenario: 'x'.repeat(500) }), NOW);
    assert.strictEqual(e.ts, new Date(NOW).toISOString()); assert.strictEqual(e.rule.length, 120);
  });
  await check('premier passage : seulement les decisions de moins d 1 h, maxId = plus grand id', () => {
    const r = CS.csShipSelect([D({ id: 1, created_at: '2026-11-12T07:00:00Z' }), D({ id: 2 }), D({ id: 3, origin: 'CAPI' })], null, NOW);
    assert.deepStrictEqual(r.events.map((e) => e.extra.decision_id), [2]); assert.strictEqual(r.maxId, 3);
  });
  await check('passages suivants : seulement id > maxId, sans doublon', () => {
    const r = CS.csShipSelect([D({ id: 5 }), D({ id: 6, created_at: '2026-11-10T00:00:00Z' }), D({ id: 4 })], { maxId: 5 }, NOW);
    assert.deepStrictEqual(r.events.map((e) => e.extra.decision_id), [6]); assert.strictEqual(r.maxId, 6);
    assert.strictEqual(CS.csShipSelect([D({ id: 5 })], { maxId: 5 }, NOW).events.length, 0);
  });
  await check('LAPI vide (null) : rien, etat conserve', () => {
    assert.deepStrictEqual(CS.csShipSelect(null, { maxId: 8 }, NOW), { events: [], maxId: 8 });
    assert.deepStrictEqual(CS.csShipSelect(null, null, NOW), { events: [], maxId: null });
  });
  await check('corps NDJSON : paquets de 200 maximum, une ligne par evenement', () => {
    const evs = Array.from({ length: 450 }, (_, i) => CS.csShipEvent(D({ id: i + 1 }), NOW));
    const b = CS.csShipBodies(evs);
    assert.deepStrictEqual(b.map((x) => x.trim().split('\n').length), [200, 200, 50]);
    JSON.parse(b[0].split('\n')[0]);
  });

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csship-'));
  const mk = (over = {}) => ({
    stateFile: path.join(dir, 's.json'), token: 'T'.repeat(30), now: () => NOW,
    resolveConfig: () => ({ config: { shipperEnable: true, shipperCrowdsec: true, shipperName: 'ngx-shipper' } }),
    crowdsec: { crowdsecConfigured: () => true, crowdsecGet: async () => [D({ id: 20 }), D({ id: 21, origin: 'CAPI' })] },
    ...over,
  });
  await check('passage complet : envoi au shipper local, etat avance seulement apres succes', async () => {
    const calls = [];
    let r = await ship.tick(mk({ post: async (u, t, b) => { calls.push({ u, t, b }); return false; } }));
    assert.strictEqual(r.error, 'shipper'); assert.ok(!fs.existsSync(path.join(dir, 's.json')));
    r = await ship.tick(mk({ post: async (u, t, b) => { calls.push({ u, t, b }); return true; } }));
    assert.strictEqual(r.sent, 1);
    assert.strictEqual(calls[1].u, 'http://ngx-shipper:9181'); assert.strictEqual(calls[1].t, 'T'.repeat(30));
    assert.strictEqual(JSON.parse(calls[1].b.trim()).extra.decision_id, 20);
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(path.join(dir, 's.json'), 'utf8')), { maxId: 21 });
    r = await ship.tick(mk({ post: async () => { throw new Error('ne doit pas etre rappele'); } }));
    assert.strictEqual(r.sent, 0);
  });
  await check('desactive : shipper arrete, option coupee ou CrowdSec non configure', async () => {
    const post = async () => { throw new Error('aucun envoi attendu'); };
    for (const o of [
      { resolveConfig: () => ({ config: { shipperEnable: false, shipperCrowdsec: true } }) },
      { resolveConfig: () => ({ config: { shipperEnable: true, shipperCrowdsec: false } }) },
      { crowdsec: { crowdsecConfigured: () => false, crowdsecGet: async () => [] } },
    ]) assert.strictEqual((await ship.tick(mk({ post, ...o }))).skipped, 'disabled');
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
