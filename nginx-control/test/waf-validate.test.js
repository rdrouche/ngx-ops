'use strict';
/** lib/waf-validate.js : liste blanche + bornes de tout ce que le dashboard relaie au WAF. */
const assert = require('assert');
const V = require('../lib/waf-validate');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const sp = (s) => new URLSearchParams(s);

console.log('\npickQuery() : liste blanche');
check('cle inconnue ignoree, jamais retransmise', () => {
  const r = V.pickQuery(sp('limit=10&evil=1&host=x'), V.SCHEMAS.hits);
  assert.deepStrictEqual(r, { ok: true, value: { limit: 10 } });
});
check('bornes et formats : limit, ip, mode, rule, hours', () => {
  assert.strictEqual(V.pickQuery(sp('limit=501'), V.SCHEMAS.hits).ok, false);
  assert.strictEqual(V.pickQuery(sp('limit=0'), V.SCHEMAS.hits).ok, false);
  assert.strictEqual(V.pickQuery(sp('ip=1.2.3.4/24'), V.SCHEMAS.hits).ok, false);
  assert.strictEqual(V.pickQuery(sp('ip=203.0.113.9'), V.SCHEMAS.hits).ok, true);
  assert.strictEqual(V.pickQuery(sp('mode=block'), V.SCHEMAS.hits).ok, false);
  assert.strictEqual(V.pickQuery(sp('rule=abc'), V.SCHEMAS.hits).ok, false);
  assert.strictEqual(V.pickQuery(sp('vhost=a.com%0d%0aX:1'), V.SCHEMAS.hits).ok, false);
  assert.strictEqual(V.pickQuery(sp('hours=721'), V.SCHEMAS.hitsStats).ok, false);
  assert.strictEqual(V.pickQuery(sp('list=other'), V.SCHEMAS.lists).ok, false);
  assert.strictEqual(V.pickQuery(sp('list=challenge'), V.SCHEMAS.lists).ok, true);
  assert.strictEqual(V.pickQuery(sp('category=a%2Fb'), V.SCHEMAS.rules).ok, false);
});
check('toQuery() reencode proprement', () => assert.strictEqual(V.toQuery({ q: 'a b&c', limit: 5 }), 'q=a+b%26c&limit=5'));

console.log('\nvalidateSimulate()');
check('requete valide : normalisee', () => {
  const r = V.validateSimulate({ method: 'get', uri: '/?a=<script>', ua: 'curl', ip: '203.0.113.1', paranoia: '2', headers: { 'X-Test': 'v' } });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.value.method, 'GET'); assert.strictEqual(r.value.paranoia, 2);
});
check('refus : methode, uri, en-tetes, ip, paranoia', () => {
  assert.strictEqual(V.validateSimulate({ method: 'FOO', uri: '/' }).ok, false);
  assert.strictEqual(V.validateSimulate({ uri: 'http://evil/' }).ok, false);
  assert.strictEqual(V.validateSimulate({ uri: '/a\r\nb' }).ok, false);
  assert.strictEqual(V.validateSimulate({ uri: '/', headers: { 'bad name': 'x' } }).ok, false);
  assert.strictEqual(V.validateSimulate({ uri: '/', headers: { A: 'x\ny' } }).ok, false);
  assert.strictEqual(V.validateSimulate({ uri: '/', ip: '10.0.0.0/8' }).ok, false);
  assert.strictEqual(V.validateSimulate({ uri: '/', paranoia: 9 }).ok, false);
  assert.strictEqual(V.validateSimulate('x').ok, false);
});

console.log('\nvalidateSettings()');
check('cle inconnue refusee, valeurs hors bornes refusees', () => {
  assert.strictEqual(V.validateSettings({ foo: 1 }).ok, false);
  assert.strictEqual(V.validateSettings({ mode: 'block' }).ok, false);
  assert.strictEqual(V.validateSettings({ paranoia: 5 }).ok, false);
  assert.strictEqual(V.validateSettings({ thresholds: { block: 0 } }).ok, false);
  assert.strictEqual(V.validateSettings({ thresholds: { x: 1 } }).ok, false);
  assert.strictEqual(V.validateSettings(JSON.parse('{"vhosts":{"__proto__":{}}}')).ok, false);
  assert.strictEqual(V.validateSettings({ vhosts: { 'a.com': { evil: 1 } } }).ok, false);
  assert.strictEqual(V.validateSettings({ excludeIps: ['nope'] }).ok, false);
  assert.strictEqual(V.validateSettings({ ignoreStatus: [99] }).ok, false);
  assert.strictEqual(V.validateSettings({ exceptions: [{ id: 'a', rule: 1, ip: 'x' }] }).ok, false);
  assert.strictEqual(V.validateSettings({ exceptions: [{ id: 'a', rule: 1 }, { id: 'a', rule: 2 }] }).ok, false);
});
check('reglages complets valides, normalises', () => {
  const r = V.validateSettings({ enable: true, mode: 'observe', paranoia: '2', thresholds: { challenge: 5, block: 10 }, windowMinutes: 60,
    listHours: { block: 24 }, vhostMode: 'selected', vhosts: { 'a.com': { analyze: true, mode: 'remediate', disabledRules: [942100, 942100] } },
    disabledRules: [920350], exceptions: [{ id: 'e1', rule: 942100, ip: '203.0.113.0/24', pathPrefix: '/api' }], ignoreStatus: [404], excludeIps: ['10.0.0.0/8'] });
  assert.strictEqual(r.ok, true, r.error);
  assert.strictEqual(r.value.paranoia, 2);
  assert.deepStrictEqual(r.value.vhosts['a.com'].disabledRules, [942100]);
});

console.log('\ncorps des actions');
check('unlist / ack / rules update / custom rules', () => {
  assert.strictEqual(V.validateUnlist({ ip: '203.0.113.1' }).value.list, 'all');
  assert.strictEqual(V.validateUnlist({ ip: '203.0.113.0/24' }).ok, false);
  assert.strictEqual(V.validateUnlist({ ip: '203.0.113.1', list: 'x' }).ok, false);
  assert.strictEqual(V.validateAck({ ids: [] }).ok, false);
  assert.strictEqual(V.validateAck({ ids: ['a'] }).ok, false);
  assert.deepStrictEqual(V.validateAck({ ids: [1, 1, 2] }).value.ids, [1, 2]);
  assert.deepStrictEqual(V.validateRulesUpdate(undefined), { ok: true, value: {} });
  assert.strictEqual(V.validateRulesUpdate({ version: 'v4.9.0' }).value.version, 'v4.9.0');
  assert.strictEqual(V.validateRulesUpdate({ version: 'main' }).ok, false);
  assert.strictEqual(V.validateCustomRules({ text: 'SecRule' }).ok, true);
  assert.strictEqual(V.validateCustomRules({ text: 'a\u0000b' }).ok, false);
  assert.strictEqual(V.validateCustomRules({ text: 'x'.repeat(200001) }).ok, false);
  assert.strictEqual(V.validateCustomRules({}).ok, false);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
