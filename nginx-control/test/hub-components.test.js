'use strict';
/** #126 : états de composants du résumé Hub = vocabulaire du contrat (ok | degraded | disabled | unknown), jamais « configured ». */
const assert = require('assert');
const { componentStates } = require('../features/hub');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

check('WAF et CrowdSec configurés, analyseur joignable -> ok', () => {
  const c = componentStates({ traffic: {}, waf: { configured: true }, crowdsec: { configured: true }, errors: [] });
  assert.deepStrictEqual(c, { analyzer: { state: 'ok' }, crowdsec: { state: 'ok' }, waf: { state: 'ok' } });
});
check('non configurés -> disabled', () => {
  const c = componentStates({ traffic: {}, waf: { configured: false }, crowdsec: { configured: false }, errors: [] });
  assert.strictEqual(c.waf.state, 'disabled'); assert.strictEqual(c.crowdsec.state, 'disabled');
});
check('CrowdSec configuré mais collecte en échec -> degraded ; WAF intact', () => {
  const c = componentStates({ traffic: {}, waf: { configured: true }, crowdsec: { configured: true }, errors: ['crowdsec: timeout'] });
  assert.strictEqual(c.crowdsec.state, 'degraded'); assert.strictEqual(c.waf.state, 'ok');
});
check('pas de données de trafic -> unknown (ne dégrade pas) ; pas de digest -> tout désactivé sans exception', () => {
  assert.strictEqual(componentStates({ waf: { configured: true }, crowdsec: { configured: false } }).analyzer.state, 'unknown');
  const c = componentStates(null);
  assert.deepStrictEqual(c, { analyzer: { state: 'unknown' }, crowdsec: { state: 'disabled' }, waf: { state: 'disabled' } });
});
check('aucun état hors vocabulaire', () => {
  const ok = new Set(['ok', 'degraded', 'unknown', 'disabled']);
  for (const d of [null, {}, { traffic: {}, waf: { configured: true }, crowdsec: { configured: true }, errors: ['waf: x'] }])
    for (const v of Object.values(componentStates(d))) assert.ok(ok.has(v.state), v.state);
});
console.log(`\n${pass} pass, ${fail} fail`); if (fail) process.exit(1);
