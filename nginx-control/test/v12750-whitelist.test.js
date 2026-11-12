'use strict';
// v12.75.0 — liste blanche du challenge + IP exclues de l'envoi Intelligence.
const assert = require('assert');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const G = require('../lib/challenge-gate'), S = require('../lib/challenge-settings');
const I = require('../lib/intel-settings'), C = require('../lib/intel-client');

console.log('\nchallenge_whitelist');
const txt = 'challenge_enable: true\nchallenge_whitelist:\n  - 203.0.113.10 # bureau\n  - 198.51.100.0/24\n  - 2001:db8::/32\n  - pas-une-ip\n  - 999.1.1.1\n';
check('lecture, validation (invalides signalees), IPv4/IPv6/CIDR', () => {
  const { settings, errors } = G.normalizeChallengeSettings(S.challengeOverridesFromText(txt));
  assert.deepStrictEqual(settings.whitelist, ['203.0.113.10', '198.51.100.0/24', '2001:db8::/32']);
  assert.strictEqual(errors.length, 2);
});
check('geo $nc_exempt_ip et variables combinees dans toutes les cartes', () => {
  const { settings } = G.normalizeChallengeSettings(S.challengeOverridesFromText(txt + 'profiles:\n  - name: forge\n    mode: listed\n'));
  const http = G.buildChallengeHttp(settings, [], 's');
  assert.ok(http.includes('geo $nc_exempt_ip {') && http.includes('203.0.113.10 1;') && http.includes('2001:db8::/32 1;'));
  assert.ok(http.includes('map "$nc_exempt_path$nc_exempt_ua$nc_exempt_ip" $nc_gate_skip_all') && http.includes('"000" 0;'));
  assert.ok(http.includes('map "$blocklist_challenge$nc_exempt_path$nc_exempt_ua$nc_exempt_ip" $nc_gate_skip') && http.includes('"1000" 0;'));
  assert.ok(http.includes('$nc_exempt_ua_forge$nc_exempt_ip" $nc_gate_skip_forge'));
});
check('sans liste : geo vide valide', () => {
  const http = G.buildChallengeHttp(G.normalizeChallengeSettings({}).settings, [], 's');
  assert.ok(/geo \$nc_exempt_ip \{\n    default 0;\n\}/.test(http));
});

console.log('\nintelligence exclude_ips');
const { settings: is, errors: ie } = I.normalizeIntelSettings('enable: true\napi_url: https://x.tld/e\nexclude_ips:\n  - 203.0.113.10\n  - 198.51.100.0/24\n  - nope\n');
check('lecture et validation', () => { assert.deepStrictEqual(is.excludeIps, ['203.0.113.10', '198.51.100.0/24']); assert.ok(ie.some(e => /exclude_ips/.test(e))); });
check('alerte d une IP exclue jamais envoyee ; autres IP envoyees', () => {
  assert.strictEqual(C.shouldSend({ type: 'flood', severity: 'high', ip: '198.51.100.7' }, is), false);
  assert.strictEqual(C.shouldSend({ type: 'flood', severity: 'high', evidence: { ip: '203.0.113.10' } }, is), false);
  assert.strictEqual(C.shouldSend({ type: 'flood', severity: 'high', ip: '192.0.2.1' }, is), true);
});
check('campagne : IP exclues retirees de la liste partagee', () => {
  const a = { id: 1, ts: Date.now(), type: 'scan', severity: 'high', evidence: { campaign: true, ips: [['203.0.113.10', 5], ['192.0.2.9', 3]] } };
  const out = C.shapeAlert(a, is);
  assert.deepStrictEqual(out.ips, [['192.0.2.9', 3]]);
});
console.log(`\n${pass} ok, ${fail} ko`); process.exit(fail ? 1 : 0);
