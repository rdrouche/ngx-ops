'use strict';
// v12.74.1 — conteneur challenge arrete : snippets neutres ; (re)demarrage : snippets actifs.
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chp-'));
process.env.USERS_FILE = path.join(dir, 'users.yml');
process.env.DIR_SNIPPETS = path.join(dir, 'snippets'); process.env.DIR_CONF = path.join(dir, 'conf');
fs.mkdirSync(process.env.DIR_SNIPPETS); fs.mkdirSync(process.env.DIR_CONF);
fs.writeFileSync(path.join(dir, 'challenge.yml'), "challenge_enable: true\nchallenge_exempt_ua_regex: '^(forgejo-runner/|git/|NGXOps)'\n");
fs.writeFileSync(path.join(dir, 'blocklists.yml'), 'enable: true\n');
const B = require('../features/blocklists');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const code = s => s.split('\n').filter(l => !l.startsWith('#')).join('\n');
console.log('\npause du challenge');
check('actif : snippets avec auth_request et exemption UA', () => {
  const f = B.computeChallengeFiles().files;
  assert.ok(code(f.find(x => x.name === 'challenge-all.conf').content).includes('auth_request'));
  assert.ok(f.find(x => x.name === 'blocklist-challenge.conf').content.includes('"~*^(forgejo-runner/|git/|NGXOps)" 1;'));
});
check('pause : snippets sans aucune directive', () => {
  B.setChallengePaused(true);
  assert.strictEqual(B.isChallengePaused(), true);
  for (const x of B.computeChallengeFiles().files.filter(x => x.name.startsWith('challenge-'))) assert.ok(!/auth_request/.test(code(x.content)), x.name);
});
check('fin de pause : snippets actifs a nouveau', () => {
  B.setChallengePaused(false);
  assert.ok(code(B.computeChallengeFiles().files.find(x => x.name === 'challenge-all.conf').content).includes('auth_request'));
});
console.log('\nchallenge_fail_open');
const G = require('../lib/challenge-gate'), S = require('../lib/challenge-settings');
check('defaut : pas de fail-open (5xx maintenu)', () => {
  const { settings } = G.normalizeChallengeSettings(S.challengeOverridesFromText('challenge_enable: true\n'));
  assert.strictEqual(settings.failOpen, false);
  assert.ok(!/nc_gate_open/.test(G.buildGateSnippet(settings, 'all')));
});
check('true : error_page 5xx -> 204 dans /_nc_gate + location interne', () => {
  const { settings } = G.normalizeChallengeSettings(S.challengeOverridesFromText('challenge_enable: true\nchallenge_fail_open: true\n'));
  assert.strictEqual(settings.failOpen, true);
  const c = code(G.buildGateSnippet(settings, 'all'));
  assert.ok(c.includes('error_page 500 502 503 504 = @nc_gate_open;') && c.includes('location @nc_gate_open {') && c.includes('return 204;'));
  assert.ok(c.includes('error_page 401 = @nc_challenge;'), 'le 401 (a challenger) reste intact');
});
check('valeur invalide refusee, defaut conserve', () => {
  const r = G.normalizeChallengeSettings({ challenge_fail_open: 'oui' });
  assert.strictEqual(r.settings.failOpen, false); assert.ok(r.errors.length);
});
console.log(`\n${pass} ok, ${fail} ko`); process.exit(fail ? 1 : 0);
