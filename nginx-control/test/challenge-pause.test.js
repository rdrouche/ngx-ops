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
console.log(`\n${pass} ok, ${fail} ko`); process.exit(fail ? 1 : 0);
