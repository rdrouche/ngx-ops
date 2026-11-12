'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const { spawnSync } = require('child_process');
const backup = require('../lib/hub-backup');
const tool = path.join(__dirname, '..', 'tools', 'ngxb-decrypt.js');

test('l outil autonome déchiffre ce que le dashboard chiffre (et refuse un mauvais mot de passe)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ngxb-'));
  const plain = Buffer.from('contenu tar.gz factice');
  const f = path.join(dir, 'b.ngxb'); fs.writeFileSync(f, backup.encrypt(plain, 'correct horse'));
  const ok = spawnSync('node', [tool, f, path.join(dir, 'o.tar.gz')], { env: { ...process.env, HUB_BACKUP_PASSPHRASE: 'correct horse' } });
  assert.equal(ok.status, 0, ok.stderr.toString());
  assert.deepEqual(fs.readFileSync(path.join(dir, 'o.tar.gz')), plain);
  const bad = spawnSync('node', [tool, f, path.join(dir, 'x.tar.gz')], { env: { ...process.env, HUB_BACKUP_PASSPHRASE: 'faux' } });
  assert.equal(bad.status, 1); assert.match(bad.stderr.toString(), /incorrect/); assert.ok(!fs.existsSync(path.join(dir, 'x.tar.gz')));
  assert.equal(spawnSync('node', [tool, f], { env: { ...process.env, HUB_BACKUP_PASSPHRASE: '' }, input: '' }).status, 2);
});
