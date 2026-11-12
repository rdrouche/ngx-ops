'use strict';
// #117 : reglages de sauvegarde, cibles (local / Git / S3), rotation distante, archive YAML — sans reseau (client S3 factice).
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const S = require('../lib/backup-settings');
const T = require('../lib/backup-targets');

let fail = 0;
async function check(name, fn) { try { await fn(); console.log('  PASS  ' + name); } catch (e) { fail++; console.log('  FAIL  ' + name + '\n        ' + e.message); } }

const FULL = { s3_enable: 'true', s3_endpoint: 'https://s3.example.com', s3_bucket: 'mon-bucket', s3_access_key: 'AK', s3_secret_key: 'SK', s3_prefix: 'ngx' };

function fakeClient() {
  const store = new Map();
  return { store, put: async (k, b) => { store.set(k, { size: b.length, lastModified: new Date(1e12 + store.size * 1000).toISOString() }); },
    del: async (k) => { store.delete(k); }, list: async (p) => [...store].filter(([k]) => k.startsWith(p)).map(([key, v]) => ({ key, ...v })) };
}
const fakeZip = (name = '2026-11-12_07-00-00_scheduled.zip') => async (label, o) => {
  assert.ok(o && o.dir && o.rotate === false, 'ZIP temporaire sans rotation locale');
  const zipPath = path.join(o.dir, name); fs.writeFileSync(zipPath, 'PK-data'); return { zipPath, zipName: name, ts: '2026-11-12_07-00-00', files: 3 };
};

(async () => {
  console.log('\nreglages');
  await check('defauts : S3 desactive, auto non explicite, prefixe normalise', () => {
    const s = S.load({}, {});
    assert.strictEqual(s.s3.enable, false); assert.strictEqual(s.auto.explicit, false);
    assert.strictEqual(s.s3.prefix, 'ngx-ops/'); assert.strictEqual(s.s3.keep, 30); assert.strictEqual(s.s3.pathStyle, true);
    assert.strictEqual(S.load({}, { s3_prefix: '/a/b' }).s3.prefix, 'a/b/'); assert.strictEqual(S.load({}, { s3_prefix: '' }).s3.prefix, '');
  });
  await check('identifiants : l\'ENV prime sur le fichier ; champs manquants listes', () => {
    const s = S.load({ BACKUP_S3_ACCESS_KEY: 'ENVAK', BACKUP_S3_SECRET_KEY: 'ENVSK' }, FULL);
    assert.strictEqual(s.s3.accessKey, 'ENVAK'); assert.strictEqual(s.s3.secretKey, 'ENVSK');
    assert.deepStrictEqual(S.s3Missing(S.load({}, { s3_enable: 'true' }).s3), ['s3_endpoint', 's3_bucket', 's3_access_key', 's3_secret_key']);
    assert.deepStrictEqual(S.s3Missing(S.load({}, { ...FULL, s3_include_secrets: 'true' }).s3), ['S3_BACKUP_PASSPHRASE (ou BACKUP_PASSPHRASE)']);
    assert.deepStrictEqual(S.s3Missing(S.load({ BACKUP_PASSPHRASE: 'x' }, { ...FULL, s3_include_secrets: 'true' }).s3), []);
    assert.deepStrictEqual(S.s3Missing(S.load({ HUB_BACKUP_PASSPHRASE: 'x' }, { ...FULL, s3_include_secrets: 'true' }).s3).length, 1); // la phrase Hub ne sert pas au S3
  });
  await check('cibles automatiques : historique si rien n\'est dit, sinon les cases du fichier', () => {
    const legacy = { local: true, git: true };
    assert.deepStrictEqual(S.autoTargets(legacy, S.load({}, {})), { local: true, git: true, s3: false });
    assert.deepStrictEqual(S.autoTargets({ local: true, git: false }, S.load({}, {})), { local: true, git: false, s3: false });
    assert.deepStrictEqual(S.autoTargets(legacy, S.load({}, { auto_s3: 'true' })), { local: true, git: false, s3: true });
    assert.deepStrictEqual(S.autoTargets(legacy, S.load({}, { auto_local: 'false', auto_git: 'true' })), { local: false, git: true, s3: false });
  });

  await check('phrase de passe : <FONCTION>_BACKUP_PASSPHRASE prioritaire, BACKUP_PASSPHRASE en repli, aucun croisement Hub / S3', () => {
    const env = { HUB_BACKUP_PASSPHRASE: 'h', S3_BACKUP_PASSPHRASE: 's', BACKUP_PASSPHRASE: 'c' };
    assert.strictEqual(S.passphraseFor('HUB', env), 'h'); assert.strictEqual(S.passphraseFor('S3', env), 's');
    assert.strictEqual(S.passphraseFor('HUB', { BACKUP_PASSPHRASE: 'c' }), 'c'); assert.strictEqual(S.passphraseFor('S3', { BACKUP_PASSPHRASE: 'c' }), 'c');
    assert.strictEqual(S.passphraseFor('S3', { HUB_BACKUP_PASSPHRASE: 'h' }), ''); assert.strictEqual(S.passphraseFor('HUB', { S3_BACKUP_PASSPHRASE: 's' }), '');
    assert.strictEqual(S.load(env, {}).s3.passphrase, 's');
    assert.strictEqual(require('../lib/hub-settings').load({ BACKUP_PASSPHRASE: 'c' }).passphrase, 'c');
    assert.strictEqual(require('../lib/hub-settings').load({ HUB_BACKUP_PASSPHRASE: 'h', BACKUP_PASSPHRASE: 'c' }).passphrase, 'h');
  });

  console.log('\nS3');
  await check('desactive ou incomplet -> ignore avec raison (jamais d\'exception, jamais d\'appel reseau)', async () => {
    assert.ok((await T.s3BackupPush('x', { settings: S.load({}, {}) })).skipped);
    const r = await T.s3BackupPush('x', { settings: S.load({}, { s3_enable: 'true' }) });
    assert.ok(r.skipped && /s3_endpoint/.test(r.reason));
  });
  await check('envoi : ZIP sous le prefixe, ZIP temporaire supprime', async () => {
    const c = fakeClient();
    const r = await T.s3BackupPush('scheduled', { settings: S.load({}, FULL), client: c, createZip: fakeZip() });
    assert.strictEqual(r.ok, true); assert.strictEqual(r.key, 'ngx/2026-11-12_07-00-00_scheduled.zip'); assert.strictEqual(r.bytes, 7);
    assert.deepStrictEqual([...c.store.keys()], [r.key]);
  });
  await check('archive YAML : envoyee en plus, extension .ngxb si phrase de passe', async () => {
    const c = fakeClient();
    const built = [];
    const mk = (pass) => async () => T.s3BackupPush('manual', { settings: S.load(pass ? { S3_BACKUP_PASSPHRASE: 'p' } : {}, { ...FULL, s3_include_ngxops: 'true' }), client: c, createZip: fakeZip(),
      buildNgxops: (s3) => { built.push(s3.ngxopsSecrets); return { archive: Buffer.from('arch'), manifest: { files: [1, 2] } }; } });
    const a = await mk(false)(); const b = await mk(true)();
    assert.ok(/_manual_ngxops\.tar\.gz$/.test(a.ngxops.key) && a.ngxops.encrypted === false && a.ngxops.files === 2);
    assert.ok(/_manual_ngxops\.ngxb$/.test(b.ngxops.key) && b.ngxops.encrypted === true);
  });
  await check('echec de l\'archive YAML : le ZIP reste envoye, erreur isolee', async () => {
    const c = fakeClient();
    const r = await T.s3BackupPush('x', { settings: S.load({}, { ...FULL, s3_include_ngxops: 'true' }), client: c, createZip: fakeZip(), buildNgxops: () => { throw new Error('boum'); } });
    assert.strictEqual(r.ok, true); assert.strictEqual(r.ngxops.error, 'boum');
  });
  await check('rotation distante : garde N par famille (zip / YAML), ignore le reste et les sous-dossiers', async () => {
    const c = fakeClient();
    for (let i = 1; i <= 5; i++) await c.put(`ngx/2026-11-0${i}_a.zip`, Buffer.alloc(1));
    for (let i = 1; i <= 4; i++) await c.put(`ngx/2026-11-0${i}_a_ngxops.ngxb`, Buffer.alloc(1));
    await c.put('ngx/notes.txt', Buffer.alloc(1)); await c.put('ngx/sous/old.zip', Buffer.alloc(1)); await c.put('autre/x.zip', Buffer.alloc(1));
    const removed = await T.rotateRemote(c, S.load({}, { ...FULL, s3_keep: '2' }).s3);
    assert.strictEqual(removed, 5);
    assert.deepStrictEqual([...c.store.keys()].sort(), ['autre/x.zip', 'ngx/2026-11-04_a.zip', 'ngx/2026-11-04_a_ngxops.ngxb', 'ngx/2026-11-05_a.zip', 'ngx/2026-11-03_a_ngxops.ngxb', 'ngx/notes.txt', 'ngx/sous/old.zip'].sort());
    assert.strictEqual(await T.rotateRemote(c, S.load({}, { ...FULL, s3_keep: '0' }).s3), 0);
  });

  console.log('\ncibles');
  await check('runTargets : seules les cibles demandees, ordre local -> git -> s3', async () => {
    const calls = [];
    const deps = { createBackupZip: async (l) => { calls.push('zip:' + l); return { zipName: 'z.zip' }; }, gitBackupPush: async (l) => { calls.push('git'); return { ok: true, tag: 't' }; }, s3BackupPush: async () => { calls.push('s3'); return { ok: true, key: 'k' }; } };
    const r = await T.runTargets('lbl', { local: true, git: false, s3: true }, deps);
    assert.deepStrictEqual(calls, ['zip:lbl', 's3']); assert.strictEqual(r.failed, false); assert.strictEqual(r.git, undefined);
  });
  await check('runTargets : l\'echec d\'une cible n\'arrete pas les autres, failed = true', async () => {
    const calls = [];
    const deps = { createBackupZip: async () => { throw new Error('disque plein'); }, gitBackupPush: async () => { calls.push('git'); return { ok: true }; }, s3BackupPush: async () => { calls.push('s3'); throw new Error('S3 403'); } };
    const r = await T.runTargets('x', { local: true, git: true, s3: true }, deps);
    assert.strictEqual(r.zip.error, 'disque plein'); assert.strictEqual(r.s3.error, 'S3 403'); assert.deepStrictEqual(calls, ['git', 's3']); assert.strictEqual(r.failed, true);
  });
  await check('autoBackup : sans backup.yml = comportement historique du point d\'appel (aucune regression)', async () => {
    const calls = [];
    const deps = { settings: S.load({}, {}), createBackupZip: async () => { calls.push('zip'); return {}; }, gitBackupPush: async () => { calls.push('git'); return {}; }, s3BackupPush: async () => { calls.push('s3'); return {}; } };
    await T.autoBackup('pre-edit', { local: true, git: false }, deps);
    await T.autoBackup('pre-deploy', { local: true, git: true }, deps);
    assert.deepStrictEqual(calls, ['zip', 'zip', 'git']);
  });
  await check('autoBackup : avec backup.yml explicite, S3 seul', async () => {
    const calls = [];
    const deps = { settings: S.load({}, { auto_local: 'false', auto_s3: 'true' }), createBackupZip: async () => { calls.push('zip'); return {}; }, gitBackupPush: async () => { calls.push('git'); return {}; }, s3BackupPush: async () => { calls.push('s3'); return {}; } };
    await T.autoBackup('pre-deploy', { local: true, git: true }, deps);
    assert.deepStrictEqual(calls, ['s3']);
  });

  console.log(`\n${fail ? 'FAIL' : 'OK'} (${fail} echec(s))`);
  process.exit(fail ? 1 : 0);
})();
