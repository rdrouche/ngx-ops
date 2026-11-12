'use strict';
// #118 : déchiffrement NGXB1 dans le navigateur (module ESM sans DOM) — doit rester compatible avec lib/hub-backup.js du dashboard.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const MOD = pathToFileURL(path.join(__dirname, '..', 'public', 'assets', 'js', 'ngxb.js')).href;

// même format que nginx-dashboard/lib/hub-backup.js (encrypt)
function encrypt(buf, pass) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(String(pass), salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([Buffer.from('NGXB1'), salt, iv, ct, c.getAuthTag()]);
}

function tarFile(name, content) {
  const h = Buffer.alloc(512);
  h.write(name, 0); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(content.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136);
  h.write('        ', 148); h.write('0', 156); h.write('ustar\0', 257); h.write('00', 263);
  let sum = 0; for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  const pad = Buffer.alloc((512 - (content.length % 512)) % 512);
  return Buffer.concat([h, content, pad]);
}
const tarGz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).map(([n, c]) => tarFile(n, Buffer.from(c))), Buffer.alloc(1024)]));

test('scrypt JS = crypto.scryptSync (N=2^15, r=8, p=1)', async () => {
  const M = await import(MOD);
  const salt = crypto.randomBytes(16);
  const mine = await M.scrypt(new TextEncoder().encode('phrase de passe é'), salt);
  const ref = crypto.scryptSync('phrase de passe é', salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  assert.equal(Buffer.from(mine).toString('hex'), ref.toString('hex'));
});

test('scrypt JS : vecteur RFC 7914 (N=1024, r=8, p=16)', async () => {
  const M = await import(MOD);
  const dk = await M.scrypt(new TextEncoder().encode('password'), new TextEncoder().encode('NaCl'), { n: 1024, r: 8, p: 16, dkLen: 64 });
  assert.equal(Buffer.from(dk).toString('hex').slice(0, 32), 'fdbabe1c9d3472007856e7190d01e9fe');
});

test('aller-retour : chiffré (format dashboard) → tar.gz → liste et lecture des fichiers', async () => {
  const M = await import(MOD);
  const plain = tarGz({ 'manifest.json': '{"schema":1}', 'nginx/sites/a.conf': 'server { listen 80; }\n', 'env/bin.dat': 'a\0b' });
  const enc = encrypt(plain, 'secret');
  assert.ok(M.isNgxb(enc) && !M.isNgxb(plain));
  const out = await M.decryptNgxb(enc, 'secret');
  assert.deepEqual(Buffer.from(out), plain);
  const tar = await M.gunzip(out);
  const list = M.parseTar(tar);
  assert.deepEqual(list.map((e) => e.path), ['manifest.json', 'nginx/sites/a.conf', 'env/bin.dat']);
  assert.equal(Buffer.from(M.readEntry(tar, list[1])).toString(), 'server { listen 80; }\n');
  assert.ok(M.looksText(M.readEntry(tar, list[0])) && !M.looksText(M.readEntry(tar, list[2])));
});

test('mauvaise phrase, fichier altéré ou non NGXB1 → erreurs typées, rien en clair', async () => {
  const M = await import(MOD);
  const enc = encrypt(tarGz({ 'manifest.json': '{}' }), 'bonne');
  await assert.rejects(() => M.decryptNgxb(enc, 'mauvaise'), { code: 'bad_passphrase' });
  const bad = Buffer.from(enc); bad[bad.length - 20] ^= 1;
  await assert.rejects(() => M.decryptNgxb(bad, 'bonne'), { code: 'bad_passphrase' });
  await assert.rejects(() => M.decryptNgxb(Buffer.from('pas une archive du tout, trop court?'), 'x'), { code: 'not_ngxb' });
});

test('gunzip plafonné (anti-bombe) et tar tronqué refusé', async () => {
  const M = await import(MOD);
  await assert.rejects(() => M.gunzip(zlib.gzipSync(Buffer.alloc(2 * 1024 * 1024)), 1024 * 1024), { code: 'too_big' });
  const tar = Buffer.concat([tarFile('x', Buffer.alloc(2000))]).subarray(0, 700);
  assert.throws(() => M.parseTar(new Uint8Array(tar)), { code: 'bad_tar' });
});
