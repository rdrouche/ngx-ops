'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const load = () => import(pathToFileURL(path.join(__dirname, '..', 'public', 'assets', 'js', 'qr.js')).href);
const digest = (m) => crypto.createHash('sha256').update(m.map((r) => r.map((v) => (v ? 1 : 0)).join('')).join('')).digest('hex');

// Les empreintes ci-dessous proviennent de matrices DÉCODÉES avec succès par un décodeur indépendant (OpenCV) :
// toute modification de l'encodeur qui les change doit être re-vérifiée avec un décodeur avant de mettre à jour le test.
const OTPAUTH = 'otpauth://totp/NGX%20Ops%20Hub:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=NGX%20Ops%20Hub&algorithm=SHA1&digits=6&period=30';

test('QR : empreintes de référence (décodables) et déterminisme', async () => {
  const { qrMatrix } = await load();
  assert.equal(digest(qrMatrix('hello')), '99ccedcf0d82e92a63894c8b42e405a3ac50eafa33ee2ce68fa895813fdcb386');
  assert.equal(digest(qrMatrix(OTPAUTH)), '8f5c3fe20b3bc57e268b7e0177f48253cc93b03fde6c1586782fcd599836353c');
  assert.equal(digest(qrMatrix('hello')), digest(qrMatrix('hello')));
});

test('QR : structure (motifs de repérage, minuterie, tailles par version, limites)', async () => {
  const { qrMatrix } = await load();
  const m = qrMatrix('hello');
  assert.equal(m.length, 21);
  for (const [ox, oy] of [[0, 0], [14, 0], [0, 14]]) {
    for (let d = 0; d < 7; d++) { // bord 7×7 sombre, anneau clair, centre 3×3 sombre
      assert.ok(m[oy][ox + d] && m[oy + 6][ox + d] && m[oy + d][ox] && m[oy + d][ox + 6]);
    }
    assert.ok(!m[oy + 1][ox + 1] && !m[oy + 1][ox + 5] && m[oy + 2][ox + 2] && m[oy + 4][ox + 4]);
  }
  for (let i = 8; i < 13; i++) assert.equal(m[6][i], i % 2 === 0, 'ligne de minuterie');
  assert.equal(qrMatrix('x'.repeat(106)).length, 41);   // version 6
  assert.equal(qrMatrix('x'.repeat(213)).length, 57);   // version 10 (capacité maximale)
  assert.throws(() => qrMatrix('x'.repeat(214)), /trop long/);
});
