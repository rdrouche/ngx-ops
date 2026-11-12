'use strict';
// Les dossiers sont lus à l'import de lib/config : à fixer AVANT le require.
const fs = require('fs'), os = require('os'), path = require('path');
const { execFileSync } = require('child_process');
const test = require('node:test');
const assert = require('node:assert/strict');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'certfind-'));
process.env.DIR_SSL = path.join(root, 'ssl');
process.env.DIR_CERTS = path.join(root, 'le');
fs.mkdirSync(process.env.DIR_SSL, { recursive: true });
fs.mkdirSync(path.join(process.env.DIR_CERTS, 'synced'), { recursive: true });
const certs = require('../lib/certs');

function mk(dir, base, san, days = 30, keyName) {
  fs.mkdirSync(dir, { recursive: true });
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, keyName), '-out', path.join(dir, base),
    '-days', String(days), '-subj', '/CN=' + san.replace('*.', 'w.'), '-addext', 'subjectAltName=' + san.split(',').map(d => 'DNS:' + d).join(',')], { stdio: 'ignore' });
}

test('rien nulle part → found:false', () => {
  assert.equal(certs.findUsableCertificate(['agh-central.bourgesplus.net']).found, false);
});

test('wildcard déposé à la main dans ssl/ (avec sa clé) → chemins /ssl/…', () => {
  mk(process.env.DIR_SSL, 'bourgesplus.cer', '*.bourgesplus.net,bourgesplus.net', 30, 'bourgesplus.key');
  const r = certs.findUsableCertificate(['agh-central.bourgesplus.net']);
  assert.deepEqual([r.found, r.source, r.certPath, r.keyPath], [true, 'ssl', '/ssl/bourgesplus.cer', '/ssl/bourgesplus.key']);
  // un wildcard ne couvre pas deux niveaux ni un autre domaine
  assert.equal(certs.findUsableCertificate(['a.b.bourgesplus.net']).found, false);
  assert.equal(certs.findUsableCertificate(['x.autre.net']).found, false);
});

test('certificat ssl/ sans clé → ignoré', () => {
  mk(process.env.DIR_SSL, 'orphelin.cer', 'orphelin.example.org', 30, 'autre.key');
  assert.equal(certs.findUsableCertificate(['orphelin.example.org']).found, false);
});

test('synced/ → chemins /etc/letsencrypt/synced/…', () => {
  mk(path.join(process.env.DIR_CERTS, 'synced', 'site1'), 'fullchain.pem', 'sync.example.org', 30, 'privkey.pem');
  const r = certs.findUsableCertificate(['sync.example.org']);
  assert.deepEqual([r.found, r.source, r.certPath], [true, 'synced', '/etc/letsencrypt/synced/site1/fullchain.pem']);
});

test('tous les noms du vhost doivent être couverts', () => {
  assert.equal(certs.findUsableCertificate(['agh-central.bourgesplus.net', 'x.autre.net']).found, false);
  assert.equal(certs.findUsableCertificate(['agh-central.bourgesplus.net', 'bourgesplus.net']).found, true);
});
