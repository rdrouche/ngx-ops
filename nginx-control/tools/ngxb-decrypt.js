#!/usr/bin/env node
'use strict';
/**
 * Déchiffre une sauvegarde NGX Ops Hub (format NGXB1) — outil autonome, Node ≥ 16, aucune dépendance.
 *
 *   HUB_BACKUP_PASSPHRASE='ma phrase' node ngxb-decrypt.js sauvegarde.ngxb [sortie.tar.gz] [--extract [dossier]]
 *
 * La phrase de passe se lit dans HUB_BACKUP_PASSPHRASE, S3_BACKUP_PASSPHRASE ou BACKUP_PASSPHRASE (ou sur l'entrée standard si aucune n'est définie) :
 * jamais en argument de ligne de commande (visible dans `ps` et l'historique du shell).
 * Format : "NGXB1" | sel(16) | iv(12) | données chiffrées | tag(16) ; AES-256-GCM, clé = scrypt(phrase, sel, N=2^15, r=8, p=1).
 * Un mauvais mot de passe ou un fichier altéré → erreur d'authentification (rien n'est écrit).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const MAGIC = Buffer.from('NGXB1');
function decrypt(buf, pass) {
  if (buf.length < MAGIC.length + 16 + 12 + 16 || !buf.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error("ce fichier n'est pas une archive NGXB1 (déjà déchiffrée ?)");
  const salt = buf.subarray(5, 21), iv = buf.subarray(21, 33), tag = buf.subarray(buf.length - 16), ct = buf.subarray(33, buf.length - 16);
  const key = crypto.scryptSync(String(pass), salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv); d.setAuthTag(tag);
  try { return Buffer.concat([d.update(ct), d.final()]); } catch { throw new Error('mot de passe incorrect ou archive altérée'); }
}

function main() {
  const args = process.argv.slice(2);
  const ei = args.indexOf('--extract');
  let extractDir = null;
  if (ei >= 0) { extractDir = args[ei + 1] && !args[ei + 1].startsWith('-') ? args.splice(ei, 2)[1] : (args.splice(ei, 1), null); }
  const [input, output] = args;
  if (!input) { console.error('usage : HUB_BACKUP_PASSPHRASE=… node ngxb-decrypt.js <archive> [sortie.tar.gz] [--extract [dossier]]'); process.exit(2); }
  let pass = process.env.HUB_BACKUP_PASSPHRASE || process.env.S3_BACKUP_PASSPHRASE || process.env.BACKUP_PASSPHRASE || '';
  if (!pass) { try { pass = fs.readFileSync(0, 'utf8').replace(/\r?\n$/, ''); } catch { /* pas de stdin */ } }
  if (!pass) { console.error('phrase de passe absente (HUB_BACKUP_PASSPHRASE / S3_BACKUP_PASSPHRASE / BACKUP_PASSPHRASE ou entrée standard)'); process.exit(2); }
  let plain;
  try { plain = decrypt(fs.readFileSync(input), pass); } catch (e) { console.error('erreur : ' + e.message); process.exit(1); }
  const out = output || input.replace(/\.(ngxb|enc)$/i, '') + (/\.tar\.gz$/.test(input) ? '' : '.tar.gz');
  fs.writeFileSync(out, plain, { mode: 0o600 });
  console.log('déchiffré : ' + out + ' (' + plain.length + ' octets)');
  if (extractDir !== null || ei >= 0) {
    const dir = extractDir || out.replace(/\.tar\.gz$/, '') + '-contenu';
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    execFileSync('tar', ['-xzf', out, '-C', dir]);
    console.log('extrait dans : ' + path.resolve(dir) + ' (manifest.json en premier ; vérifier les sha256 du manifeste)');
  }
}
if (require.main === module) main();
module.exports = { decrypt };
