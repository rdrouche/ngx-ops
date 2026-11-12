'use strict';
/**
 * Destinations de sauvegarde de la configuration (#117) : local (ZIP), Git (branche backup + tag), S3 (ZIP + archive YAML optionnelle).
 * Point d'entree unique des appelants (edition de config, deploiement, sauvegarde manuelle, tache planifiee) : `runTargets`.
 * Un echec d'une cible n'empeche jamais les autres ; chaque resultat porte `error` en cas d'echec, `skipped` si non applicable.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const cfg = require('./config');
const settings = require('./backup-settings');
const { createClient } = require('./s3');

const errText = (e) => (e && (e.message || e.error || e.stderr)) || String(e);
const stamp = () => new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
const cleanLabel = (l) => String(l || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 40);

/** Client S3 issu des reglages, ou { skipped, reason }. */
function s3FromSettings(s = settings.load()) {
  if (!s.s3.enable) return { skipped: true, reason: 'S3 desactive (backup.yml : s3_enable)' };
  const missing = settings.s3Missing(s.s3);
  if (missing.length) return { skipped: true, reason: 'S3 incomplet : ' + missing.join(', ') };
  return { client: createClient(s.s3), s3: s.s3 };
}

/** Garde les `keep` plus recents de chaque famille (zip / ngxops) sous le prefixe ; ne touche que les objets que nous avons crees. */
async function rotateRemote(client, s3) {
  if (!s3.keep) return 0;
  const objs = (await client.list(s3.prefix)).filter((o) => o.key.startsWith(s3.prefix) && !o.key.slice(s3.prefix.length).includes('/'));
  const newestFirst = (a, b) => (a.lastModified < b.lastModified ? 1 : a.lastModified > b.lastModified ? -1 : a.key < b.key ? 1 : -1);
  const families = [objs.filter((o) => o.key.endsWith('.zip')), objs.filter((o) => /_ngxops\.(tar\.gz|ngxb)$/.test(o.key))];
  let removed = 0;
  for (const fam of families) {
    for (const o of fam.sort(newestFirst).slice(s3.keep)) { await client.del(o.key); removed++; }
  }
  return removed;
}

/**
 * Envoie la configuration nginx (ZIP) vers S3, plus l'archive des YAML NGX Ops si s3_include_ngxops.
 * @param {string} label
 * @param {{settings?:object, client?:object, createZip?:Function, buildNgxops?:Function}} [deps]  injectables pour les tests
 */
async function s3BackupPush(label, deps = {}) {
  const s = deps.settings || settings.load();
  const base = deps.client ? { client: deps.client, s3: s.s3 } : s3FromSettings(s);
  if (base.skipped) return base;
  const { client, s3 } = base;
  const createZip = deps.createZip || require('./backup').createBackupZip;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ngx-s3-'));
  try {
    const z = await createZip(label, { dir: tmp, rotate: false });
    const data = fs.readFileSync(z.zipPath);
    const key = `${s3.prefix}${z.zipName}`;
    await client.put(key, data, 'application/zip');
    const res = { ok: true, key, bytes: data.length, files: z.files };
    if (s3.ngxops) {
      try {
        const b = (deps.buildNgxops || buildNgxopsArchive)(s3);
        const nk = `${s3.prefix}${z.ts || stamp()}${label ? '_' + cleanLabel(label) : ''}_ngxops.${s3.passphrase ? 'ngxb' : 'tar.gz'}`;
        await client.put(nk, b.archive, 'application/octet-stream');
        res.ngxops = { key: nk, bytes: b.archive.length, encrypted: !!s3.passphrase, files: b.manifest.files.length };
      } catch (e) { res.ngxops = { error: errText(e) }; }
    }
    try { res.rotated = await rotateRemote(client, s3); } catch (e) { res.rotateError = errText(e); }
    return res;
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}

/** Archive tar.gz des fichiers de configuration NGX Ops (*.yml|json) — meme format que la sauvegarde Hub (chiffree NGXB1 si phrase de passe). */
function buildNgxopsArchive(s3) {
  return require('./hub-backup').build({
    dirs: { config: cfg.CONFIG_DIR }, include: ['ngxops'], includeSecrets: s3.ngxopsSecrets, passphrase: s3.passphrase,
    retentionDays: 3650, instance: { id: cfg.INSTANCE_ID, version: cfg.VERSION || cfg.APP_VERSION },
  });
}

/**
 * Lance les cibles demandees (en parallele impossible : le ZIP local et le ZIP S3 lisent les memes fichiers, ordre sequentiel stable).
 * @param {string} label
 * @param {{local?:boolean, git?:boolean, s3?:boolean}} targets
 * @param {{createBackupZip?:Function, gitBackupPush?:Function, s3BackupPush?:Function, gitConfigured?:boolean}} [deps]
 * @returns {Promise<{zip?:object, git?:object, s3?:object, failed:boolean}>}
 */
async function runTargets(label, targets, deps = {}) {
  const createBackupZip = deps.createBackupZip || require('./backup').createBackupZip;
  const gitBackupPush = deps.gitBackupPush || require('./git').gitBackupPush;
  const push = deps.s3BackupPush || s3BackupPush;
  const out = { failed: false };
  if (targets.local) out.zip = await createBackupZip(label).catch((e) => ({ error: errText(e) }));
  if (targets.git) out.git = await gitBackupPush(label).catch((e) => ({ ok: false, error: errText(e) }));
  if (targets.s3) out.s3 = await push(label).catch((e) => ({ ok: false, error: errText(e) }));
  out.failed = !!((out.zip && out.zip.error) || (out.git && out.git.error) || (out.s3 && out.s3.error));
  return out;
}

/** Sauvegarde automatique (avant edition / deploiement) : cibles selon backup.yml, sinon comportement historique du point d'appel. */
function autoBackup(label, legacy, deps = {}) {
  return runTargets(label, settings.autoTargets(legacy, deps.settings), deps);
}

module.exports = { s3BackupPush, s3FromSettings, rotateRemote, buildNgxopsArchive, runTargets, autoBackup };
