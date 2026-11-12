'use strict';
/**
 * Reglages des sauvegardes de configuration (#117) — config/backup.yml (modifiable depuis la page Configuration).
 *   - destination S3 (s3_*) : les identifiants peuvent venir de l'ENV (BACKUP_S3_ACCESS_KEY / BACKUP_S3_SECRET_KEY), prioritaires sur le fichier ;
 *   - cibles de la sauvegarde AUTOMATIQUE (avant edition de config, avant deploiement) : auto_local / auto_git / auto_s3.
 *     Aucune de ces trois cles presente -> comportement historique inchange (voir autoTargets).
 * Donnees pures : aucune E/S hors lecture du fichier.
 */
const path = require('path');
const cfg = require('./config');
const { parseYmlFlat } = require('./notify');

const FILE = process.env.BACKUP_FILE || path.join(cfg.CONFIG_DIR, 'backup.yml');

const asBool = (v, d) => (v === true || v === 'true' ? true : v === false || v === 'false' ? false : d);
const asInt = (v, d, min, max) => { const n = parseInt(v, 10); return Number.isFinite(n) && n >= min && n <= max ? n : d; };
const str = (v) => (v === undefined || v === null ? '' : String(v).trim());

function normalizePrefix(p) {
  const s = str(p).replace(/^\/+/, '');
  return s && !s.endsWith('/') ? s + '/' : s;
}

/**
 * Phrase de passe de chiffrement d'une fonctionnalité : <KIND>_BACKUP_PASSPHRASE (HUB ou S3), sinon BACKUP_PASSPHRASE (repli commun).
 * Chaque fonctionnalité peut ainsi avoir sa propre phrase sans que le déploiement de l'une impose l'autre.
 */
const passphraseFor = (kind, env = process.env) => str(env[`${kind}_BACKUP_PASSPHRASE`]) || str(env.BACKUP_PASSPHRASE);

function load(env = process.env, raw) {
  let y = raw;
  if (y === undefined) { try { y = parseYmlFlat(FILE) || {}; } catch { y = {}; } }
  const explicitAuto = ['auto_local', 'auto_git', 'auto_s3'].some((k) => y[k] !== undefined);
  return {
    s3: {
      enable: asBool(y.s3_enable, false),
      endpoint: str(y.s3_endpoint),
      region: str(y.s3_region) || 'us-east-1',
      bucket: str(y.s3_bucket),
      prefix: normalizePrefix(y.s3_prefix === undefined ? 'ngx-ops/' : y.s3_prefix),
      pathStyle: asBool(y.s3_path_style, true),
      allowInsecure: asBool(y.s3_allow_insecure, false),
      accessKey: str(env.BACKUP_S3_ACCESS_KEY) || str(y.s3_access_key),
      secretKey: str(env.BACKUP_S3_SECRET_KEY) || str(y.s3_secret_key),
      keep: asInt(y.s3_keep, 30, 0, 10000), // 0 = pas de rotation distante
      timeoutMs: asInt(y.s3_timeout_s, 60, 5, 600) * 1000,
      ngxops: asBool(y.s3_include_ngxops, false), // archive annexe des fichiers de config NGX Ops (YAML)
      ngxopsSecrets: asBool(y.s3_include_secrets, false), // exige S3_BACKUP_PASSPHRASE ou BACKUP_PASSPHRASE (chiffrement NGXB1)
      passphrase: passphraseFor('S3', env),
    },
    auto: {
      explicit: explicitAuto,
      local: asBool(y.auto_local, true),
      git: asBool(y.auto_git, false),
      s3: asBool(y.auto_s3, false),
    },
  };
}

/** Champs manquants pour que la destination S3 soit utilisable. */
function s3Missing(s3) {
  const m = [];
  if (!s3.endpoint) m.push('s3_endpoint');
  if (!s3.bucket) m.push('s3_bucket');
  if (!s3.accessKey) m.push('s3_access_key');
  if (!s3.secretKey) m.push('s3_secret_key');
  if (s3.ngxopsSecrets && !s3.passphrase) m.push('S3_BACKUP_PASSPHRASE (ou BACKUP_PASSPHRASE)');
  return m;
}

/**
 * Cibles de la sauvegarde automatique a un point d'appel donne.
 * @param {{local:boolean, git:boolean}} legacy  comportement historique de ce point d'appel (utilise si backup.yml ne dit rien)
 * @returns {{local:boolean, git:boolean, s3:boolean}}
 */
function autoTargets(legacy, settings = load()) {
  const a = settings.auto;
  if (!a.explicit) return { local: !!legacy.local, git: !!legacy.git, s3: false };
  return { local: a.local, git: a.git, s3: a.s3 };
}

module.exports = { FILE, load, s3Missing, autoTargets, normalizePrefix, passphraseFor };
