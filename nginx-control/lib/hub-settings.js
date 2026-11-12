'use strict';
/**
 * NGX Ops Hub (v12.76.0) — réglages. config/hub.yml pour le non-secret ;
 * les secrets restent dans l'ENV (jamais dans un fichier versionnable) :
 *   HUB_TOKEN_SHA256         empreinte(s) SHA-256 du jeton de lecture (résumé) — virgules = rotation
 *   HUB_BACKUP_TOKEN_SHA256  empreinte(s) du jeton de lecture des sauvegardes (pull)
 *   HUB_PUSH_TOKEN           jeton d'envoi des sauvegardes vers le Hub (push)
 *   HUB_BACKUP_PASSPHRASE    phrase de passe de chiffrement des sauvegardes Hub (repli : BACKUP_PASSPHRASE, commun avec S3_BACKUP_PASSPHRASE)
 */
const path = require('path');
const cfg = require('./config');
const { parseYmlFlat } = require('./notify');
const { passphraseFor } = require('./backup-settings');

const FILE = process.env.HUB_FILE || path.join(cfg.CONFIG_DIR, 'hub.yml');
const CATS = ['nginx', 'ngxops', 'env', 'ssl'];

function asBool(v, d) { if (v === true || v === 'true') return true; if (v === false || v === 'false') return false; return d; }
function asList(v) { return Array.isArray(v) ? v.map(String) : (typeof v === 'string' && v.trim() ? v.replace(/^\s*\[|\]\s*$/g, '').split(',').map(s => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean) : null); }

function parseHashes(value) {
  return String(value || '').split(',').map(s => s.trim().toLowerCase()).filter(s => /^[a-f0-9]{64}$/.test(s));
}

/** URL du Hub : http(s) uniquement, pas d'identifiants dans l'URL. */
function validHubUrl(u) {
  try {
    const x = new URL(u);
    if (!/^https?:$/.test(x.protocol) || x.username || x.password) return null;
    return x.origin + x.pathname.replace(/\/+$/, '');
  } catch { return null; }
}

const MODULES = ['inventory', 'traffic', 'security', 'ops', 'monitoring', 'reports', 'indicators'];

function load(env = process.env) {
  let raw = {};
  try { raw = parseYmlFlat(FILE) || {}; } catch { /* absent */ }
  const include = (asList(raw.backup_include) || ['nginx', 'ngxops', 'env']).filter(c => CATS.includes(c));
  const days = parseInt(raw.retention_days, 10);
  return {
    hubUrl: validHubUrl(String(raw.hub_url || '')) || '',
    backupEnable: asBool(raw.backup_enable, false),
    include: include.length ? include : ['nginx', 'ngxops', 'env'],
    expose: (asList(raw.expose_modules) || MODULES).filter(m => MODULES.includes(m)),
    exposeIps: asBool(raw.expose_ips, false),
    includeSecrets: asBool(raw.backup_include_secrets, false),
    retentionDays: Number.isFinite(days) && days >= 1 && days <= 3650 ? days : 30,
    timeoutSeconds: Math.min(300, Math.max(5, parseInt(raw.push_timeout_s, 10) || 60)),
    summaryHashes: parseHashes(env.HUB_TOKEN_SHA256),
    backupHashes: parseHashes(env.HUB_BACKUP_TOKEN_SHA256),
    pushToken: String(env.HUB_PUSH_TOKEN || ''),
    passphrase: passphraseFor('HUB', env),
  };
}

module.exports = { FILE, CATS, MODULES, load, parseHashes, validHubUrl };
