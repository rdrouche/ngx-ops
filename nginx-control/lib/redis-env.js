'use strict';
/**
 * Variables Redis transmises aux conteneurs gérés par le dashboard (analyzer, challenge).
 * Rien n'est ajouté si REDIS_URL est vide (comportement historique). Les valeurs sont
 * nettoyées (pas de retour ligne) ; le mot de passe n'est jamais journalisé.
 */
const { parseUrl } = require('./redis-lite');

const clean = v => String(v == null ? '' : v).replace(/[\r\n\0]/g, '').trim();

function base() {
  const url = clean(process.env.REDIS_URL);
  if (!url) return null;
  try { parseUrl(url); } catch { return null; } // URL invalide : on n'en propage pas
  return { url, password: String(process.env.REDIS_PASSWORD || '').replace(/[\r\n\0]/g, ''),
    prefix: clean(process.env.REDIS_PREFIX).replace(/[^A-Za-z0-9_-]/g, '') };
}

function analyzerEnv() {
  const b = base(); if (!b) return [];
  const out = [`REDIS_URL=${b.url}`];
  if (b.password) out.push(`REDIS_PASSWORD=${b.password}`);
  if (b.prefix) out.push(`REDIS_PREFIX=${b.prefix}`);
  return out;
}

function challengeEnv() {
  const b = base(); if (!b) return [];
  const out = [`NC_REDIS_URL=${b.url}`];
  if (b.password) out.push(`NC_REDIS_PASSWORD=${b.password}`);
  if (b.prefix) out.push(`NC_REDIS_PREFIX=${b.prefix}`);
  return out;
}

module.exports = { analyzerEnv, challengeEnv };
