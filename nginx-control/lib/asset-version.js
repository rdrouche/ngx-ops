'use strict';
/**
 * Cache des fichiers statiques : evite qu'un navigateur (ou un proxy) serve une ancienne version
 * de l'interface apres une mise a jour.
 *  - computeVersion : empreinte courte des fichiers (chemin, taille, date) ; change a chaque deploiement.
 *  - versionAssetUrls : ajoute ?v=<empreinte> aux src/href vers /assets/ dans le HTML servi.
 *  - etagOf : validateur de contenu pour les assets (If-None-Match -> 304).
 * Module pur : aucune dependance au serveur HTTP.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function listFiles(dir, out = []) {
  let ents;
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of ents) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) listFiles(p, out); else out.push(p);
  }
  return out;
}

/** @param {string[]} roots  fichiers ou dossiers a empreinter */
function computeVersion(roots) {
  const h = crypto.createHash('sha1');
  const files = [];
  for (const r of roots) {
    try { if (fs.statSync(r).isDirectory()) listFiles(r, files); else files.push(r); } catch { /* absent */ }
  }
  files.sort();
  for (const f of files) {
    try { const s = fs.statSync(f); h.update(`${f}:${s.size}:${Math.floor(s.mtimeMs)}\n`); } catch { /* disparu */ }
  }
  return h.digest('hex').slice(0, 10);
}

const ASSET_URL_RE = /\b((?:src|href)=")(\/assets\/[^"?#]+\.(?:js|css|mjs|svg|png|woff2?))(")/g;
function versionAssetUrls(html, version) {
  if (!/^[a-f0-9]{6,40}$/.test(String(version))) return html;
  return html.replace(ASSET_URL_RE, `$1$2?v=${version}$3`);
}

function etagOf(buf) {
  return '"' + crypto.createHash('sha1').update(buf).digest('base64url').slice(0, 22) + '"';
}

/** true si le navigateur a deja cette version (If-None-Match). */
function notModified(ifNoneMatch, etag) {
  if (!ifNoneMatch) return false;
  return String(ifNoneMatch).split(',').map((s) => s.trim().replace(/^W\//, '')).includes(etag);
}

module.exports = { computeVersion, versionAssetUrls, etagOf, notModified };
