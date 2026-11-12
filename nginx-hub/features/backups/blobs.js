'use strict';
/**
 * Stockage des archives sur disque, adressées par SHA-256 : <dir>/<2 premiers hex>/<sha256>.bin (hors base de données).
 * - le nom de fichier n'est JAMAIS construit à partir d'une entrée non validée (sha strictement /^[0-9a-f]{64}$/) ;
 * - écriture atomique (fichier temporaire puis rename), permissions 0600, répertoires 0700 ;
 * - plusieurs lignes en base peuvent référencer la même archive (déduplication) : la suppression d'un blob
 *   n'est faite que si plus aucune ligne ne le référence (voir service.gc).
 */
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { randomBytes } = require('node:crypto');

const SHA_RE = /^[0-9a-f]{64}$/;

class BlobStore {
  constructor(dir) { this.dir = dir; this.tmpDir = path.join(dir, 'tmp'); }

  async init() {
    await fsp.mkdir(this.tmpDir, { recursive: true, mode: 0o700 });
    // Nettoyage des envois interrompus (arrêt brutal pendant un upload)
    for (const f of await fsp.readdir(this.tmpDir)) await fsp.rm(path.join(this.tmpDir, f), { force: true });
  }

  static valid(sha) { return typeof sha === 'string' && SHA_RE.test(sha); }

  pathFor(sha) {
    if (!BlobStore.valid(sha)) throw new Error('sha256 invalide');
    return path.join(this.dir, sha.slice(0, 2), sha + '.bin');
  }

  tmpPath() { return path.join(this.tmpDir, randomBytes(12).toString('hex') + '.part'); }

  async has(sha) { try { return (await fsp.stat(this.pathFor(sha))).isFile(); } catch { return false; } }

  /** Place un fichier temporaire sous son nom définitif (ou le supprime s'il existe déjà). @returns {boolean} true si nouveau */
  async adopt(tmp, sha) {
    const dest = this.pathFor(sha);
    if (await this.has(sha)) { await fsp.rm(tmp, { force: true }); return false; }
    await fsp.mkdir(path.dirname(dest), { recursive: true, mode: 0o700 });
    await fsp.chmod(tmp, 0o600);
    await fsp.rename(tmp, dest);
    return true;
  }

  stream(sha) { return fs.createReadStream(this.pathFor(sha)); }

  async remove(sha) { await fsp.rm(this.pathFor(sha), { force: true }); }

  /** Supprime les blobs non référencés (et plus vieux que minAgeMs : protège un envoi en cours de validation). */
  async gc(referenced, minAgeMs = 10 * 60_000) {
    let removed = 0;
    let dirs = [];
    try { dirs = await fsp.readdir(this.dir, { withFileTypes: true }); } catch { return 0; }
    for (const d of dirs) {
      if (!d.isDirectory() || !/^[0-9a-f]{2}$/.test(d.name)) continue;
      for (const f of await fsp.readdir(path.join(this.dir, d.name))) {
        const m = /^([0-9a-f]{64})\.bin$/.exec(f);
        if (!m || referenced.has(m[1])) continue;
        const p = path.join(this.dir, d.name, f);
        try { if (Date.now() - (await fsp.stat(p)).mtimeMs > minAgeMs) { await fsp.rm(p, { force: true }); removed++; } } catch { /* disparu */ }
      }
    }
    return removed;
  }
}

module.exports = { BlobStore, SHA_RE };
