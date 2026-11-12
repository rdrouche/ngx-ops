'use strict';
/**
 * Inspection MINIMALE d'une archive de sauvegarde — jamais d'extraction ni de décompression complète (anti zip-bomb,
 * anti path traversal) : on ne lit que l'en-tête ustar du premier fichier (manifest.json) dans les premiers Mo décompressés.
 * Archive chiffrée : "NGXB1" | salt(16) | iv(12) | ciphertext | tag(16) — opaque pour le Hub (il ne connaît pas la phrase).
 */
const fsp = require('node:fs/promises');
const zlib = require('node:zlib');
const fs = require('node:fs');

const MAGIC = Buffer.from('NGXB1');
const ENC_MIN = MAGIC.length + 16 + 12 + 16;
const MANIFEST_MAX = 900 * 1024;

async function head(file, n) {
  const fh = await fsp.open(file, 'r');
  try { const b = Buffer.alloc(n); const { bytesRead } = await fh.read(b, 0, n, 0); return b.subarray(0, bytesRead); } finally { await fh.close(); }
}

/** @returns {'encrypted'|'gzip'|'unknown'} */
async function sniff(file, size) {
  const b = await head(file, 8);
  if (size >= ENC_MIN && b.subarray(0, MAGIC.length).equals(MAGIC)) return 'encrypted';
  if (b[0] === 0x1f && b[1] === 0x8b) return 'gzip';
  return 'unknown';
}

function str(v, max = 200) { return typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max) : null; }
function num(v) { return Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1e15) : 0; }

/** Lit les premiers octets décompressés (plafond dur), sans jamais dépasser MANIFEST_MAX + 512. */
function inflateHead(file, limit) {
  return new Promise((resolve) => {
    const chunks = []; let size = 0; let done = false;
    const gz = zlib.createGunzip();
    const rs = fs.createReadStream(file, { end: 8 * 1024 * 1024 });
    const finish = (ok) => { if (done) return; done = true; rs.destroy(); gz.destroy(); resolve(ok ? Buffer.concat(chunks) : null); };
    gz.on('data', (d) => { chunks.push(d); size += d.length; if (size >= limit) finish(true); });
    gz.on('end', () => finish(true));
    gz.on('error', () => finish(size > 0));
    rs.on('error', () => finish(false));
    rs.pipe(gz);
  });
}

/**
 * @returns {Promise<object|null>} manifeste réduit et assaini, ou null si illisible (archive acceptée quand même : le contrat
 *   garantit manifest.json en premier, mais le Hub reste tolérant sur la forme tar — pax, préfixe « ./ »…).
 */
async function readManifest(file) {
  const buf = await inflateHead(file, MANIFEST_MAX + 512);
  if (!buf || buf.length < 512) return null;
  const name = buf.toString('latin1', 0, 100).replace(/\0.*$/s, '').replace(/^\.\//, '');
  if (name !== 'manifest.json') return null;
  const size = Number.parseInt(buf.toString('latin1', 124, 136).replace(/\0.*$/s, '').trim() || '0', 8);
  if (!Number.isFinite(size) || size <= 0 || size > MANIFEST_MAX || buf.length < 512 + size) return null;
  let m;
  try { m = JSON.parse(buf.toString('utf8', 512, 512 + size)); } catch { return null; }
  if (!m || typeof m !== 'object' || Array.isArray(m)) return null;
  const files = Array.isArray(m.files) ? m.files : [];
  const categories = {};
  let bytes = 0;
  for (const f of files.slice(0, 20000)) {
    const c = str(f && f.category, 24) || 'autre';
    categories[c] = (categories[c] || 0) + 1;
    bytes += num(f && f.size);
  }
  return {
    schema: num(m.schema),
    generated_at: str(m.generated_at, 40),
    instance: str(typeof m.instance === 'object' && m.instance ? m.instance.id : m.instance, 64),
    retention_days: num(m.retention_days),
    encrypted: !!m.encrypted,
    includes_secrets: !!m.includes_secrets,
    files: files.length,
    bytes,
    categories: Object.fromEntries(Object.entries(categories).slice(0, 20)),
    excluded_secrets: Array.isArray(m.excluded_secrets) ? m.excluded_secrets.length : 0,
    skipped: Array.isArray(m.skipped) ? m.skipped.length : 0,
  };
}

module.exports = { sniff, readManifest, ENC_MIN, MAGIC };
