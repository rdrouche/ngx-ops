'use strict';
/**
 * Sauvegarde vers NGX Ops Hub (v12.76.0) — collecte, archive tar.gz, chiffrement.
 *
 *  - Catégories : nginx (sites/conf/snippets/streams), ngxops (config/*.yml|json…),
 *    env (valeurs effectives, secrets MASQUÉS), ssl (opt-in).
 *  - Les fichiers « secrets » (users.yml, mfa.json, .generated-secrets.json, smtp.yml,
 *    clés privées…) sont EXCLUS sauf `include_secrets: true`, et dans ce cas
 *    l'archive est obligatoirement chiffrée (AES-256-GCM, clé dérivée par scrypt
 *    d'une phrase de passe que seul l'admin connaît) : jamais de secret en clair.
 *  - Pas de dépendance : tar (ustar) écrit à la main + zlib.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

const MAGIC = Buffer.from('NGXB1');
const LIMITS = { files: 5000, fileBytes: 5 * 1024 * 1024, totalBytes: 100 * 1024 * 1024, depth: 6 };
const CONF_EXT = /\.(conf|yml|yaml|json|txt|map|inc|cnf|html|snip)$/i;
const SECRET_NAME = /^(users\.yml|mfa\.json|smtp\.yml|\.generated-secrets\.json)$|secret|token|passw|\.key$|\.pem$|id_rsa|\.p12$|\.pfx$/i;

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');

function walk(dir, base, category, out, skipped, depth = 0, opts = {}) {
  let names;
  try { names = fs.readdirSync(dir); } catch { return; }
  for (const name of names.sort()) {
    const abs = path.join(dir, name);
    let st;
    try { st = fs.lstatSync(abs); } catch { continue; }
    if (st.isSymbolicLink()) { skipped.push({ path: abs.replace(base, ''), reason: 'symlink' }); continue; }
    if (st.isDirectory()) { if (depth < LIMITS.depth && !(opts.flat && depth >= 0)) walk(abs, base, category, out, skipped, depth + 1, opts); continue; }
    if (!st.isFile()) continue;
    if (opts.ext && !opts.ext.test(name)) continue;
    if (st.size > LIMITS.fileBytes) { skipped.push({ path: name, reason: 'too_large' }); continue; }
    out.push({ abs, rel: path.join(opts.prefix || category, path.relative(base, abs)).split(path.sep).join('/'), category, secret: SECRET_NAME.test(name), size: st.size });
  }
}

/** Valeurs effectives des variables, secrets masqués (jamais la valeur). */
function effectiveEnv() {
  const { ENTRIES } = require('./system-info');
  const rows = ENTRIES.map(e => ({
    key: e.key, category: e.category,
    value: e.sensitive ? (e.value ? '***set***' : '***unset***') : e.value,
    default: e.sensitive ? undefined : e.default,
    overridden: !!e.override,
  }));
  return Buffer.from(JSON.stringify({ schema: 1, variables: rows }, null, 2));
}

/**
 * @param {{dirs:{nginx:string[],config:string,ssl:string}, include:string[], includeSecrets:boolean}} o
 * @returns {{files:Array, excludedSecrets:string[], skipped:Array}}
 */
function collect({ dirs, include = ['nginx', 'ngxops', 'env'], includeSecrets = false }) {
  const all = [], skipped = [];
  if (include.includes('nginx')) for (const d of dirs.nginx || []) walk(d, path.dirname(d), 'nginx', all, skipped, 0, { prefix: 'nginx' });
  if (include.includes('ngxops') && dirs.config) walk(dirs.config, dirs.config, 'ngxops', all, skipped, 0, { ext: CONF_EXT, prefix: 'ngxops', flat: true });
  if (include.includes('ssl') && dirs.ssl) walk(dirs.ssl, dirs.ssl, 'ssl', all, skipped, 0, { prefix: 'ssl' });
  const excludedSecrets = [];
  const files = [];
  let total = 0;
  for (const f of all) {
    if (f.secret && !includeSecrets) { excludedSecrets.push(f.rel); continue; }
    if (files.length >= LIMITS.files || total + f.size > LIMITS.totalBytes) { skipped.push({ path: f.rel, reason: 'limit' }); continue; }
    total += f.size; files.push(f);
  }
  return { files, excludedSecrets, skipped };
}

// ── tar ustar ───────────────────────────────────────────────────────────────
function tarHeader(name, size, mtime) {
  let prefix = '';
  let n = name;
  if (Buffer.byteLength(n) > 100) {
    const i = n.lastIndexOf('/', 155);
    if (i < 1 || Buffer.byteLength(n.slice(i + 1)) > 100) throw new Error('name too long: ' + name);
    prefix = n.slice(0, i); n = n.slice(i + 1);
  }
  const h = Buffer.alloc(512);
  h.write(n, 0, 100); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124);
  h.write(Math.floor(mtime / 1000).toString(8).padStart(11, '0') + '\0', 136);
  h.write('        ', 148); h.write('0', 156); h.write('ustar\0', 257); h.write('00', 263); h.write(prefix, 345, 155);
  let sum = 0; for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}
function tarEntry(name, data, mtime) {
  const pad = (512 - (data.length % 512)) % 512;
  return Buffer.concat([tarHeader(name, data.length, mtime), data, Buffer.alloc(pad)]);
}

/** Construit manifest + archive (tar.gz, éventuellement chiffrée). */
function build({ dirs, include, includeSecrets, passphrase, retentionDays, instance, now = Date.now() }) {
  if (includeSecrets && !passphrase) throw new Error('include_secrets requires HUB_BACKUP_PASSPHRASE (or BACKUP_PASSPHRASE) (secrets are never sent in clear)');
  const { files, excludedSecrets, skipped } = collect({ dirs, include, includeSecrets });
  const entries = [];
  for (const f of files) {
    let data; try { data = fs.readFileSync(f.abs); } catch { skipped.push({ path: f.rel, reason: 'unreadable' }); continue; }
    entries.push({ rel: f.rel, data, category: f.category, secret: f.secret });
  }
  if (include.includes('env')) entries.push({ rel: 'env/effective-env.json', data: effectiveEnv(), category: 'env', secret: false });
  const manifest = {
    schema: 1, generated_at: new Date(now).toISOString(), instance, retention_days: retentionDays,
    encrypted: !!passphrase, includes_secrets: !!includeSecrets, include,
    files: entries.map(e => ({ path: e.rel, size: e.data.length, sha256: sha256(e.data), category: e.category, secret: e.secret })),
    excluded_secrets: excludedSecrets, skipped,
  };
  const mbuf = Buffer.from(JSON.stringify(manifest, null, 2));
  const tar = Buffer.concat([tarEntry('manifest.json', mbuf, now), ...entries.map(e => tarEntry(e.rel, e.data, now)), Buffer.alloc(1024)]);
  let archive = zlib.gzipSync(tar, { level: 6 });
  if (passphrase) archive = encrypt(archive, passphrase);
  return { manifest, archive, sha256: sha256(archive) };
}

// ── chiffrement ─────────────────────────────────────────────────────────────
function encrypt(buf, passphrase) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(String(passphrase), salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([MAGIC, salt, iv, ct, c.getAuthTag()]);
}
function decrypt(buf, passphrase) {
  if (!buf.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('not an NGXB1 archive');
  const salt = buf.subarray(5, 21), iv = buf.subarray(21, 33), tag = buf.subarray(buf.length - 16), ct = buf.subarray(33, buf.length - 16);
  const key = crypto.scryptSync(String(passphrase), salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

module.exports = { build, collect, encrypt, decrypt, effectiveEnv, SECRET_NAME, MAGIC };
