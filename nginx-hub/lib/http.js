'use strict';
/** Helpers HTTP : JSON, corps borné, cookies, fichiers statiques sans traversée de répertoire. */
const fs = require('node:fs');
const path = require('node:path');

const MAX_BODY = 64 * 1024;

class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code || 'error'; }
}

function sendJson(res, status, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), ...headers });
  res.end(body);
}

function readJson(req, limit = MAX_BODY) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers['content-type'] || '');
    if (!/^application\/json\b/i.test(ct)) return reject(new HttpError(415, 'Content-Type application/json requis', 'unsupported_media_type'));
    const chunks = []; let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new HttpError(413, 'Corps trop volumineux', 'payload_too_large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!size) return resolve({});
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('objet attendu');
        resolve(v);
      } catch { reject(new HttpError(400, 'JSON invalide', 'bad_json')); }
    });
    req.on('error', reject);
  });
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function cookieString(name, value, { maxAge, secure = true } = {}) {
  let s = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict`;
  if (secure) s += '; Secure';
  if (maxAge !== undefined) s += `; Max-Age=${maxAge}`;
  return s;
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8', '.woff2': 'font/woff2',
};

/** Sert un fichier de `root` ; refuse toute sortie du répertoire. Renvoie false si introuvable. */
function serveStatic(root, relPath, req, res) {
  let rel;
  try { rel = decodeURIComponent(relPath); } catch { return false; }
  if (rel.includes('\0')) return false;
  const abs = path.resolve(root, '.' + path.posix.normalize('/' + rel));
  if (abs !== root && !abs.startsWith(root + path.sep)) return false;
  let st;
  try { st = fs.statSync(abs); } catch { return false; }
  if (!st.isFile()) return false;
  const ext = path.extname(abs).toLowerCase();
  const type = MIME[ext];
  if (!type) return false;
  const headers = {
    'Content-Type': type, 'Content-Length': st.size,
    'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=300',
    ETag: `W/"${st.size}-${Math.floor(st.mtimeMs)}"`,
  };
  if (req.headers['if-none-match'] === headers.ETag) { res.writeHead(304, headers); res.end(); return true; }
  res.writeHead(200, headers);
  if (req.method === 'HEAD') res.end(); else fs.createReadStream(abs).pipe(res);
  return true;
}

module.exports = { HttpError, sendJson, readJson, parseCookies, cookieString, serveStatic };
