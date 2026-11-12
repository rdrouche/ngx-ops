'use strict';
/**
 * Client S3 minimal, sans dependance (#117) : signature AWS SigV4 + PUT / DELETE / LIST (v2) / GET.
 * Compatible AWS, MinIO, Scaleway, OVH, Ceph... (adressage « path-style » ou « virtual-host »).
 * Securite : HTTPS obligatoire (http uniquement si allowInsecure), aucun identifiant dans l'URL, pas de redirection suivie,
 * delai et taille de reponse bornes, messages d'erreur limites au code/message S3 (jamais de cle ni de signature).
 */
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');
const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const encPath = (p) => p.split('/').map(enc).join('/');
const EMPTY_SHA = sha256hex('');

class S3Error extends Error {
  constructor(message, { status = 0, code = '' } = {}) { super(message); this.name = 'S3Error'; this.status = status; this.code = code; }
}

/**
 * Signature SigV4 d'une requete S3.
 * @param {{method:string, host:string, path:string, query?:Record<string,string>, headers?:Record<string,string>, payloadHash?:string,
 *          region:string, accessKey:string, secretKey:string, now?:Date}} o  `path` deja encode (commence par /).
 * @returns {{headers:Record<string,string>, signature:string, canonicalRequest:string, signedHeaders:string}}
 */
function signRequest(o) {
  const now = o.now || new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const date = amzDate.slice(0, 8);
  const payloadHash = o.payloadHash || EMPTY_SHA;
  const h = { host: o.host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  for (const [k, v] of Object.entries(o.headers || {})) h[k.toLowerCase()] = String(v).trim().replace(/\s+/g, ' ');
  const names = Object.keys(h).sort();
  const canonicalHeaders = names.map((n) => `${n}:${h[n]}\n`).join('');
  const signedHeaders = names.join(';');
  const canonicalQuery = Object.entries(o.query || {}).map(([k, v]) => [enc(k), enc(v)]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`).join('&');
  const canonicalRequest = [o.method, o.path, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${date}/${o.region}/s3/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');
  const kSigning = hmac(hmac(hmac(hmac('AWS4' + o.secretKey, date), o.region), 's3'), 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(toSign).digest('hex');
  h.authorization = `AWS4-HMAC-SHA256 Credential=${o.accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers: h, signature, canonicalRequest, signedHeaders };
}

const decodeXml = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
const tag = (xml, name) => { const m = xml.match(new RegExp(`<${name}>([\\s\\S]*?)</${name}>`)); return m ? decodeXml(m[1]) : ''; };

/** Valide l'endpoint (http(s) sans identifiants). @returns {URL} */
function parseEndpoint(endpoint, allowInsecure) {
  let u;
  try { u = new URL(endpoint); } catch { throw new S3Error('endpoint S3 invalide'); }
  if (u.protocol !== 'https:' && !(allowInsecure && u.protocol === 'http:')) throw new S3Error('endpoint S3 : HTTPS requis (http seulement avec allow_insecure)');
  if (u.username || u.password || !u.hostname) throw new S3Error('endpoint S3 : URL sans identifiants attendue');
  return u;
}

/**
 * @param {{endpoint:string, region:string, bucket:string, accessKey:string, secretKey:string, pathStyle?:boolean, allowInsecure?:boolean, timeoutMs?:number, maxResponseBytes?:number}} c
 */
function createClient(c) {
  const ep = parseEndpoint(c.endpoint, !!c.allowInsecure);
  const pathStyle = c.pathStyle !== false;
  const timeoutMs = c.timeoutMs || 30_000;
  const maxResp = c.maxResponseBytes || 16 * 1024 * 1024;
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(c.bucket || '')) throw new S3Error('nom de bucket invalide');

  function request(method, key, { query, body, contentType } = {}) {
    const data = body || Buffer.alloc(0);
    const host = pathStyle ? ep.host : `${c.bucket}.${ep.host}`;
    const base = ep.pathname.replace(/\/+$/, '');
    const objPath = key ? '/' + encPath(key) : '';
    const path = (pathStyle ? `${base}/${enc(c.bucket)}${objPath}` : `${base}${objPath || '/'}`) || '/';
    const headers = { 'content-length': String(data.length) };
    if (contentType) headers['content-type'] = contentType;
    const signed = signRequest({ method, host, path, query, headers, payloadHash: data.length ? sha256hex(data) : EMPTY_SHA, region: c.region, accessKey: c.accessKey, secretKey: c.secretKey });
    const qs = Object.entries(query || {}).map(([k, v]) => `${enc(k)}=${enc(v)}`).sort().join('&');
    const lib = ep.protocol === 'https:' ? https : http;
    return new Promise((resolve, reject) => {
      const req = lib.request({ protocol: ep.protocol, hostname: ep.hostname, port: ep.port || undefined, method, path: path + (qs ? '?' + qs : ''), headers: signed.headers, timeout: timeoutMs }, (res) => {
        const chunks = []; let n = 0;
        res.on('data', (d) => { n += d.length; if (n > maxResp) { req.destroy(new S3Error('reponse S3 trop volumineuse')); return; } chunks.push(d); });
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          if (res.statusCode >= 200 && res.statusCode < 300) return resolve({ status: res.statusCode, headers: res.headers, body: buf });
          const xml = buf.toString('utf8', 0, 4096);
          const code = tag(xml, 'Code').slice(0, 60), msg = tag(xml, 'Message').slice(0, 200).replace(/[\r\n]+/g, ' ');
          reject(new S3Error(`S3 ${method} ${res.statusCode}${code ? ' ' + code : ''}${msg ? ' : ' + msg : ''}`, { status: res.statusCode, code }));
        });
        res.on('error', reject);
      });
      req.on('timeout', () => req.destroy(new S3Error('delai S3 depasse')));
      req.on('error', (e) => reject(e instanceof S3Error ? e : new S3Error(`S3 injoignable : ${e.code || e.message}`)));
      req.end(data);
    });
  }

  return {
    put: (key, buf, contentType = 'application/octet-stream') => request('PUT', key, { body: buf, contentType }),
    get: async (key) => (await request('GET', key)).body,
    del: (key) => request('DELETE', key),
    /** Liste les objets d'un prefixe (pagination, 10 pages max). @returns {Promise<{key:string,size:number,lastModified:string}[]>} */
    async list(prefix = '', { maxKeys = 1000 } = {}) {
      const out = []; let token = '';
      for (let page = 0; page < 10; page++) {
        const q = { 'list-type': '2', prefix, 'max-keys': String(maxKeys) };
        if (token) q['continuation-token'] = token;
        const xml = (await request('GET', '', { query: q })).body.toString('utf8');
        for (const m of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) out.push({ key: tag(m[1], 'Key'), size: Number(tag(m[1], 'Size')) || 0, lastModified: tag(m[1], 'LastModified') });
        if (tag(xml, 'IsTruncated') !== 'true') break;
        token = tag(xml, 'NextContinuationToken');
        if (!token) break;
      }
      return out;
    },
  };
}

module.exports = { createClient, signRequest, parseEndpoint, S3Error, sha256hex };
