// Déchiffrement local des sauvegardes NGX Ops (format NGXB1) dans le navigateur (#118).
// Format : "NGXB1" | sel(16) | iv(12) | données chiffrées | tag(16) ; AES-256-GCM, clé = scrypt(phrase, sel, N=2^15, r=8, p=1).
// La phrase de passe ne quitte jamais le navigateur. WebCrypto n'offre pas scrypt : implémentation JS pure
// (PBKDF2 et AES-GCM restent délégués à WebCrypto). Module sans accès DOM : testable sous Node.
const MAGIC = [0x4e, 0x47, 0x58, 0x42, 0x31]; // "NGXB1"
const SALT = 16, IV = 12, TAG = 16;
const N = 1 << 15, R = 8, P = 1;

export const MAX_UNPACKED = 512 * 1024 * 1024;

export function isNgxb(buf) {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return u.length >= MAGIC.length && MAGIC.every((b, i) => u[i] === b);
}

const rotl = (a, b) => (a << b) | (a >>> (32 - b));

function salsa8(B, x) {
  for (let i = 0; i < 16; i++) x[i] = B[i];
  for (let i = 0; i < 8; i += 2) {
    x[4] ^= rotl(x[0] + x[12], 7); x[8] ^= rotl(x[4] + x[0], 9); x[12] ^= rotl(x[8] + x[4], 13); x[0] ^= rotl(x[12] + x[8], 18);
    x[9] ^= rotl(x[5] + x[1], 7); x[13] ^= rotl(x[9] + x[5], 9); x[1] ^= rotl(x[13] + x[9], 13); x[5] ^= rotl(x[1] + x[13], 18);
    x[14] ^= rotl(x[10] + x[6], 7); x[2] ^= rotl(x[14] + x[10], 9); x[6] ^= rotl(x[2] + x[14], 13); x[10] ^= rotl(x[6] + x[2], 18);
    x[3] ^= rotl(x[15] + x[11], 7); x[7] ^= rotl(x[3] + x[15], 9); x[11] ^= rotl(x[7] + x[3], 13); x[15] ^= rotl(x[11] + x[7], 18);
    x[1] ^= rotl(x[0] + x[3], 7); x[2] ^= rotl(x[1] + x[0], 9); x[3] ^= rotl(x[2] + x[1], 13); x[0] ^= rotl(x[3] + x[2], 18);
    x[6] ^= rotl(x[5] + x[4], 7); x[7] ^= rotl(x[6] + x[5], 9); x[4] ^= rotl(x[7] + x[6], 13); x[5] ^= rotl(x[4] + x[7], 18);
    x[11] ^= rotl(x[10] + x[9], 7); x[8] ^= rotl(x[11] + x[10], 9); x[9] ^= rotl(x[8] + x[11], 13); x[10] ^= rotl(x[9] + x[8], 18);
    x[12] ^= rotl(x[15] + x[14], 7); x[13] ^= rotl(x[12] + x[15], 9); x[14] ^= rotl(x[13] + x[12], 13); x[15] ^= rotl(x[14] + x[13], 18);
  }
  for (let i = 0; i < 16; i++) B[i] += x[i];
}

// B : 32*r mots (modifié en place) ; Y, t, x : tampons de travail
function blockMix(B, Y, r, t, x) {
  for (let i = 0; i < 16; i++) t[i] = B[(2 * r - 1) * 16 + i];
  for (let i = 0; i < 2 * r; i++) {
    for (let k = 0; k < 16; k++) t[k] ^= B[i * 16 + k];
    salsa8(t, x);
    for (let k = 0; k < 16; k++) Y[i * 16 + k] = t[k];
  }
  for (let i = 0; i < r; i++) {
    for (let k = 0; k < 16; k++) { B[i * 16 + k] = Y[2 * i * 16 + k]; B[(i + r) * 16 + k] = Y[(2 * i + 1) * 16 + k]; }
  }
}

const tick = () => new Promise((res) => setTimeout(res, 0));

async function roMix(B, n, r, onProgress) {
  const len = 32 * r, V = new Int32Array(len * n), Y = new Int32Array(len), t = new Int32Array(16), x = new Int32Array(16);
  const step = 2048;
  for (let i = 0; i < n; i++) {
    V.set(B, i * len); blockMix(B, Y, r, t, x);
    if (i % step === step - 1) { onProgress?.(i / (2 * n)); await tick(); }
  }
  for (let i = 0; i < n; i++) {
    const j = B[(2 * r - 1) * 16] & (n - 1);
    for (let k = 0; k < len; k++) B[k] ^= V[j * len + k];
    blockMix(B, Y, r, t, x);
    if (i % step === step - 1) { onProgress?.(0.5 + i / (2 * n)); await tick(); }
  }
}

async function pbkdf2(pass, salt, bits) {
  const key = await crypto.subtle.importKey('raw', pass, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 1 }, key, bits));
}

/** scrypt (RFC 7914) : PBKDF2(1) → ROMix par bloc → PBKDF2(1). Little-endian supposé (toutes les plateformes visées). */
export async function scrypt(passBytes, salt, { n = N, r = R, p = P, dkLen = 32, onProgress } = {}) {
  const B = await pbkdf2(passBytes, salt, p * 128 * r * 8);
  for (let i = 0; i < p; i++) {
    const w = new Int32Array(32 * r);
    new Uint8Array(w.buffer).set(B.subarray(i * 128 * r, (i + 1) * 128 * r));
    await roMix(w, n, r, onProgress);
    B.set(new Uint8Array(w.buffer), i * 128 * r);
  }
  return pbkdf2(passBytes, B, dkLen * 8);
}

/** Déchiffre une archive NGXB1. @returns {Promise<Uint8Array>} tar.gz en clair. Codes : insecure_context, not_ngxb, bad_passphrase. */
export async function decryptNgxb(buf, passphrase, { onProgress } = {}) {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (!globalThis.crypto?.subtle) throw Object.assign(new Error('Le déchiffrement local exige HTTPS (ou localhost).'), { code: 'insecure_context' });
  if (u.length < MAGIC.length + SALT + IV + TAG || !isNgxb(u)) throw Object.assign(new Error('Ce fichier n’est pas une archive NGXB1.'), { code: 'not_ngxb' });
  const salt = u.subarray(5, 5 + SALT), iv = u.subarray(5 + SALT, 5 + SALT + IV), body = u.subarray(5 + SALT + IV);
  const keyBytes = await scrypt(new TextEncoder().encode(String(passphrase)), salt, { onProgress });
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  try {
    // WebCrypto attend « données chiffrées || tag », exactement la disposition du format
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, body));
  } catch { throw Object.assign(new Error('Phrase de passe incorrecte ou archive altérée.'), { code: 'bad_passphrase' }); }
}

/** Décompresse du gzip avec plafond (anti « bombe »). Code : too_big. */
export async function gunzip(u8, max = MAX_UNPACKED) {
  const reader = new Blob([u8]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
  const parts = []; let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) { await reader.cancel(); throw Object.assign(new Error('Archive décompressée trop volumineuse.'), { code: 'too_big' }); }
    parts.push(value);
  }
  const out = new Uint8Array(total); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const dec = new TextDecoder();
const cstr = (u, a, b) => { let e = a; while (e < b && u[e] !== 0) e++; return dec.decode(u.subarray(a, e)); };

/** Liste les fichiers d'un tar (ustar). @returns {{path:string,size:number,offset:number}[]} Code : bad_tar. */
export function parseTar(u) {
  const out = [];
  let o = 0;
  while (o + 512 <= u.length) {
    if (u.subarray(o, o + 512).every((b) => b === 0)) break;
    const name = cstr(u, o, o + 100), prefix = cstr(u, o + 345, o + 500);
    const size = parseInt(cstr(u, o + 124, o + 136).trim() || '0', 8);
    const type = String.fromCharCode(u[o + 156] || 48);
    if (!Number.isFinite(size) || size < 0 || o + 512 + size > u.length) throw Object.assign(new Error('Archive tar tronquée ou invalide.'), { code: 'bad_tar' });
    if (type === '0') out.push({ path: prefix ? `${prefix}/${name}` : name, size, offset: o + 512 });
    o += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

export const readEntry = (u, e) => u.subarray(e.offset, e.offset + e.size);

/** Texte affichable ? (pas d'octet nul dans le début du fichier) */
export const looksText = (b) => !b.subarray(0, 4096).includes(0);
