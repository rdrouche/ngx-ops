'use strict';
/** TOTP (RFC 6238, SHA-1, 6 chiffres, pas de 30 s) — sans dépendance. */
const crypto = require('node:crypto');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0; let value = 0; let out = '';
  for (const b of buf) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  let bits = 0; let value = 0; const out = [];
  for (const ch of String(str).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '')) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('base32 invalide');
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

function generateSecret() { return base32Encode(crypto.randomBytes(20)); }

function hotp(secretB32, counter, digits = 6) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', base32Decode(secretB32)).update(msg).digest();
  const o = h[h.length - 1] & 0xf;
  const code = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(code % 10 ** digits).padStart(digits, '0');
}

const STEP = 30;

function totpAt(secretB32, tsMs = Date.now()) { return hotp(secretB32, Math.floor(tsMs / 1000 / STEP)); }

/**
 * Vérifie un code avec une fenêtre ±1 pas. `lastStep` empêche le rejeu d'un code déjà accepté.
 * @returns {{ok:boolean, step?:number}}
 */
function verifyTotp(secretB32, code, { tsMs = Date.now(), lastStep = 0, window = 1 } = {}) {
  const c = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(c)) return { ok: false };
  const now = Math.floor(tsMs / 1000 / STEP);
  let found = null;
  for (let w = -window; w <= window; w++) {
    const step = now + w;
    const expected = hotp(secretB32, step);
    // pas de sortie anticipée : temps constant sur la fenêtre
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(c)) && step > lastStep) found = step;
  }
  return found ? { ok: true, step: found } : { ok: false };
}

function otpauthUri(secretB32, account, issuer = 'NGX Ops Hub') {
  const label = encodeURIComponent(issuer) + ':' + encodeURIComponent(account);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${STEP}`;
}

module.exports = { generateSecret, totpAt, verifyTotp, otpauthUri, base32Encode, base32Decode };
