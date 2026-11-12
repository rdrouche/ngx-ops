'use strict';
/**
 * TOTP (RFC 6238 / HOTP RFC 4226) — zéro dépendance, node:crypto uniquement.
 * SHA-1, 6 chiffres, pas de 30 s : les valeurs que tous les authentificateurs
 * (Google Authenticator, Aegis, 2FAS, Authy, Bitwarden, 1Password…) supportent.
 */
const crypto = require('crypto');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const b of buf) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str || '').toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) {
    const i = B32.indexOf(ch);
    if (i < 0) throw new Error('invalid base32');
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

function generateSecret() { return base32Encode(crypto.randomBytes(20)); }

function hotp(secretB32, counter, digits = 6) {
  const key = base32Decode(secretB32);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(buf).digest();
  const o = h[h.length - 1] & 15;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

function counterAt(nowMs = Date.now(), step = 30) { return Math.floor(nowMs / 1000 / step); }

/**
 * Vérifie un code à ±`window` pas. Retourne le compteur accepté ou null.
 * `lastCounter` : un compteur déjà consommé n'est plus accepté (anti-rejeu).
 */
function verify(secretB32, code, { window = 1, nowMs = Date.now(), lastCounter = -1 } = {}) {
  const c = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(c)) return null;
  const now = counterAt(nowMs);
  let found = null;
  for (let d = -window; d <= window; d++) {
    const ctr = now + d;
    const exp = hotp(secretB32, ctr);
    // comparaison à temps constant, on ne s'arrête pas au premier match
    if (crypto.timingSafeEqual(Buffer.from(exp), Buffer.from(c)) && found === null && ctr > lastCounter) found = ctr;
  }
  return found;
}

function otpauthUri({ secret, account, issuer = 'NGX Ops' }) {
  const label = encodeURIComponent(issuer) + ':' + encodeURIComponent(account);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

module.exports = { base32Encode, base32Decode, generateSecret, hotp, verify, counterAt, otpauthUri };
