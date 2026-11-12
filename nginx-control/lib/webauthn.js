'use strict';
/**
 * WebAuthn minimal (clés de sécurité type YubiKey, passkeys) — node:crypto
 * uniquement. Attestation « none » (on ne vérifie pas la chaîne du
 * constructeur : standard pour un usage MFA interne) ; assertions vérifiées
 * complètement : rpIdHash, flags UP (+UV si exigé), origin, challenge,
 * signature (ES256 / RS256 / EdDSA) et compteur de signatures.
 */
const crypto = require('crypto');

// ── CBOR minimal (map/array/int/bytes/text/bool/null) ──────────────────────
function cborDecode(buf, offset = 0) {
  let pos = offset;
  function read() {
    if (pos >= buf.length) throw new Error('cbor: eof');
    const ib = buf[pos++];
    const major = ib >> 5; let ai = ib & 31; let n;
    if (ai < 24) n = ai;
    else if (ai === 24) { n = buf[pos]; pos += 1; }
    else if (ai === 25) { n = buf.readUInt16BE(pos); pos += 2; }
    else if (ai === 26) { n = buf.readUInt32BE(pos); pos += 4; }
    else if (ai === 27) { n = Number(buf.readBigUInt64BE(pos)); pos += 8; }
    else throw new Error('cbor: unsupported length');
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { const v = buf.subarray(pos, pos + n); if (v.length !== n) throw new Error('cbor: eof'); pos += n; return Buffer.from(v); }
      case 3: { const v = buf.subarray(pos, pos + n); if (v.length !== n) throw new Error('cbor: eof'); pos += n; return v.toString('utf8'); }
      case 4: { if (n > 1024) throw new Error('cbor: too big'); const a = []; for (let i = 0; i < n; i++) a.push(read()); return a; }
      case 5: { if (n > 1024) throw new Error('cbor: too big'); const m = new Map(); for (let i = 0; i < n; i++) { const k = read(); m.set(k, read()); } return m; }
      case 7: if (ai === 20) return false; if (ai === 21) return true; if (ai === 22) return null; throw new Error('cbor: unsupported simple');
      default: throw new Error('cbor: unsupported major');
    }
  }
  const value = read();
  return { value, end: pos };
}

const b64u = (b) => Buffer.from(b).toString('base64url');
const fromB64u = (s) => Buffer.from(String(s || ''), 'base64url');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();

function parseAuthData(ad) {
  if (ad.length < 37) throw new Error('authData too short');
  const out = {
    rpIdHash: ad.subarray(0, 32), flags: ad[32],
    up: !!(ad[32] & 1), uv: !!(ad[32] & 4), at: !!(ad[32] & 64),
    counter: ad.readUInt32BE(33), end: 37,
  };
  if (out.at) {
    if (ad.length < 55) throw new Error('attested data too short');
    out.aaguid = ad.subarray(37, 53);
    const len = ad.readUInt16BE(53);
    out.credentialId = Buffer.from(ad.subarray(55, 55 + len));
    const { value, end } = cborDecode(ad, 55 + len);
    out.coseKey = value; out.end = end;
  }
  return out;
}

/** Clé COSE (ES256 / RS256 / EdDSA) → KeyObject SPKI PEM. */
function coseToPem(cose) {
  if (!(cose instanceof Map)) throw new Error('bad COSE key');
  const kty = cose.get(1), alg = cose.get(3);
  let jwk;
  if (kty === 2 && alg === -7) {
    if (cose.get(-1) !== 1) throw new Error('unsupported curve');
    jwk = { kty: 'EC', crv: 'P-256', x: b64u(cose.get(-2)), y: b64u(cose.get(-3)) };
  } else if (kty === 3 && alg === -257) {
    jwk = { kty: 'RSA', n: b64u(cose.get(-1)), e: b64u(cose.get(-2)) };
  } else if (kty === 1 && alg === -8) {
    jwk = { kty: 'OKP', crv: 'Ed25519', x: b64u(cose.get(-2)) };
  } else throw new Error('unsupported key type/alg');
  const pem = crypto.createPublicKey({ key: jwk, format: 'jwk' }).export({ type: 'spki', format: 'pem' });
  return { pem, alg };
}

function checkClientData(clientDataJSON, { type, challenge, origins }) {
  let cd;
  try { cd = JSON.parse(Buffer.from(clientDataJSON).toString('utf8')); } catch { throw new Error('bad clientData'); }
  if (cd.type !== type) throw new Error('wrong type');
  if (cd.challenge !== challenge) throw new Error('challenge mismatch');
  if (!origins.includes(cd.origin)) throw new Error('origin mismatch');
  return cd;
}

/** Enregistrement : retourne { credentialId, publicKeyPem, alg, counter }. */
function verifyRegistration({ clientDataJSON, attestationObject }, { challenge, origins, rpId, requireUV = false }) {
  checkClientData(Buffer.from(clientDataJSON, 'base64url'), { type: 'webauthn.create', challenge, origins });
  const att = cborDecode(Buffer.from(attestationObject, 'base64url')).value;
  if (!(att instanceof Map)) throw new Error('bad attestation');
  const ad = parseAuthData(att.get('authData'));
  if (!ad.rpIdHash.equals(sha256(rpId))) throw new Error('rpId mismatch');
  if (!ad.up) throw new Error('user presence required');
  if (requireUV && !ad.uv) throw new Error('user verification required');
  if (!ad.at) throw new Error('no credential data');
  const { pem, alg } = coseToPem(ad.coseKey);
  return { credentialId: b64u(ad.credentialId), publicKeyPem: pem, alg, counter: ad.counter };
}

/** Authentification : lève une erreur si invalide ; retourne le nouveau compteur. */
function verifyAssertion({ clientDataJSON, authenticatorData, signature }, cred, { challenge, origins, rpId, requireUV = false }) {
  const cdBuf = Buffer.from(clientDataJSON, 'base64url');
  checkClientData(cdBuf, { type: 'webauthn.get', challenge, origins });
  const ad = Buffer.from(authenticatorData, 'base64url');
  const p = parseAuthData(ad);
  if (!p.rpIdHash.equals(sha256(rpId))) throw new Error('rpId mismatch');
  if (!p.up) throw new Error('user presence required');
  if (requireUV && !p.uv) throw new Error('user verification required');
  const data = Buffer.concat([ad, sha256(cdBuf)]);
  const sig = Buffer.from(signature, 'base64url');
  const key = crypto.createPublicKey(cred.publicKeyPem);
  let ok;
  if (cred.alg === -8) ok = crypto.verify(null, data, key, sig);
  else if (cred.alg === -257) ok = crypto.verify('sha256', data, key, sig);
  else ok = crypto.verify('sha256', data, key, sig); // ES256 : DER (format WebAuthn)
  if (!ok) throw new Error('bad signature');
  // Compteur : s'il est utilisé (≠ 0), il doit strictement croître (détection de clone).
  if ((p.counter !== 0 || cred.counter !== 0) && p.counter <= cred.counter) throw new Error('counter regression');
  return p.counter;
}

module.exports = { cborDecode, parseAuthData, coseToPem, verifyRegistration, verifyAssertion, b64u, fromB64u };
