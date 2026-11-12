'use strict';
/** Validation des entrées « instance » (création / modification). */
const { parseInstanceUrl } = require('../../lib/security');

const TOKEN_RE = /^[A-Za-z0-9._~-]{16,200}$/;
const TAG_RE = /^[\p{L}\p{N} ._-]{1,24}$/u;

/** @returns {{ok:true,value:object}|{ok:false,error:string}} */
function validateInstanceInput(body, policy, { partial = false } = {}) {
  const v = {};
  if (!partial || body.name !== undefined) {
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (name.length < 1 || name.length > 60 || /[\u0000-\u001f<>]/.test(name)) return { ok: false, error: 'nom : 1–60 caractères, sans < > ni contrôle' };
    v.name = name;
  }
  if (!partial || body.url !== undefined) {
    const r = parseInstanceUrl(body.url, policy);
    if (!r.ok) return { ok: false, error: 'url : ' + r.error };
    v.url = r.url;
  }
  if (body.token !== undefined && body.token !== null && body.token !== '') {
    if (typeof body.token !== 'string' || !TOKEN_RE.test(body.token)) return { ok: false, error: 'token : 16–200 caractères [A-Za-z0-9._~-]' };
    v.token = body.token;
  }
  if (body.tags !== undefined) {
    if (!Array.isArray(body.tags) || body.tags.length > 8 || !body.tags.every((t) => typeof t === 'string' && TAG_RE.test(t))) {
      return { ok: false, error: 'tags : 8 maximum, 1–24 caractères alphanumériques' };
    }
    v.tags = [...new Set(body.tags.map((t) => t.trim()))];
  }
  if (body.enabled !== undefined) {
    if (typeof body.enabled !== 'boolean') return { ok: false, error: 'enabled : booléen attendu' };
    v.enabled = body.enabled;
  }
  return { ok: true, value: v };
}

module.exports = { validateInstanceInput };
