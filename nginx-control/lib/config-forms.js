'use strict';
/**
 * Moteur des formulaires de configuration (#102) : valide un corps de formulaire selon le schema d'un fichier
 * (lib/config-schemas.js) et met a jour le YAML PLAT ligne par ligne — commentaires, cles inconnues et listes sont
 * conserves tels quels. Les secrets ne sont jamais renvoyes (`set`), une valeur vide supprime la cle (le repli env
 * s'applique), les valeurs sont ecrites sans commentaire de fin de ligne (compatible avec tous les lecteurs).
 */
const { parseFlatYaml } = require('./simple-yaml');

const MAX = 300;
const CTRL = /[\u0000-\u001f\u007f"]/;           // controles et guillemet : jamais dans une valeur
const EMAIL_RE = /^[^\s@"]{1,100}@[^\s@"]{1,200}$/;
const IMAGE_RE = /^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,250}$/;
const PATH_RE = /^\/[A-Za-z0-9._@+:\/-]{0,299}$/;
const CRON_RE = /^[0-9*\/,\-]+( [0-9*\/,\-]+){4}$/;
const MASK_RE = /^\*+$/;

const stripUserinfo = (u) => { try { const x = new URL(u); if (!x.username && !x.password) return u; x.username = ''; x.password = ''; return x.toString().replace(/\/$/, u.endsWith('/') ? '/' : ''); } catch { return u; } };
const hasUserinfo = (u) => { try { const x = new URL(u); return !!(x.username || x.password); } catch { return false; } };

/** Valide une valeur (non vide) ; renvoie { v } (texte a ecrire) ou { err }. */
function validate(f, raw) {
  const s = typeof raw === 'string' ? raw.trim() : raw;
  switch (f.type) {
    case 'bool': if (s === true || s === 'true') return { v: 'true' }; if (s === false || s === 'false') return { v: 'false' }; return { err: 'booleen attendu' };
    case 'int': case 'number': {
      const n = Number(s);
      if (s === '' || !Number.isFinite(n) || (f.type === 'int' && !Number.isInteger(n))) return { err: f.type === 'int' ? 'entier attendu' : 'nombre attendu' };
      if ((f.min != null && n < f.min) || (f.max != null && n > f.max)) return { err: `entre ${f.min} et ${f.max}` };
      return { v: String(n) };
    }
    case 'enum': return (f.options || []).includes(s) ? { v: s } : { err: 'valeur non autorisee' };
    case 'cron': return typeof s === 'string' && CRON_RE.test(s) && s.length <= 100 ? { v: s } : { err: 'cron a 5 champs attendu' };
    case 'regex': {
      if (typeof s !== 'string' || !s || s.length > MAX || CTRL.test(s)) return { err: 'expression invalide' };
      try { new RegExp(s); } catch { return { err: 'expression reguliere invalide' }; }
      return { v: s };
    }
    default: break;
  }
  if (typeof s !== 'string' || s.length > MAX || CTRL.test(s)) return { err: 'caracteres interdits ou valeur trop longue' };
  switch (f.type) {
    case 'path': return PATH_RE.test(s) && !s.split('/').includes('..') ? { v: s } : { err: 'chemin absolu attendu (sans ..)' };
    case 'url': { let u; try { u = new URL(s); } catch { return { err: 'URL invalide' }; }
      return /^https?:$/.test(u.protocol) && !u.username && !u.password ? { v: s } : { err: 'URL http(s) sans identifiants attendue' }; }
    case 'email': return EMAIL_RE.test(s) ? { v: s } : { err: 'adresse invalide' };
    case 'image': return IMAGE_RE.test(s) ? { v: s } : { err: 'reference d\'image invalide' };
    case 'secret': return /\s/.test(s) ? { err: 'espaces interdits' } : { v: s };
    default: return f.pattern && !f.pattern.test(s) ? { err: 'format invalide' } : { v: s };
  }
}

const fmt = (f, v) => (f.type === 'cron' ? `"${v}"` : quoteIfNeeded(v));
const quoteIfNeeded = (v) => (/^[^\s#'"]([^#'"]*[^\s#'"])?$/.test(v) && !/\s#/.test(v) ? v : `"${v}"`);

/** Pose (value, deja formate) ou retire (null) la cle `key` dans un YAML plat, en conservant le reste. */
function setKey(text, key, value) {
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const lines = text === '' ? [] : text.split(/\r?\n/);
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  const re = new RegExp('^' + key + '\\s*:(\\s|$)');
  const idx = lines.findIndex((l) => re.test(l));
  if (value == null) { if (idx >= 0) lines.splice(idx, 1); }
  else {
    const line = `${key}: ${value}`;
    if (idx >= 0) lines[idx] = line; else lines.push(line);
  }
  return lines.length ? lines.join(eol) + eol : '';
}

/** Vue du formulaire : valeurs non secretes, `set` pour les secrets, URL sans identifiants (`credentials`). */
function formView(schema, text) {
  const y = parseFlatYaml(text);
  const values = {}; const secretSet = {}; const credentials = {};
  for (const f of schema.fields) {
    const raw = y[f.key];
    if (f.type === 'secret') { secretSet[f.key] = !!raw; continue; }
    if (f.type === 'url' && raw && hasUserinfo(raw)) { values[f.key] = stripUserinfo(raw); credentials[f.key] = true; continue; }
    values[f.key] = raw === undefined ? '' : raw;
  }
  return { values, secretSet, credentials };
}

/**
 * @returns {{ ok: true, text: string } | { ok: false, errors: Object<string,string> }}
 * Champ absent du corps = inchange. Secret : vide ou masque = conserve, `clear_<cle>: true` = supprime.
 */
function applyForm(schema, body, previous) {
  const b = body && typeof body === 'object' ? body : {};
  const prev = parseFlatYaml(previous);
  const errors = {}; let text = previous || '';
  for (const f of schema.fields) {
    const sent = Object.prototype.hasOwnProperty.call(b, f.key);
    if (f.type === 'secret') {
      if (b['clear_' + f.key] === true) { text = setKey(text, f.key, null); continue; }
      const v = typeof b[f.key] === 'string' ? b[f.key].trim() : '';
      if (!v || MASK_RE.test(v)) continue;
      const r = validate(f, v); if (r.err) errors[f.key] = r.err; else text = setKey(text, f.key, fmt(f, r.v));
      continue;
    }
    if (!sent) continue;
    const raw = b[f.key];
    if (raw === '' || raw === null || raw === undefined) { text = setKey(text, f.key, null); continue; }
    if (f.type === 'url' && typeof raw === 'string' && prev[f.key] && hasUserinfo(prev[f.key]) && raw.trim() === stripUserinfo(prev[f.key])) continue; // identifiants existants conserves
    const r = validate(f, raw);
    if (r.err) errors[f.key] = r.err; else text = setKey(text, f.key, fmt(f, r.v));
  }
  return Object.keys(errors).length ? { ok: false, errors } : { ok: true, text };
}

module.exports = { validate, setKey, formView, applyForm };
