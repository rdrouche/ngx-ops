'use strict';
/**
 * WAF emule — validation (pure) de tout ce que le dashboard transmet au
 * conteneur `ngx-waf` : parametres de requete (liste blanche + bornes) et
 * corps JSON. Le navigateur ne choisit JAMAIS l'hote : c'est le nom du
 * conteneur de config/waf.yml (valide par lib/waf-config.js). Ici on ne
 * valide donc que des valeurs, jamais une destination (pas de SSRF).
 *
 * Chaque fonction retourne `{ ok:true, value }` ou `{ ok:false, error }` ;
 * `error` est un message technique court (anglais) destine a la reponse 400.
 * Le conteneur revalide strictement de son cote (defense en profondeur).
 */
const { isValidIpOrCidr } = require('./blocklist-parse');

const HOST_RE = /^[A-Za-z0-9._:-]{1,253}$/;
const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;
const SLUG_RE = /^[a-z0-9_-]{1,40}$/;
const EXC_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const CRS_RE = /^v?\d{1,2}\.\d{1,3}\.\d{1,3}(-rc\d{1,2})?$/;
const HTTP_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'CONNECT']);
const MODES = new Set(['observe', 'remediate']);
const LISTS = new Set(['block', 'challenge']);
const RULE_STATES = new Set(['active', 'disabled_global', 'disabled_system', 'ignored']);

const err = (error) => ({ ok: false, error });
const okv = (value) => ({ ok: true, value });
const hasCtl = (s) => /[\u0000-\u001f\u007f]/.test(s);
const isObj = (o) => o !== null && typeof o === 'object' && !Array.isArray(o);

/** IP seule (v4/v6), sans masque. */
function isSingleIp(s) { return typeof s === 'string' && !s.includes('/') && isValidIpOrCidr(s); }

function intIn(v, min, max, name) {
  const n = typeof v === 'string' && /^-?\d+$/.test(v.trim()) ? Number(v) : v;
  if (!Number.isInteger(n) || n < min || n > max) return err(`${name}: integer ${min}-${max} expected`);
  return okv(n);
}

/**
 * Applique un schema de parametres de requete : seules les cles du schema sont
 * retenues (liste blanche), chacune validee par sa fonction. Une cle inconnue
 * est ignoree (jamais retransmise) ; une valeur invalide -> erreur.
 * @param {URLSearchParams} sp
 * @param {Object<string,(v:string)=>{ok,value?,error?}>} schema
 */
function pickQuery(sp, schema) {
  const out = {};
  for (const [k, fn] of Object.entries(schema)) {
    if (!sp.has(k)) continue;
    const raw = sp.get(k);
    if (raw === '' ) continue;
    const r = fn(raw);
    if (!r.ok) return err(r.error);
    out[k] = r.value;
  }
  return okv(out);
}

const V = {
  int: (min, max, name) => (v) => intIn(v, min, max, name),
  enum: (set, name) => (v) => (set.has(v) ? okv(v) : err(`${name}: invalid value`)),
  ip: (name) => (v) => (isSingleIp(v) ? okv(v) : err(`${name}: IP address expected`)),
  host: (name) => (v) => (HOST_RE.test(v) ? okv(v) : err(`${name}: invalid host name`)),
  slug: (name) => (v) => (SLUG_RE.test(v) ? okv(v) : err(`${name}: invalid value`)),
  text: (max, name) => (v) => (v.length <= max && !hasCtl(v) ? okv(v) : err(`${name}: too long or control characters`)),
  flag: () => (v) => okv(v === '1' || v === 'true' ? '1' : '0'),
};

const SCHEMAS = {
  hits: {
    since: V.int(0, 8.64e15, 'since'), until: V.int(0, 8.64e15, 'until'),
    ip: V.ip('ip'), vhost: V.host('vhost'), rule: V.int(1, 2147483647, 'rule'),
    minScore: V.int(0, 100000, 'minScore'), mode: V.enum(MODES, 'mode'),
    limit: V.int(1, 500, 'limit'), offset: V.int(0, 10_000_000, 'offset'),
    order: V.enum(new Set(['asc', 'desc']), 'order'),
  },
  hitsStats: { hours: V.int(1, 720, 'hours') },
  rules: {
    q: V.text(100, 'q'), category: V.slug('category'), state: V.enum(RULE_STATES, 'state'),
    limit: V.int(1, 1000, 'limit'), offset: V.int(0, 100000, 'offset'),
  },
  alerts: {
    sinceId: V.int(0, 2147483647, 'sinceId'), order: V.enum(new Set(['asc', 'desc']), 'order'),
    limit: V.int(1, 500, 'limit'), raw: V.flag(),
  },
  lists: { list: V.enum(LISTS, 'list') },
};

const toQuery = (obj) => new URLSearchParams(Object.entries(obj).map(([k, v]) => [k, String(v)])).toString();

/** Corps de POST /api/waf/simulate. */
function validateSimulate(b) {
  if (!isObj(b)) return err('body: object expected');
  const out = {};
  const method = String(b.method || 'GET').toUpperCase();
  if (!HTTP_METHODS.has(method)) return err('method: invalid HTTP method');
  out.method = method;
  if (typeof b.uri !== 'string' || !b.uri.startsWith('/') || b.uri.length > 4096 || hasCtl(b.uri)) return err('uri: path starting with "/" expected (max 4096, no control characters)');
  out.uri = b.uri;
  if (b.vhost !== undefined && b.vhost !== '') {
    if (typeof b.vhost !== 'string' || !HOST_RE.test(b.vhost)) return err('vhost: invalid host name');
    out.vhost = b.vhost;
  }
  if (b.ua !== undefined && b.ua !== '') {
    if (typeof b.ua !== 'string' || b.ua.length > 512 || hasCtl(b.ua)) return err('ua: too long or control characters');
    out.ua = b.ua;
  }
  if (b.ip !== undefined && b.ip !== '') {
    if (!isSingleIp(b.ip)) return err('ip: IP address expected');
    out.ip = b.ip;
  }
  if (b.paranoia !== undefined && b.paranoia !== '' && b.paranoia !== null) {
    const p = intIn(b.paranoia, 1, 4, 'paranoia'); if (!p.ok) return p;
    out.paranoia = p.value;
  }
  if (b.headers !== undefined && b.headers !== null) {
    if (!isObj(b.headers)) return err('headers: object expected');
    const entries = Object.entries(b.headers);
    if (entries.length > 20) return err('headers: 20 entries max');
    const h = {};
    for (const [k, v] of entries) {
      if (!HEADER_NAME_RE.test(k)) return err('headers: invalid header name');
      if (typeof v !== 'string' || v.length > 1024 || hasCtl(v)) return err('headers: invalid header value');
      h[k] = v;
    }
    out.headers = h;
  }
  return okv(out);
}

function intList(v, min, max, maxLen, name) {
  if (!Array.isArray(v) || v.length > maxLen) return err(`${name}: array (max ${maxLen}) expected`);
  const out = [];
  for (const x of v) {
    const r = intIn(x, min, max, name); if (!r.ok) return r;
    out.push(r.value);
  }
  return okv([...new Set(out)]);
}

function ipList(v, maxLen, name) {
  if (!Array.isArray(v) || v.length > maxLen) return err(`${name}: array (max ${maxLen}) expected`);
  for (const x of v) if (typeof x !== 'string' || !isValidIpOrCidr(x)) return err(`${name}: IP or CIDR expected`);
  return okv([...new Set(v)]);
}

const RULE_MAX = 2147483647;
const SETTINGS_KEYS = new Set(['enable', 'mode', 'paranoia', 'thresholds', 'windowMinutes', 'listHours', 'alertMinScore',
  'vhostMode', 'vhosts', 'disabledRules', 'exceptions', 'ignoreStatus', 'excludeIps']);

/**
 * Corps de PUT /api/waf/settings : JSON COMPLET des reglages (WAF-CONTRACT.md).
 * Cles inconnues refusees ; la valeur normalisee ne contient que les cles connues.
 */
function validateSettings(b) {
  if (!isObj(b)) return err('body: object expected');
  for (const k of Object.keys(b)) if (!SETTINGS_KEYS.has(k)) return err(`unknown setting "${k}"`);
  const out = {};
  if (b.enable !== undefined) { if (typeof b.enable !== 'boolean') return err('enable: boolean expected'); out.enable = b.enable; }
  if (b.mode !== undefined) { if (!MODES.has(b.mode)) return err('mode: observe | remediate'); out.mode = b.mode; }
  if (b.paranoia !== undefined) { const r = intIn(b.paranoia, 1, 4, 'paranoia'); if (!r.ok) return r; out.paranoia = r.value; }
  if (b.thresholds !== undefined) {
    if (!isObj(b.thresholds)) return err('thresholds: object expected');
    const t = {};
    for (const k of ['challenge', 'block']) {
      if (b.thresholds[k] === undefined) continue;
      const r = intIn(b.thresholds[k], 1, 100000, `thresholds.${k}`); if (!r.ok) return r;
      t[k] = r.value;
    }
    for (const k of Object.keys(b.thresholds)) if (k !== 'challenge' && k !== 'block') return err(`thresholds: unknown key "${k}"`);
    out.thresholds = t;
  }
  if (b.windowMinutes !== undefined) { const r = intIn(b.windowMinutes, 1, 10080, 'windowMinutes'); if (!r.ok) return r; out.windowMinutes = r.value; }
  if (b.listHours !== undefined) {
    if (!isObj(b.listHours)) return err('listHours: object expected');
    const t = {};
    for (const k of Object.keys(b.listHours)) {
      if (k !== 'challenge' && k !== 'block') return err(`listHours: unknown key "${k}"`);
      const r = intIn(b.listHours[k], 1, 8760, `listHours.${k}`); if (!r.ok) return r;
      t[k] = r.value;
    }
    out.listHours = t;
  }
  if (b.alertMinScore !== undefined) { const r = intIn(b.alertMinScore, 0, 100000, 'alertMinScore'); if (!r.ok) return r; out.alertMinScore = r.value; }
  if (b.vhostMode !== undefined) {
    if (b.vhostMode !== 'all' && b.vhostMode !== 'selected') return err('vhostMode: all | selected');
    out.vhostMode = b.vhostMode;
  }
  if (b.vhosts !== undefined) {
    if (!isObj(b.vhosts)) return err('vhosts: object expected');
    const names = Object.keys(b.vhosts);
    if (names.length > 2000) return err('vhosts: 2000 entries max');
    const vh = {};
    for (const name of names) {
      if (!HOST_RE.test(name) || name === '__proto__') return err('vhosts: invalid host name');
      const v = b.vhosts[name];
      if (!isObj(v)) return err('vhosts: object expected per host');
      const o = {};
      for (const k of Object.keys(v)) {
        if (k === 'analyze') { if (typeof v.analyze !== 'boolean') return err('vhosts.analyze: boolean expected'); o.analyze = v.analyze; }
        else if (k === 'mode') { if (!MODES.has(v.mode)) return err('vhosts.mode: observe | remediate'); o.mode = v.mode; }
        else if (k === 'paranoia') { const r = intIn(v.paranoia, 1, 4, 'vhosts.paranoia'); if (!r.ok) return r; o.paranoia = r.value; }
        else if (k === 'disabledRules') { const r = intList(v.disabledRules, 1, RULE_MAX, 2000, 'vhosts.disabledRules'); if (!r.ok) return r; o.disabledRules = r.value; }
        else return err(`vhosts: unknown key "${k}"`);
      }
      vh[name] = o;
    }
    out.vhosts = vh;
  }
  if (b.disabledRules !== undefined) { const r = intList(b.disabledRules, 1, RULE_MAX, 5000, 'disabledRules'); if (!r.ok) return r; out.disabledRules = r.value; }
  if (b.exceptions !== undefined) {
    if (!Array.isArray(b.exceptions) || b.exceptions.length > 500) return err('exceptions: array (max 500) expected');
    const ids = new Set();
    const list = [];
    for (const e of b.exceptions) {
      if (!isObj(e)) return err('exceptions: object expected');
      for (const k of Object.keys(e)) if (!['id', 'rule', 'vhost', 'pathPrefix', 'uaContains', 'ip', 'reason', 'createdAt'].includes(k)) return err(`exceptions: unknown key "${k}"`);
      if (typeof e.id !== 'string' || !EXC_ID_RE.test(e.id) || ids.has(e.id)) return err('exceptions.id: unique identifier expected');
      ids.add(e.id);
      const rule = intIn(e.rule, 1, RULE_MAX, 'exceptions.rule'); if (!rule.ok) return rule;
      const o = { id: e.id, rule: rule.value };
      if (e.vhost !== undefined && e.vhost !== '') { if (typeof e.vhost !== 'string' || !HOST_RE.test(e.vhost)) return err('exceptions.vhost: invalid host name'); o.vhost = e.vhost; }
      if (e.pathPrefix !== undefined && e.pathPrefix !== '') { if (typeof e.pathPrefix !== 'string' || !e.pathPrefix.startsWith('/') || e.pathPrefix.length > 512 || hasCtl(e.pathPrefix)) return err('exceptions.pathPrefix: path starting with "/" expected'); o.pathPrefix = e.pathPrefix; }
      if (e.uaContains !== undefined && e.uaContains !== '') { if (typeof e.uaContains !== 'string' || e.uaContains.length > 200 || hasCtl(e.uaContains)) return err('exceptions.uaContains: invalid'); o.uaContains = e.uaContains; }
      if (e.ip !== undefined && e.ip !== '') { if (typeof e.ip !== 'string' || !isValidIpOrCidr(e.ip)) return err('exceptions.ip: IP or CIDR expected'); o.ip = e.ip; }
      if (e.reason !== undefined && e.reason !== '') { if (typeof e.reason !== 'string' || e.reason.length > 200 || hasCtl(e.reason)) return err('exceptions.reason: invalid'); o.reason = e.reason; }
      if (e.createdAt !== undefined && e.createdAt !== '') { if (typeof e.createdAt !== 'string' || e.createdAt.length > 40 || Number.isNaN(Date.parse(e.createdAt))) return err('exceptions.createdAt: ISO date expected'); o.createdAt = e.createdAt; }
      list.push(o);
    }
    out.exceptions = list;
  }
  if (b.ignoreStatus !== undefined) { const r = intList(b.ignoreStatus, 100, 599, 50, 'ignoreStatus'); if (!r.ok) return r; out.ignoreStatus = r.value; }
  if (b.excludeIps !== undefined) { const r = ipList(b.excludeIps, 500, 'excludeIps'); if (!r.ok) return r; out.excludeIps = r.value; }
  return okv(out);
}

/** Corps de POST /api/waf/lists/unlist. */
function validateUnlist(b) {
  if (!isObj(b)) return err('body: object expected');
  if (!isSingleIp(b.ip)) return err('ip: IP address expected');
  const list = b.list === undefined ? 'all' : b.list;
  if (list !== 'all' && !LISTS.has(list)) return err('list: block | challenge | all');
  return okv({ ip: b.ip, list });
}

/** Corps de POST /api/waf/alerts/ack. */
function validateAck(b) {
  if (!isObj(b)) return err('body: object expected');
  const r = intList(b.ids, 1, 2147483647, 500, 'ids'); if (!r.ok) return r;
  if (!r.value.length) return err('ids: at least one id expected');
  return okv({ ids: r.value });
}

/** Corps de POST /api/waf/rules/update (version optionnelle). */
function validateRulesUpdate(b) {
  if (b === undefined || b === null || (isObj(b) && b.version === undefined)) return okv({});
  if (!isObj(b)) return err('body: object expected');
  if (typeof b.version !== 'string' || !CRS_RE.test(b.version)) return err('version: CRS tag expected (e.g. v4.8.0)');
  return okv({ version: b.version.startsWith('v') ? b.version : 'v' + b.version });
}

/** Corps de PUT /api/waf/custom-rules. */
function validateCustomRules(b) {
  if (!isObj(b) || typeof b.text !== 'string') return err('text: string expected');
  if (b.text.length > 200_000) return err('text: 200000 characters max');
  if (/\u0000/.test(b.text)) return err('text: NUL character not allowed');
  return okv({ text: b.text });
}

module.exports = {
  SCHEMAS, pickQuery, toQuery, V, isSingleIp,
  validateSimulate, validateSettings, validateUnlist, validateAck, validateRulesUpdate, validateCustomRules,
};
