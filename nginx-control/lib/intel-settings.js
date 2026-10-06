'use strict';
/**
 * NGX Ops Intelligence (v12.69.0) — lecture et validation de
 * config/intelligence.yml. Pur (aucune E/S hors lecture du fichier passee par
 * l'appelant) pour rester testable.
 *
 * Priorités :
 *  - URL     : intelligence.yml (api_url) > INTEL_API_URL (ARG/ENV de l'image) > vide
 *  - jeton   : INTEL_TOKEN (ENV, recommandé pour un secret) > intelligence.yml (token)
 *  - le reste : intelligence.yml > valeurs par défaut ci-dessous
 */
const { stripInlineComment } = require('./simple-yaml');

const MODES = ['anonymous', 'identified'];
const SEVERITIES = ['low', 'medium', 'high'];
const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };

const DEFAULTS = Object.freeze({
  enable: false,
  mode: 'anonymous',
  apiUrl: '',
  user: '',
  token: '',
  intervalSeconds: 300,
  batchSize: 100,
  timeoutSeconds: 10,
  // Les alertes volumétriques n'ont pas de sens hors de l'instance qui les a produites.
  excludeRules: ['volumetric', 'country_traffic', 'data_volume'],
  includeRules: [],
  minSeverity: 'low',
  shareUserAgents: true,
  sharePaths: true,
  shareVhost: false,
  // v12.73.0 : blocages automatiques du challenge integre (IP qui echouent systematiquement). Opt-in :
  // la plateforme doit connaitre le type d'alerte `challenge` (voir README / prompt-intelligence).
  includeChallenge: false,
  backfillHours: 0,
  // Ping de connexion (POST /api/v1/ping) : intelligent, saute le ping si un lot vient de reussir.
  pingEnable: true,
  pingIntervalMinutes: 5,
  pingUrl: '',
});

// Cles reconnues de intelligence.yml ; `enabled` est un alias de `enable` (faute de frappe frequente).
const KNOWN_KEYS = new Set(['enable', 'enabled', 'mode', 'api_url', 'user', 'token', 'interval_seconds', 'batch_size',
  'timeout_seconds', 'exclude_rules', 'include_rules', 'min_severity', 'share_user_agents', 'share_paths', 'share_vhost', 'include_challenge', 'backfill_hours',
  'ping_enable', 'ping_interval_minutes', 'ping_url', 'url_ping']);

const RULE_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;

function unquote(v) {
  const s = stripInlineComment(v);
  if (/^".*"$/.test(s) || /^'.*'$/.test(s)) return s.slice(1, -1);
  return s;
}

/** Sous-ensemble YAML : `clé: scalaire`, `clé: [a, b]` et `clé:` suivie de `  - item`. */
function parseIntelYaml(text) {
  const out = {};
  let listKey = null;
  for (const raw of String(text || '').replace(/\r/g, '').split('\n')) {
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const item = raw.match(/^\s+-\s+(.*)$/);
    if (item && listKey) { out[listKey].push(unquote(item[1])); continue; }
    const m = raw.match(/^([a-z_]+)\s*:\s*(.*)$/);
    if (!m) { listKey = null; continue; }
    const val = stripInlineComment(m[2]);
    if (val === '') { listKey = m[1]; out[listKey] = []; continue; }
    listKey = null;
    if (/^\[.*\]$/.test(val)) {
      out[m[1]] = val.slice(1, -1).split(',').map(x => unquote(x.trim())).filter(Boolean);
    } else out[m[1]] = unquote(val);
  }
  return out;
}

const bool = (v, def) => (v === undefined ? def : String(v).toLowerCase() === 'true');
const intIn = (v, def, min, max) => {
  if (v === undefined || v === '') return def;
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.round(n))) : def;
};

/** URL d'envoi : https obligatoire, pas d'identifiants dans l'URL. Retourne { url, error }. */
function validateApiUrl(u) {
  if (!u) return { url: '', error: null };
  let p;
  try { p = new URL(u); } catch { return { url: '', error: 'api_url invalide' }; }
  if (p.protocol !== 'https:') return { url: '', error: 'api_url doit utiliser https://' };
  if (p.username || p.password) return { url: '', error: 'api_url ne doit pas contenir d identifiants' };
  return { url: p.toString(), error: null };
}

/** URL de ping derivee de l'URL d'envoi : `.../events` -> `.../ping`, sinon `<origine>/api/v1/ping`. */
function derivePingUrl(apiUrl) {
  if (!apiUrl) return '';
  try {
    const u = new URL(apiUrl);
    u.search = ''; u.hash = '';
    u.pathname = /\/events\/?$/.test(u.pathname) ? u.pathname.replace(/\/events\/?$/, '/ping') : '/api/v1/ping';
    return u.toString();
  } catch { return ''; }
}

/**
 * @param {string} text   contenu de intelligence.yml (peut être vide)
 * @param {object} env    { apiUrl, token }
 * @returns {{ settings, errors: string[] }}
 */
function normalizeIntelSettings(text, env = {}) {
  const y = parseIntelYaml(text);
  const errors = [];
  const s = { ...DEFAULTS };
  // v12.70.5 : cle inconnue = avertissement explicite (avant, `enabled: true` etait ignoree sans un mot).
  for (const k of Object.keys(y)) {
    if (!KNOWN_KEYS.has(k)) errors.push(`cle inconnue "${k}" ignoree (cles valides : ${[...KNOWN_KEYS].filter(x => x !== 'enabled').join(', ')})`);
  }
  s.enable = bool(y.enable !== undefined ? y.enable : y.enabled, DEFAULTS.enable);
  if (y.mode !== undefined) {
    if (MODES.includes(y.mode)) s.mode = y.mode;
    else errors.push(`mode invalide ("${y.mode}") : anonymous | identified`);
  }
  const rawUrl = (y.api_url || '').trim() || (env.apiUrl || '').trim();
  const u = validateApiUrl(rawUrl);
  s.apiUrl = u.url;
  if (u.error) errors.push(u.error);
  s.user = String(y.user || '').trim().slice(0, 254);
  if (s.user && !/^[^\s@]+@[^\s@]+$|^[A-Za-z0-9_.-]{1,64}$/.test(s.user)) {
    errors.push('user : adresse e-mail ou identifiant attendu'); s.user = '';
  }
  s.token = String(env.token || y.token || '').trim();
  s.intervalSeconds = intIn(y.interval_seconds, DEFAULTS.intervalSeconds, 60, 3600);
  s.batchSize = intIn(y.batch_size, DEFAULTS.batchSize, 1, 500);
  s.timeoutSeconds = intIn(y.timeout_seconds, DEFAULTS.timeoutSeconds, 3, 60);
  const rules = (key, def) => {
    if (y[key] === undefined) return [...def];
    const list = Array.isArray(y[key]) ? y[key] : String(y[key]).split(',');
    const ok = [];
    for (const r of list.map(x => String(x).trim()).filter(Boolean)) {
      if (RULE_NAME_RE.test(r)) ok.push(r); else errors.push(`${key} : nom de règle invalide "${r}"`);
    }
    return ok;
  };
  s.excludeRules = rules('exclude_rules', DEFAULTS.excludeRules);
  s.includeRules = rules('include_rules', DEFAULTS.includeRules);
  if (y.min_severity !== undefined) {
    if (SEVERITIES.includes(y.min_severity)) s.minSeverity = y.min_severity;
    else errors.push(`min_severity invalide ("${y.min_severity}") : low | medium | high`);
  }
  s.shareUserAgents = bool(y.share_user_agents, DEFAULTS.shareUserAgents);
  s.sharePaths = bool(y.share_paths, DEFAULTS.sharePaths);
  s.shareVhost = bool(y.share_vhost, DEFAULTS.shareVhost);
  s.includeChallenge = bool(y.include_challenge, DEFAULTS.includeChallenge);
  s.backfillHours = intIn(y.backfill_hours, 0, 0, 168);
  // Ping : active par defaut, toutes les 5 min (3 a 60). `ping_url` (alias `url_ping`) surcharge la
  // derivation automatique ; elle doit rester sur le MEME hote que api_url (le jeton ne part jamais ailleurs).
  s.pingEnable = bool(y.ping_enable, DEFAULTS.pingEnable);
  s.pingIntervalMinutes = intIn(y.ping_interval_minutes, DEFAULTS.pingIntervalMinutes, 3, 60);
  s.pingUrl = derivePingUrl(s.apiUrl);
  const customPing = (y.ping_url || y.url_ping || '').trim();
  if (customPing) {
    const pu = validateApiUrl(customPing);
    if (pu.error) errors.push('ping_url : ' + pu.error.replace(/^api_url\s*/, ''));
    else if (s.apiUrl && new URL(pu.url).host !== new URL(s.apiUrl).host) errors.push('ping_url : doit utiliser le meme hote que api_url (ignoree)');
    else if (pu.url) s.pingUrl = pu.url;
  }
  // Prérequis d'un envoi : l'URL, et en mode identifié l'utilisateur + le jeton.
  s.ready = !!s.apiUrl && (s.mode === 'anonymous' || (!!s.user && !!s.token));
  if (s.enable && !s.apiUrl) errors.push('enable: true mais aucune URL (api_url ou INTEL_API_URL)');
  if (s.enable && s.mode === 'identified' && (!s.user || !s.token)) errors.push('mode identified : user et token requis');
  return { settings: s, errors };
}

module.exports = { derivePingUrl, KNOWN_KEYS, DEFAULTS, MODES, SEVERITIES, SEVERITY_RANK, parseIntelYaml, normalizeIntelSettings, validateApiUrl };
