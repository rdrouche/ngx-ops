'use strict';
/**
 * Journal centralise (log store) — lecture et validation de config/logstore.yml (v12.80.0).
 * Pur : aucune E/S (le texte du fichier est passe par l'appelant), donc testable.
 *
 * Deux usages dans un seul fichier :
 *  - LECTURE (page « Journaux ») : `url` + jeton `read` du log store ;
 *  - ENVOI : conteneur shipper gere par le dashboard (`shipper_*`), seul point de sortie vers le log store.
 *
 * Priorites : jeton ENV (LOGSTORE_READ_TOKEN / LOGSINK_TOKEN) > yml. Les secrets ne quittent jamais
 * le serveur : ni le navigateur, ni les journaux, ni les reponses d'API.
 *
 * Securite des URL : elles viennent UNIQUEMENT de ce fichier (edite par un administrateur), jamais d'une
 * requete. https:// partout ; http:// seulement vers une boucle locale, un nom de service Docker (un seul
 * label) ou une IP privee — sauf `*_allow_insecure: true` explicite. Aucun identifiant, chemin ni requete
 * dans l'URL (le chemin est fixe cote client) ; aucune redirection n'est suivie au transport.
 */
const { stripInlineComment } = require('./simple-yaml');
const { validShipperUrl } = require('./shipper-url');

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/;
const IMAGE_RE = /^[A-Za-z0-9][A-Za-z0-9._\/:@-]{0,200}$/;
const INSTANCE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const TOKEN_RE = /^[A-Za-z0-9_.~+\/=-]{16,300}$/;
const SHIPPER_PORT = 9181;

const DEFAULTS = Object.freeze({
  enable: false,
  url: '',
  token: '',
  timeoutSeconds: 10,
  allowInsecure: false,
  // conteneur shipper gere par le dashboard
  shipperEnable: false,
  shipperName: 'ngx-shipper',
  shipperImage: '',
  shipperHostLogsPath: '',
  shipperHostDataPath: '',
  sinkUrl: '',
  sinkToken: '',
  sinkAllowInsecure: false,
  instance: '',
  shipperBlocklist: true,
  shipperCrowdsec: true,
  shipperCountry: false,
});

function unquote(raw) {
  const v = stripInlineComment(raw);
  if (v === '' || v === '~' || v.toLowerCase() === 'null') return '';
  if (/^".*"$/.test(v) || /^'.*'$/.test(v)) return v.slice(1, -1);
  return v;
}

function parseYaml(text) {
  const out = {};
  for (const line of String(text || '').replace(/\r/g, '').split('\n')) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const m = line.match(/^([a-z_]+)\s*:\s*(.*)$/);
    if (m) out[m[1]] = unquote(m[2]);
  }
  return out;
}

function validHostPath(p) {
  return typeof p === 'string' && p.startsWith('/') && p.length <= 512
    && !/[:\u0000-\u001f\u007f]/.test(p) && !p.split('/').includes('..');
}

/** URL `schema://hote[:port]` sans chemin/identifiants. `allowInsecure` leve la limite sur http://. */
function validLogstoreUrl(u, allowInsecure) {
  if (typeof u !== 'string' || !u || u.length > 255) return false;
  if (validShipperUrl(u)) return true;
  if (!allowInsecure) return false;
  let p;
  try { p = new URL(u); } catch { return false; }
  if (p.protocol !== 'http:' || p.username || p.password || (p.pathname !== '/' && p.pathname !== '') || p.search || p.hash) return false;
  return true;
}

/**
 * @param {string} text  contenu de logstore.yml
 * @param {{readToken?:string, sinkToken?:string, defaultLogsPath?:string, defaultImage?:string, instanceId?:string}} env
 * @returns {{config:object, errors:string[]}} config est toujours utilisable (valeurs par defaut si erreur)
 */
function normalizeLogstoreConfig(text, env = {}) {
  const y = parseYaml(text);
  const errors = [];
  const c = { ...DEFAULTS };

  const bool = (key, field) => {
    if (y[key] === undefined || y[key] === '') return;
    const v = String(y[key]).toLowerCase();
    if (v === 'true' || v === '1') c[field] = true;
    else if (v === 'false' || v === '0') c[field] = false;
    else errors.push(`${key} : true ou false attendu`);
  };
  bool('enable', 'enable');
  bool('allow_insecure', 'allowInsecure');
  bool('shipper_enable', 'shipperEnable');
  bool('shipper_allow_insecure', 'sinkAllowInsecure');
  bool('shipper_blocklist', 'shipperBlocklist');
  bool('shipper_crowdsec', 'shipperCrowdsec');
  bool('shipper_country', 'shipperCountry');

  if (y.timeout_seconds !== undefined && y.timeout_seconds !== '') {
    const n = /^\d+$/.test(y.timeout_seconds) ? Number(y.timeout_seconds) : NaN;
    if (n >= 2 && n <= 60) c.timeoutSeconds = n; else errors.push('timeout_seconds : entier entre 2 et 60 attendu');
  }

  const url = (key, field, allow) => {
    if (!y[key]) return;
    if (validLogstoreUrl(y[key], allow)) c[field] = y[key].replace(/\/+$/, '');
    else errors.push(`${key} : URL schema://hote:port attendue, sans chemin ni identifiants (http:// reserve a un hote local, un nom de service ou une IP privee, sauf allow_insecure)`);
  };
  url('url', 'url', c.allowInsecure);
  url('shipper_sink_url', 'sinkUrl', c.sinkAllowInsecure);
  if (!c.sinkUrl && c.url && !y.shipper_sink_url) { // meme serveur que la lecture, par defaut
    c.sinkUrl = c.url;
    if (c.allowInsecure) c.sinkAllowInsecure = true;
  }

  // Jetons : ENV > yml. Une valeur invalide est refusee (jamais recopiee dans un message).
  const token = (envVal, ymlVal, field, label) => {
    const v = envVal || ymlVal;
    if (!v) return;
    if (TOKEN_RE.test(v)) c[field] = v;
    else errors.push(`${label} : 16 a 300 caracteres (lettres, chiffres, _ . ~ + / = -)`);
  };
  token(env.readToken, y.token, 'token', env.readToken ? 'LOGSTORE_READ_TOKEN' : 'token');
  token(env.sinkToken, y.shipper_sink_token, 'sinkToken', env.sinkToken ? 'LOGSINK_TOKEN' : 'shipper_sink_token');

  if (y.shipper_name) {
    if (NAME_RE.test(y.shipper_name)) c.shipperName = y.shipper_name;
    else errors.push('shipper_name : nom de conteneur invalide');
  }
  if (y.shipper_image) {
    if (IMAGE_RE.test(y.shipper_image)) c.shipperImage = y.shipper_image;
    else errors.push('shipper_image : nom d image invalide');
  }
  for (const [key, field] of [['shipper_host_logs_path', 'shipperHostLogsPath'], ['shipper_host_data_path', 'shipperHostDataPath']]) {
    if (!y[key]) continue;
    if (validHostPath(y[key])) c[field] = y[key].length > 1 ? y[key].replace(/\/+$/, '') : y[key];
    else errors.push(`${key} : chemin HOTE absolu attendu, sans « : », sans « .. » ni caractere de controle`);
  }
  if (!c.shipperHostLogsPath && env.defaultLogsPath && validHostPath(env.defaultLogsPath)) c.shipperHostLogsPath = env.defaultLogsPath;
  if (!c.shipperImage && env.defaultImage) c.shipperImage = env.defaultImage;

  if (y.instance) {
    if (INSTANCE_RE.test(y.instance)) c.instance = y.instance;
    else errors.push('instance : 1 a 63 caracteres (lettres, chiffres, . _ -)');
  }
  if (!c.instance && env.instanceId && INSTANCE_RE.test(env.instanceId)) c.instance = env.instanceId;

  // Conditions de la lecture et de l'envoi, pour des messages d'etat precis.
  const readBlockers = [];
  if (!c.enable) readBlockers.push('disabled');
  if (!c.url) readBlockers.push('url');
  if (!c.token) readBlockers.push('token');
  const shipperBlockers = [];
  if (!c.shipperEnable) shipperBlockers.push('disabled');
  if (!c.sinkUrl) shipperBlockers.push('sink_url');
  if (!c.sinkToken) shipperBlockers.push('sink_token');
  if (!c.shipperHostLogsPath) shipperBlockers.push('host_logs_path');
  if (!c.shipperHostDataPath) shipperBlockers.push('host_data_path');
  if (!c.shipperImage) shipperBlockers.push('image');
  if (!c.instance) shipperBlockers.push('instance');
  if (errors.length) { readBlockers.push('invalid'); shipperBlockers.push('invalid'); }
  return { config: c, errors, readBlockers, shipperBlockers };
}

/** URL locale que les producteurs (WAF, challenge) doivent utiliser pour joindre ce shipper. */
function localShipperUrl(config) {
  return `http://${config.shipperName}:${SHIPPER_PORT}`;
}

/** Vue sans secret, pour l'API et l'interface. */
function publicView(config) {
  const { token, sinkToken, ...rest } = config;
  return { ...rest, tokenSet: !!token, sinkTokenSet: !!sinkToken };
}

module.exports = {
  DEFAULTS, SHIPPER_PORT, parseYaml, normalizeLogstoreConfig, validLogstoreUrl, validHostPath, localShipperUrl, publicView,
};
