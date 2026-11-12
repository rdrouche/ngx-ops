'use strict';
/**
 * WAF emule (conteneur `ngx-waf`) — lecture et validation de config/waf.yml, et
 * construction (pure) de la specification du conteneur. Aucune E/S ici : le
 * texte du fichier et les valeurs d'ENV sont fournis par l'appelant
 * (features/waf.js), ce qui rend le tout testable sans Docker.
 *
 * Le contrat avec le conteneur Go (variables d'ENV, ports, volumes) est dans
 * WAF-CONTRACT.md. Le WAF est EMULE : il analyse les journaux d'acces a
 * posteriori (Coraza en DetectionOnly + OWASP CRS), il ne bloque jamais lui-meme
 * et ne voit pas les corps de requete. `accept_limits: true` est donc
 * obligatoire pour demarrer le conteneur.
 *
 * Priorites : image = waf.yml (container_image) > WAF_DEFAULT_IMAGE (ENV/ARG)
 * > ANALYZER_DEFAULT_IMAGE ; le reste = waf.yml > valeur par defaut ci-dessous.
 * Le secret partage (X-WAF-Token) n'est PAS dans ce fichier : lib/waf-token.js.
 */
const { validShipperUrl } = require('./shipper-url');
const { stripInlineComment } = require('./simple-yaml');

const DEFAULTS = Object.freeze({
  enable: false,
  acceptLimits: false,
  containerName: 'ngx-waf',
  containerImage: '',
  port: 9101,
  hostDataPath: '',
  hostRulesPath: '',
  hostLogsPath: '',
  logPattern: '(^|[._])access\\.log$',
  wafLogPattern: '(^|[._-])wafemu\\.log$',
  crsVersion: 'v4.8.0',
  hitRetentionDays: 30,
  shipperUrl: '',
});

// Points de montage figes cote conteneur (WAF-CONTRACT.md).
const MOUNTS = Object.freeze({ logs: '/nginx/logs', data: '/waf', rules: '/waf-rules' });
const ENTRYPOINT = '/usr/local/bin/waf';

const NAME_RE  = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/;
const IMAGE_RE = /^[A-Za-z0-9][A-Za-z0-9._\/:@-]{0,254}$/;
const CRS_RE   = /^v?\d{1,2}\.\d{1,3}\.\d{1,3}(-rc\d{1,2})?$/;

function unquote(v) {
  const s = stripInlineComment(v);
  if (/^".*"$/.test(s) || /^'.*'$/.test(s)) return s.slice(1, -1);
  return s;
}

/** Sous-ensemble YAML : `cle: scalaire` uniquement (pas de liste, pas d'imbrication). */
function parseWafYaml(text) {
  const out = {};
  for (const raw of String(text || '').replace(/\r/g, '').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^([a-z_]+)\s*:\s*(.*)$/);
    if (!m) continue;
    out[m[1]] = unquote(m[2]);
  }
  return out;
}

const bool = (v, def) => (v === undefined ? def : String(v).toLowerCase() === 'true');
const intIn = (v, def, min, max, errors, key) => {
  if (v === undefined || v === '') return def;
  const n = Number(v);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < min || n > max) {
    errors.push(`${key} : entier entre ${min} et ${max} attendu (recu "${v}")`);
    return def;
  }
  return n;
};

/**
 * Chemin HOTE d'un montage : absolu, sans `:` (injection d'une 3e partie du
 * bind `src:dst:mode`), sans caractere de controle, sans segment `..`.
 */
function validHostPath(p) {
  if (typeof p !== 'string' || !p.startsWith('/') || p.length > 512) return false;
  if (/[:\u0000-\u001f\u007f]/.test(p)) return false;
  if (p.split('/').includes('..')) return false;
  return true;
}

function validRegex(src) {
  if (typeof src !== 'string' || !src || src.length > 200) return false;
  try { new RegExp(src); return true; } catch { return false; }
}

/**
 * @param {string} text   contenu de waf.yml (peut etre vide)
 * @param {object} env    { defaultImage, defaultLogsPath }
 * @returns {{ config, errors: string[], blockers: string[] }}
 *   blockers : raisons (codes stables, jamais du texte) pour lesquelles le conteneur ne peut pas demarrer :
 *   'disabled' | 'accept_limits' | 'host_data_path' | 'host_rules_path' | 'invalid'
 */
function normalizeWafConfig(text, env = {}) {
  const y = parseWafYaml(text);
  const errors = [];
  const c = { ...DEFAULTS };
  c.enable = bool(y.enable, DEFAULTS.enable);
  c.acceptLimits = bool(y.accept_limits, DEFAULTS.acceptLimits);

  c.containerName = DEFAULTS.containerName;
  if (y.container_name !== undefined && y.container_name !== '') {
    if (NAME_RE.test(y.container_name)) c.containerName = y.container_name;
    else errors.push('container_name : nom de conteneur invalide (lettres, chiffres, _ . -)');
  }

  const rawImage = (y.container_image || '').trim() || (env.defaultImage || '').trim();
  if (rawImage && !IMAGE_RE.test(rawImage)) {
    errors.push('container_image : reference d image invalide');
    c.containerImage = (env.defaultImage && IMAGE_RE.test(env.defaultImage)) ? env.defaultImage : '';
  } else c.containerImage = rawImage;

  c.port = intIn(y.port, DEFAULTS.port, 1, 65535, errors, 'port');

  for (const [yk, ck] of [['host_data_path', 'hostDataPath'], ['host_rules_path', 'hostRulesPath'], ['host_logs_path', 'hostLogsPath']]) {
    const v = y[yk];
    if (v === undefined || v === '') continue;
    if (validHostPath(v)) c[ck] = v.length > 1 ? v.replace(/\/+$/, '') : v;
    else errors.push(`${yk} : chemin HOTE absolu attendu, sans « : », sans « .. » ni caractere de controle`);
  }
  if (!c.hostLogsPath && env.defaultLogsPath && validHostPath(env.defaultLogsPath)) c.hostLogsPath = env.defaultLogsPath;

  for (const [yk, ck] of [['log_pattern', 'logPattern'], ['waf_log_pattern', 'wafLogPattern']]) {
    const v = y[yk];
    if (v === undefined || v === '') continue;
    if (validRegex(v)) c[ck] = v;
    else errors.push(`${yk} : expression reguliere invalide ou trop longue (200 caracteres max)`);
  }

  if (y.crs_version !== undefined && y.crs_version !== '') {
    if (CRS_RE.test(y.crs_version)) c.crsVersion = y.crs_version.startsWith('v') ? y.crs_version : 'v' + y.crs_version;
    else errors.push('crs_version : tag de version attendu (ex. v4.8.0)');
  }
  c.hitRetentionDays = intIn(y.hit_retention_days, DEFAULTS.hitRetentionDays, 1, 3650, errors, 'hit_retention_days');

  if (y.shipper_url !== undefined && y.shipper_url !== '') {
    if (validShipperUrl(y.shipper_url)) c.shipperUrl = y.shipper_url.replace(/\/+$/, '');
    else errors.push('shipper_url : URL schema://hote:port attendue, sans chemin ni identifiants (http:// reserve a un hote local, un nom de service ou une IP privee)');
  }

  const blockers = [];
  if (!c.enable) blockers.push('disabled');
  if (!c.acceptLimits) blockers.push('accept_limits');
  if (!c.hostDataPath) blockers.push('host_data_path');
  if (!c.hostRulesPath) blockers.push('host_rules_path');
  if (!c.hostLogsPath) blockers.push('host_logs_path');
  if (errors.length) blockers.push('invalid');
  return { config: c, errors, blockers };
}

/**
 * Specification `POST /containers/create` du conteneur WAF. Pur.
 * @param {object} config   resultat de normalizeWafConfig().config
 * @param {{token:string, network:string, tz?:string, shipperToken?:string}} opts
 */
function buildContainerSpec(config, { token, network, tz, shipperToken } = {}) {
  if (!token) throw new Error('jeton WAF absent');
  const env = [
    `PORT=${config.port}`,
    `WAF_TOKEN=${token}`,
    `LOGS_DIR=${MOUNTS.logs}`,
    `LOG_PATTERN=${config.logPattern}`,
    `WAF_LOG_PATTERN=${config.wafLogPattern}`,
    `DATA_DIR=${MOUNTS.data}`,
    `RULES_DIR=${MOUNTS.rules}`,
    `CRS_VERSION=${config.crsVersion}`,
    `HIT_RETENTION_DAYS=${config.hitRetentionDays}`,
  ];
  if (tz && /^[A-Za-z0-9_\/+-]{1,64}$/.test(tz)) env.push(`TZ=${tz}`);
  // Envoi des hits vers le log store, via l'API locale du shipper : seulement si shipper_url est defini.
  if (config.shipperUrl && shipperToken) env.push(`SHIPPER_URL=${config.shipperUrl}`, `SHIPPER_TOKEN=${shipperToken}`);
  return {
    Image: config.containerImage,
    Entrypoint: [ENTRYPOINT],
    Env: env,
    HostConfig: {
      Binds: [
        `${config.hostLogsPath}:${MOUNTS.logs}:ro`,
        `${config.hostDataPath}:${MOUNTS.data}`,
        `${config.hostRulesPath}:${MOUNTS.rules}`,
      ],
      RestartPolicy: { Name: 'unless-stopped' },
      NetworkMode: network || 'nginx-net',
    },
    Labels: { 'managed-by': 'nginx-dashboard' },
  };
}

module.exports = {
  DEFAULTS, MOUNTS, ENTRYPOINT, parseWafYaml, normalizeWafConfig, buildContainerSpec, validHostPath, validShipperUrl,
};
