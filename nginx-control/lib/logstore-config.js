'use strict';
/**
 * Journal centralise — formulaire de configuration (ticket #63).
 * Pur : convertit le corps du formulaire en config/logstore.yml (liste blanche stricte), le valide avec
 * normalizeLogstoreConfig (meme code que la lecture et le shipper) et fabrique la vue du formulaire.
 * Les jetons (lecture, envoi) ne sont JAMAIS renvoyes : seuls `tokenSet` / `sinkTokenSet` sont exposes.
 * Le mode IP (clair / pseudonymise / tronque) est un reglage du log store lui-meme (jeton admin, que le
 * dashboard ne detient pas) : il n'est donc pas modifiable ici.
 */
const { normalizeLogstoreConfig, parseYaml } = require('./logstore-settings');

const TOKEN_RE = /^[A-Za-z0-9_.~+/=-]{16,300}$/;
const FORBIDDEN = /["\r\n#\\]/;
const bool = (v) => v === true || v === 'true';
const str = (v) => (v == null ? '' : String(v).trim());

/** Vue du formulaire (aucun secret). `text` : contenu actuel de logstore.yml ; `config` : configuration effective. */
function formView({ config, errors, text, env = {} }) {
  const raw = parseYaml(text);
  return {
    values: {
      enable: config.enable, url: raw.url || '', timeout_seconds: config.timeoutSeconds, allow_insecure: config.allowInsecure,
      shipper_enable: config.shipperEnable, shipper_name: raw.shipper_name || '', shipper_image: raw.shipper_image || '',
      shipper_host_logs_path: raw.shipper_host_logs_path || '', shipper_host_data_path: raw.shipper_host_data_path || '',
      shipper_sink_url: raw.shipper_sink_url || '', shipper_allow_insecure: config.sinkAllowInsecure,
      instance: raw.instance || '', shipper_blocklist: config.shipperBlocklist, shipper_country: config.shipperCountry,
    },
    effective: { shipper_name: config.shipperName, shipper_image: config.shipperImage, shipper_host_logs_path: config.shipperHostLogsPath, shipper_sink_url: config.sinkUrl, instance: config.instance },
    tokenSet: !!config.token, tokenFromEnv: !!env.readToken,
    sinkTokenSet: !!config.sinkToken, sinkTokenFromEnv: !!env.sinkToken,
    errors,
  };
}

const q = (s) => `"${s}"`; // valeurs deja validees : ni guillemet, ni retour a la ligne, ni diese, ni antislash

/**
 * @param {object} body     corps du formulaire
 * @param {string} previous contenu actuel de logstore.yml (pour conserver les jetons)
 * @param {object} env      { readToken, sinkToken, defaultLogsPath, defaultImage, instanceId }
 * @returns {{ ok: boolean, yaml?: string, errors: string[] }}
 */
function buildConfig(body, previous, env = {}) {
  const b = body && typeof body === 'object' ? body : {};
  const errors = [];
  const prev = parseYaml(previous);

  const secret = (field, prevValue, clearKey, label) => {
    if (b[clearKey] === true) return '';
    const v = typeof b[field] === 'string' ? b[field].trim() : '';
    if (v && !/^\*+$/.test(v)) {
      if (!TOKEN_RE.test(v)) { errors.push(`${label} : caracteres ou longueur invalides`); return prevValue; }
      return v;
    }
    return prevValue;
  };
  const token = secret('token', String(prev.token || ''), 'clearToken', 'token');
  const sinkToken = secret('shipper_sink_token', String(prev.shipper_sink_token || ''), 'clearSinkToken', 'shipper_sink_token');

  const text = {};
  for (const k of ['url', 'shipper_name', 'shipper_image', 'shipper_host_logs_path', 'shipper_host_data_path', 'shipper_sink_url', 'instance']) {
    text[k] = str(b[k]);
    if (FORBIDDEN.test(text[k])) errors.push(`${k} : caracteres interdits`);
  }
  let timeout;
  if (b.timeout_seconds !== undefined && b.timeout_seconds !== '' && b.timeout_seconds !== null) {
    timeout = Number(b.timeout_seconds);
    if (!Number.isInteger(timeout)) errors.push('timeout_seconds : entier attendu');
  }
  if (errors.length) return { ok: false, errors };

  let y = '# NGX Ops — config/logstore.yml (genere par le formulaire de la page Journaux, #63)\n';
  y += '# Jetons : preferer LOGSTORE_READ_TOKEN et LOGSINK_TOKEN (variables d\'environnement) a une valeur ecrite ici.\n';
  y += `enable: ${bool(b.enable)}\n`;
  if (text.url) y += `url: ${q(text.url)}\n`;
  if (token) y += `token: ${q(token)}\n`;
  if (timeout !== undefined) y += `timeout_seconds: ${timeout}\n`;
  y += `allow_insecure: ${bool(b.allow_insecure)}\n`;
  y += `shipper_enable: ${bool(b.shipper_enable)}\n`;
  for (const k of ['shipper_name', 'shipper_image', 'shipper_host_logs_path', 'shipper_host_data_path', 'shipper_sink_url']) if (text[k]) y += `${k}: ${q(text[k])}\n`;
  if (sinkToken) y += `shipper_sink_token: ${q(sinkToken)}\n`;
  y += `shipper_allow_insecure: ${bool(b.shipper_allow_insecure)}\n`;
  if (text.instance) y += `instance: ${q(text.instance)}\n`;
  y += `shipper_blocklist: ${bool(b.shipper_blocklist)}\nshipper_country: ${bool(b.shipper_country)}\n`;

  const r = normalizeLogstoreConfig(y, env);
  if (r.errors.length) return { ok: false, errors: r.errors };
  return { ok: true, yaml: y, errors: [], config: r.config };
}

module.exports = { formView, buildConfig };
