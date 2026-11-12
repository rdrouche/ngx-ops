'use strict';
/**
 * NGX Ops Intelligence — formulaire de configuration (ticket #88).
 * Pur : convertit le corps du formulaire en config/intelligence.yml (liste blanche stricte), le valide avec
 * normalizeIntelSettings (même code que le moteur d'envoi) et fabrique la vue du formulaire.
 * Le jeton n'est JAMAIS renvoyé : seul `tokenSet` est exposé.
 */
const { normalizeIntelSettings, parseIntelYaml, DEFAULTS, MODES, SEVERITIES } = require('./intel-settings');

const TOKEN_RE = /^[A-Za-z0-9._~+\-/=]{8,512}$/;
const DEFAULT_REGISTER_URL = 'https://intelligence.ngx-ops.net/register';

const bool = (v) => v === true || v === 'true';
const int = (v) => (v === undefined || v === null || v === '' ? undefined : Math.round(Number(v)));
const list = (v) => (Array.isArray(v) ? v : String(v == null ? '' : v).split(/[\s,;]+/)).map((x) => String(x).trim()).filter(Boolean);

/** Lien d'inscription : même origine que l'URL d'envoi si elle est valide, sinon la plateforme publique. */
function registerUrl(apiUrl) {
  try { const u = new URL(apiUrl); if (u.protocol === 'https:') return `${u.origin}/register`; } catch { /* défaut */ }
  return DEFAULT_REGISTER_URL;
}

/** Vue du formulaire à partir des réglages effectifs (aucun secret). */
function formView({ settings, errors, text, env = {} }) {
  const raw = parseIntelYaml(text);
  return {
    values: {
      enable: settings.enable, mode: settings.mode, api_url: raw.api_url !== undefined ? settings.apiUrl : (env.apiUrl ? '' : settings.apiUrl),
      user: settings.user, interval_seconds: settings.intervalSeconds, batch_size: settings.batchSize, timeout_seconds: settings.timeoutSeconds,
      backfill_hours: settings.backfillHours, min_severity: settings.minSeverity,
      exclude_rules: settings.excludeRules, include_rules: settings.includeRules, exclude_ips: settings.excludeIps,
      share_user_agents: settings.shareUserAgents, share_paths: settings.sharePaths, share_vhost: settings.shareVhost,
      include_challenge: settings.includeChallenge, ping_enable: settings.pingEnable, ping_interval_minutes: settings.pingIntervalMinutes,
      ping_url: raw.ping_url || raw.url_ping || '',
    },
    tokenSet: !!settings.token, tokenFromEnv: !!env.token, apiUrlDefault: env.apiUrl || '',
    defaults: { interval_seconds: DEFAULTS.intervalSeconds, batch_size: DEFAULTS.batchSize, timeout_seconds: DEFAULTS.timeoutSeconds, exclude_rules: DEFAULTS.excludeRules },
    modes: MODES, severities: SEVERITIES, registerUrl: registerUrl(settings.apiUrl || env.apiUrl), errors,
  };
}

const q = (s) => `"${s}"`; // valeurs déjà validées : ni guillemet, ni retour à la ligne
function yamlList(key, items) { return items.length ? `${key}:\n${items.map((i) => `  - ${i}`).join('\n')}\n` : `${key}: []\n`; }

/**
 * @param {object} body     corps du formulaire
 * @param {string} previous contenu actuel de intelligence.yml (pour conserver le jeton)
 * @param {object} env      { apiUrl, token } de l'environnement
 * @returns {{ ok: boolean, yaml?: string, errors: string[] }}
 */
function buildConfig(body, previous, env = {}) {
  const b = body && typeof body === 'object' ? body : {};
  const errors = [];
  const prev = parseIntelYaml(previous);
  let token = String(prev.token || '');
  if (b.clearToken === true) token = '';
  else if (typeof b.token === 'string' && b.token.trim() && !/^\*+$/.test(b.token.trim())) {
    if (!TOKEN_RE.test(b.token.trim())) errors.push('token : caractères ou longueur invalides');
    else token = b.token.trim();
  }
  const mode = MODES.includes(b.mode) ? b.mode : (b.mode === undefined ? DEFAULTS.mode : (errors.push('mode invalide'), DEFAULTS.mode));
  const sev = SEVERITIES.includes(b.min_severity) ? b.min_severity : (b.min_severity === undefined ? DEFAULTS.minSeverity : (errors.push('min_severity invalide'), DEFAULTS.minSeverity));
  const apiUrl = String(b.api_url || '').trim();
  const user = String(b.user || '').trim();
  const pingUrl = String(b.ping_url || '').trim();
  for (const [k, v] of [['api_url', apiUrl], ['user', user], ['ping_url', pingUrl]]) if (/["\r\n#\\]/.test(v)) errors.push(`${k} : caractères interdits`);
  const nums = { interval_seconds: int(b.interval_seconds), batch_size: int(b.batch_size), timeout_seconds: int(b.timeout_seconds), backfill_hours: int(b.backfill_hours), ping_interval_minutes: int(b.ping_interval_minutes) };
  for (const [k, v] of Object.entries(nums)) if (v !== undefined && !Number.isFinite(v)) errors.push(`${k} : nombre attendu`);
  if (errors.length) return { ok: false, errors };

  let y = `# NGX Ops — config/intelligence.yml (généré par le formulaire d'administration, #88)\n`;
  y += `enable: ${bool(b.enable)}\nmode: ${mode}\n`;
  if (apiUrl) y += `api_url: ${q(apiUrl)}\n`;
  if (user) y += `user: ${q(user)}\n`;
  if (token) y += `# Préférez la variable d'environnement INTEL_TOKEN à un jeton écrit ici.\ntoken: ${q(token)}\n`;
  for (const [k, v] of Object.entries(nums)) if (v !== undefined) y += `${k}: ${v}\n`;
  y += `min_severity: ${sev}\n`;
  y += yamlList('exclude_rules', list(b.exclude_rules));
  y += yamlList('include_rules', list(b.include_rules));
  y += yamlList('exclude_ips', list(b.exclude_ips));
  for (const k of ['share_user_agents', 'share_paths', 'share_vhost', 'include_challenge', 'ping_enable']) y += `${k}: ${bool(b[k])}\n`;
  if (pingUrl) y += `ping_url: ${q(pingUrl)}\n`;

  const { settings, errors: errs } = normalizeIntelSettings(y, env);
  if (errs.length) return { ok: false, errors: errs };
  return { ok: true, yaml: y, errors: [], settings };
}

module.exports = { buildConfig, formView, registerUrl, DEFAULT_REGISTER_URL };
