'use strict';
/**
 * Logger JSON-lines avec masquage systématique des secrets.
 * - clés sensibles (token, secret, password, cookie, authorization…) → "[redacted]"
 * - motifs de secrets dans les chaînes (jetons Hub « hubt_… », en-têtes Bearer) → masqués
 */
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 99 };
const SENSITIVE_KEY = /(token|secret|password|passwd|authorization|cookie|api[-_]?key|mfa_code|otp|seal)/i;
const SENSITIVE_VALUE = [
  [/hubt_[A-Za-z0-9_-]{8,}/g, 'hubt_[redacted]'],
  [/(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[redacted]'],
  [/(hub_sid=)[^;\s]+/gi, '$1[redacted]'],
];

function redactString(s) {
  let out = String(s);
  for (const [re, rep] of SENSITIVE_VALUE) out = out.replace(re, rep);
  return out.length > 2000 ? out.slice(0, 2000) + '…' : out;
}

function redact(value, depth = 0) {
  if (value == null) return value;
  if (typeof value === 'string') return redactString(value);
  if (typeof value !== 'object') return value;
  if (depth > 4) return '[depth]';
  if (value instanceof Error) return { name: value.name, message: redactString(value.message), code: value.code };
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(value)) out[k] = SENSITIVE_KEY.test(k) ? '[redacted]' : redact(v, depth + 1);
  return out;
}

function createLogger(level = 'info', sink = (line) => process.stdout.write(line + '\n')) {
  const min = LEVELS[level] ?? LEVELS.info;
  const log = (lvl, msg, fields) => {
    if (LEVELS[lvl] < min) return;
    sink(JSON.stringify({ t: new Date().toISOString(), level: lvl, msg: redactString(msg), ...(fields ? redact(fields) : {}) }));
  };
  return {
    debug: (m, f) => log('debug', m, f),
    info: (m, f) => log('info', m, f),
    warn: (m, f) => log('warn', m, f),
    error: (m, f) => log('error', m, f),
  };
}

module.exports = { createLogger, redact, redactString };
