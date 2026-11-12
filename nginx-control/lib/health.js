'use strict';
/**
 * État de santé (ticket #74) — logique pure : transforme les réponses des API de statut existantes
 * en états `ok | degraded | down | disabled | unknown`. Aucune E/S ici (testable seul).
 *
 * Règles de confidentialité : l'état PUBLIC ne contient qu'un mot (`status`) ; l'état PRIVÉ (session) ne contient
 * que des états par composant : jamais de version précise, de chemin, d'URL, d'IP, de jeton ni de message d'erreur brut.
 */
const STATES = ['ok', 'degraded', 'down', 'disabled', 'unknown'];

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const running = (c) => isObj(c) && (c.running === true || c.state === 'running' || c.status === 'running');

/** Composants et la façon de lire leur statut (chemin interne + fonction d'interprétation). */
const SOURCES = [
  ['analyzer', '/api/analyzer/status', (s) => {
    if (s.enabled === false) return 'disabled';
    return s.reachable === true && (s.container === undefined || s.container === null || running(s.container) || s.container.running === undefined) ? 'ok' : 'down';
  }],
  ['waf', '/api/waf/status', (s) => {
    if (s.enabled !== true) return 'disabled';
    return s.reachable === true && running(s.container) ? 'ok' : 'down';
  }],
  ['challenge', '/api/challenge/status', (s) => {
    if (s.enabled !== true) return 'disabled';
    return running(s.container) ? 'ok' : 'down';
  }],
  ['crowdsec', '/api/crowdsec/status', (s) => {
    if (s.configured === false) return 'disabled';
    return s.ok === false ? 'down' : 'ok';
  }],
  ['log_store', '/api/logstore/status', (s) => {
    if (!isObj(s.read) || s.read.enabled !== true) return 'disabled';
    return isObj(s.store) && s.store.reachable === true ? 'ok' : 'down';
  }],
  ['shipper', '/api/logstore/status', (s) => {
    if (!isObj(s.shipper) || s.shipper.enabled !== true) return 'disabled';
    return running(s.shipper.container) ? 'ok' : 'down';
  }],
  ['redis', '/api/redis/status', (s) => {
    if (s.enabled !== true) return 'disabled';
    return s.ok === false ? 'down' : 'ok';
  }],
];

/** Interprète la réponse d'un statut. Réponse absente/illisible → `unknown` (jamais `ok` par défaut). */
function interpret(fn, res) {
  if (!res || res.status !== 200 || !isObj(res.json)) return 'unknown';
  try { const s = fn(res.json); return STATES.includes(s) ? s : 'unknown'; } catch { return 'unknown'; }
}

/**
 * Santé globale : `down` si nginx ne répond pas ; `degraded` si un composant activé est en panne ;
 * `ok` sinon. Les composants `disabled` ou `unknown` ne dégradent pas (ce qui n'est pas activé n'est pas une panne).
 */
function overall(components) {
  if (components.nginx === 'down') return 'down';
  return Object.entries(components).some(([k, v]) => k !== 'dashboard' && v === 'down') ? 'degraded' : 'ok';
}

/**
 * @param {{ nginxUp: boolean, results: Record<string, {status:number, json:any}> }} input
 *        results : réponses des chemins internes (clé = chemin)
 */
function evaluate({ nginxUp, results }) {
  const components = { dashboard: 'ok', nginx: nginxUp ? 'ok' : 'down' };
  for (const [name, path, fn] of SOURCES) components[name] = interpret(fn, results[path]);
  return { status: overall(components), components };
}

/** Corps public : un seul champ. 200 si `ok` ou `degraded` (le service répond), 503 si `down`. */
function publicView(status) {
  return { code: status === 'down' ? 503 : 200, body: { status } };
}

module.exports = { STATES, SOURCES, interpret, overall, evaluate, publicView };
