'use strict';
/**
 * Configuration du Hub : version, valeurs par défaut, chargement YAML + surcharges d'environnement.
 * Toute nouvelle option DOIT recevoir une valeur par défaut ici (champs additifs seulement).
 */
const fs = require('node:fs');
const path = require('node:path');
const { parseYaml } = require('./yaml');

// Version de la suite ; le build global (CI) peut la surcharger par APP_VERSION (chaîne sobre uniquement).
const APP_VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(process.env.APP_VERSION || '') ? process.env.APP_VERSION : '12.81.0';
const API_VERSION = 'v1';
const API_PREFIX = '/api/hub/' + API_VERSION;
/** Plus haut schéma de /api/hub/v1/summary compris par ce Hub (les schémas supérieurs restent lus, champs inconnus ignorés). */
const SUMMARY_SCHEMA_MAX = 1;

const DEFAULTS = Object.freeze({
  server: {
    host: '0.0.0.0',
    port: 8090,
    data_dir: './data',
    public_base_url: '',
    cookie_secure: true,
    session_ttl_minutes: 480,
    trusted_proxies: ['127.0.0.1/32', '::1/128', '172.16.0.0/12', '10.0.0.0/8', '192.168.0.0/16'],
  },
  collector: {
    enabled: true,
    interval_seconds: 60,
    timeout_ms: 5000,
    concurrency: 8,
    max_response_bytes: 262144,
    offline_after_failures: 3,
    retention_days: 30,
  },
  security: {
    mfa_policy: 'required', // required | optional
    allow_insecure_http: false, // DEV uniquement
    allow_private_networks: false, // true si les dashboards sont sur LAN/Docker
    allowed_cidrs: [], // exceptions ciblées si allow_private_networks=false
    extra_ca_file: '', // PEM supplémentaire (CA interne) pour joindre les dashboards
    login_max_failures: 5,
    login_lock_minutes: 15,
    bootstrap_admin: true, // crée « admin » au premier démarrage si aucun compte n'existe (mot de passe dans les logs)
  },
  ui: {
    default_theme: 'light', // light | dark
    default_language: 'fr', // fr | en (le choix de l’utilisateur prime)
    dashboard_deeplink_path: '/', // chemin ajouté à l'URL de l'instance pour le lien profond
  },
  storage: {
    driver: 'sqlite', // sqlite (défaut, sans dépendance) | postgres (option : paquet npm « pg »)
    sqlite_file: 'hub.sqlite', // dans server.data_dir
    sqlite_maintenance_hours: 24, // checkpoint WAL + optimize + VACUUM si utile (#96) ; 0 = désactivé
    postgres: { // le mot de passe n'est JAMAIS ici : HUB_DB_PASSWORD ou HUB_DB_PASSWORD_FILE
      host: 'postgres', port: 5432, database: 'nginx_ops_hub', user: 'hub',
      ssl: 'disable', // disable | require (chiffré, certificat non vérifié) | verify-full (chiffré + certificat vérifié)
      pool_max: 10,
      maintenance_hours: 24, // VACUUM (ANALYZE) planifié (#96) ; 0 = désactivé (l'autovacuum PostgreSQL reste actif)
    },
  },
  modules: { // contrat dashboard 12.78.0 : alertes détaillées + modules de données (pull, lecture seule)
    enabled: true,
    list: ['alerts', 'inventory', 'traffic', 'security', 'ops', 'monitoring', 'reports'], // modules interrogés
    indicators: { enabled: false }, // corrélation par IP : données personnelles → opt-in EXPLICITE côté Hub (et expose_ips côté dashboard)
    intervals_s: { alerts: 60, inventory: 300, traffic: 300, security: 300, ops: 120, monitoring: 300, reports: 1800, indicators: 300 },
    hours: 24, // fenêtre demandée aux modules (1..720)
    max_module_bytes: 2097152,
    alerts_keep_days: 30, // rétention des alertes détaillées stockées
    alerts_batch: 500,
    concurrency: 4,
  },
  logstore: { // #62 : lecture (pull) des AGRÉGATS du log store, jeton `read` — jamais dans ce fichier : HUB_LOGSTORE_TOKEN ou HUB_LOGSTORE_TOKEN_FILE
    enabled: false,
    url: '', // https://… (mêmes garde-fous réseau que les dashboards : security.allow_private_networks / allowed_cidrs)
    hours: 24, // fenêtre par défaut (1..744 ; le log store plafonne à 31 j)
    timeout_ms: 8000,
    cache_s: 60, // les agrégats sont mis en cache (une requête sortante par fenêtre et par minute au plus)
    max_response_bytes: 1048576,
    indicators: { // corrélation par IP depuis le log store : DONNÉES PERSONNELLES → opt-in explicite (comme modules.indicators), admin seulement, jamais stockée par le Hub
      enabled: false,
      hours: 24, // fenêtre (1..168 : le log store limite cette route à 7 j)
      min_instances: 2, // une IP vue par au moins N instances
      limit: 200,
    },
    explorer: { // #107 : recherche de logs bruts + fiche IP (relais en lecture seule, rien n'est stocké) : DONNÉES PERSONNELLES → opt-in explicite, admin seulement
      enabled: false,
      page_size: 100, // lignes par page (10..500)
    },
  },
  backups: {
    enabled: true,
    dir: 'backups', // dans server.data_dir ; archives adressées par sha256 (hors base)
    max_archive_mb: 256, // refus au-delà (push et pull)
    retention_days: 30, // plafond Hub : rétention effective = min(X-Retention-Days, ce plafond)
    keep_max_per_instance: 100, // garde-fou disque
    alert_after_hours: 36, // alerte si une instance (sauvegarde attendue) n'a rien envoyé depuis N h
    pull_enabled: true, // le Hub va chercher les archives des instances qui ont un jeton de pull
    pull_interval_hours: 24,
    push_rate_per_hour: 30, // par IP
    upload_timeout_s: 600, // durée maximale d'un envoi d'archive (push)
  },
  features: {}, // { nom: false } pour désactiver une feature
  log: { level: 'info' },
});

function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }

function deepMerge(base, over) {
  const out = Array.isArray(base) ? base.slice() : { ...base };
  if (!isObj(over)) return out;
  for (const [k, v] of Object.entries(over)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    out[k] = isObj(v) && isObj(out[k]) ? deepMerge(out[k], v) : v;
  }
  return out;
}

function bool(v, d) {
  if (v === undefined || v === '') return d;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

function clampInt(v, min, max, d) {
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return d;
  return Math.min(max, Math.max(min, n));
}

function validate(cfg) {
  const c = cfg.collector;
  c.interval_seconds = clampInt(c.interval_seconds, 10, 3600, 60);
  c.timeout_ms = clampInt(c.timeout_ms, 500, 30000, 5000);
  c.concurrency = clampInt(c.concurrency, 1, 64, 8);
  c.max_response_bytes = clampInt(c.max_response_bytes, 4096, 4 * 1024 * 1024, 262144);
  c.offline_after_failures = clampInt(c.offline_after_failures, 1, 20, 3);
  c.retention_days = clampInt(c.retention_days, 1, 730, 30);
  cfg.server.port = clampInt(cfg.server.port, 0, 65535, 8090);
  cfg.server.session_ttl_minutes = clampInt(cfg.server.session_ttl_minutes, 5, 7 * 24 * 60, 480);
  cfg.security.login_max_failures = clampInt(cfg.security.login_max_failures, 3, 20, 5);
  cfg.security.login_lock_minutes = clampInt(cfg.security.login_lock_minutes, 1, 1440, 15);
  const st = cfg.storage;
  if (!['sqlite', 'postgres'].includes(st.driver)) st.driver = 'sqlite';
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(String(st.sqlite_file))) st.sqlite_file = 'hub.sqlite';
  st.sqlite_maintenance_hours = clampInt(st.sqlite_maintenance_hours, 0, 720, 24);
  st.postgres.port = clampInt(st.postgres.port, 1, 65535, 5432);
  st.postgres.pool_max = clampInt(st.postgres.pool_max, 1, 100, 10);
  st.postgres.maintenance_hours = clampInt(st.postgres.maintenance_hours, 0, 720, 24);
  if (!['disable', 'require', 'verify-full'].includes(st.postgres.ssl)) st.postgres.ssl = 'disable';
  const m = cfg.modules;
  // tolérance : `indicators: true`, `enabled: "true"` ; toute autre forme = désactivé (opt-in explicite)
  const ind = isObj(m.indicators) ? m.indicators : { enabled: m.indicators };
  m.indicators = { ...ind, enabled: ind.enabled === true || ind.enabled === 'true' };
  if (!isObj(m.intervals_s)) m.intervals_s = {};
  m.hours = clampInt(m.hours, 1, 720, 24);
  m.max_module_bytes = clampInt(m.max_module_bytes, 65536, 16 * 1024 * 1024, 2097152);
  m.alerts_keep_days = clampInt(m.alerts_keep_days, 1, 730, 30);
  m.alerts_batch = clampInt(m.alerts_batch, 10, 500, 500);
  m.concurrency = clampInt(m.concurrency, 1, 16, 4);
  const KNOWN = ['alerts', 'inventory', 'traffic', 'security', 'ops', 'monitoring', 'reports'];
  m.list = (Array.isArray(m.list) ? m.list : []).filter((x) => KNOWN.includes(x));
  for (const k of [...KNOWN, 'indicators']) m.intervals_s[k] = clampInt(m.intervals_s[k], 30, 86400, DEFAULTS.modules.intervals_s[k]);
  const ls = cfg.logstore;
  ls.enabled = ls.enabled === true || ls.enabled === 'true';
  ls.url = String(ls.url || '').trim();
  ls.hours = clampInt(ls.hours, 1, 744, 24);
  ls.timeout_ms = clampInt(ls.timeout_ms, 500, 60000, 8000);
  ls.cache_s = clampInt(ls.cache_s, 0, 3600, 60);
  ls.max_response_bytes = clampInt(ls.max_response_bytes, 4096, 8 * 1024 * 1024, 1048576);
  const li = isObj(ls.indicators) ? ls.indicators : { enabled: ls.indicators };
  ls.indicators = { ...li, enabled: li.enabled === true || li.enabled === 'true', // opt-in strict : toute autre forme = désactivé
    hours: clampInt(li.hours, 1, 168, 24), min_instances: clampInt(li.min_instances, 1, 1000, 2), limit: clampInt(li.limit, 10, 500, 200) };
  const lx = isObj(ls.explorer) ? ls.explorer : { enabled: ls.explorer };
  ls.explorer = { ...lx, enabled: lx.enabled === true || lx.enabled === 'true', page_size: clampInt(lx.page_size, 10, 500, 100) }; // opt-in strict
  const b = cfg.backups;
  b.max_archive_mb = clampInt(b.max_archive_mb, 1, 4096, 256);
  b.retention_days = clampInt(b.retention_days, 1, 3650, 30);
  b.keep_max_per_instance = clampInt(b.keep_max_per_instance, 1, 10000, 100);
  b.alert_after_hours = clampInt(b.alert_after_hours, 1, 24 * 90, 36);
  b.pull_interval_hours = clampInt(b.pull_interval_hours, 1, 24 * 30, 24);
  b.upload_timeout_s = clampInt(b.upload_timeout_s, 30, 3600, 600);
  b.push_rate_per_hour = clampInt(b.push_rate_per_hour, 1, 10000, 30);
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(String(b.dir))) b.dir = 'backups';
  if (!['required', 'optional'].includes(cfg.security.mfa_policy)) cfg.security.mfa_policy = 'required';
  if (!['light', 'dark'].includes(cfg.ui.default_theme)) cfg.ui.default_theme = 'light';
  if (!['fr', 'en'].includes(cfg.ui.default_language)) cfg.ui.default_language = 'fr';
  return cfg;
}

/**
 * @param {object} [opts] { file, overrides, env }
 */
function loadConfig(opts = {}) {
  const env = opts.env || process.env;
  const file = opts.file || env.HUB_CONFIG || path.join(__dirname, '..', 'config', 'hub.yml');
  let fromFile = {};
  if (fs.existsSync(file)) fromFile = parseYaml(fs.readFileSync(file, 'utf8')) || {};
  let cfg = deepMerge(DEFAULTS, fromFile);
  // Surcharges d'environnement (pratiques en conteneur)
  if (env.HUB_PORT) cfg.server.port = env.HUB_PORT;
  if (env.HUB_HOST) cfg.server.host = env.HUB_HOST;
  if (env.HUB_DATA_DIR) cfg.server.data_dir = env.HUB_DATA_DIR;
  if (env.HUB_PUBLIC_BASE_URL) cfg.server.public_base_url = env.HUB_PUBLIC_BASE_URL;
  if (env.HUB_COOKIE_SECURE !== undefined) cfg.server.cookie_secure = bool(env.HUB_COOKIE_SECURE, true);
  if (env.HUB_LOG_LEVEL) cfg.log.level = env.HUB_LOG_LEVEL;
  if (env.HUB_DB_DRIVER) cfg.storage.driver = env.HUB_DB_DRIVER;
  if (env.HUB_DB_HOST) cfg.storage.postgres.host = env.HUB_DB_HOST;
  if (env.HUB_DB_PORT) cfg.storage.postgres.port = env.HUB_DB_PORT;
  if (env.HUB_DB_NAME) cfg.storage.postgres.database = env.HUB_DB_NAME;
  if (env.HUB_DB_USER) cfg.storage.postgres.user = env.HUB_DB_USER;
  if (env.HUB_LOGSTORE_ENABLED !== undefined && env.HUB_LOGSTORE_ENABLED !== '') cfg.logstore.enabled = bool(env.HUB_LOGSTORE_ENABLED, false); // #122
  if (env.HUB_LOGSTORE_URL) cfg.logstore.url = env.HUB_LOGSTORE_URL;
  if (opts.overrides) cfg = deepMerge(cfg, opts.overrides);
  cfg.server.data_dir = path.resolve(cfg.server.data_dir);
  cfg.__file = fs.existsSync(file) ? file : null;
  return validate(cfg);
}

module.exports = { APP_VERSION, API_VERSION, API_PREFIX, SUMMARY_SCHEMA_MAX, DEFAULTS, loadConfig, deepMerge };
