'use strict';
/**
 * Schemas des formulaires de configuration (#102). Une entree par fichier de `features/config-editor.js` FILES :
 *   - `fields`    : cles YAML plates editables (type, bornes, suggestion de chemin hote #103) ;
 *   - `dedicated` : fichier deja pourvu d'un formulaire propre (Intelligence #88, Journaux #63) ;
 *   - `pending`   : fichier a structure imbriquee / en liste, encore edite en brut (raison donnee).
 * Ajouter un fichier a FILES sans le classer ici fait echouer test/config-forms.test.js : aucun oubli possible.
 * Types : bool, int, number, string, enum, path (chemin HOTE absolu), url, email, image, regex, cron, secret.
 * `suggest` : usage dans lib/host-paths.js (logs, geoip, certs, webroot, analyzer, config...).
 */
const bool = (key) => ({ key, type: 'bool' });
const S = {};

S.certbot = { fields: [
  bool('enable'), { key: 'email', type: 'email' }, bool('staging'), { key: 'server', type: 'url' },
  { key: 'container_image', type: 'image' },
  { key: 'webroot_host_path', type: 'path', suggest: 'webroot' }, { key: 'certs_host_path', type: 'path', suggest: 'certs' },
  { key: 'ca_bundle_host_path', type: 'path' }, { key: 'webroot_nginx_path', type: 'path' },
] };
S['certbot-dns'] = { fields: [
  bool('enable'), { key: 'provider', type: 'string', pattern: /^[a-z0-9_-]{1,40}$/ }, { key: 'container_image', type: 'image' },
  { key: 'email', type: 'email' }, { key: 'propagation_seconds', type: 'int', min: 0, max: 3600 },
  { key: 'credentials_host_path', type: 'path' }, { key: 'certs_host_path', type: 'path', suggest: 'certs' },
  { key: 'plugin_flag', type: 'string', pattern: /^--[a-z0-9-]{1,80}$/ },
  { key: 'credentials_flag', type: 'string', pattern: /^--[a-z0-9-]{1,80}$/ },
  { key: 'propagation_flag', type: 'string', pattern: /^--[a-z0-9-]{1,80}$/ },
] };
S.geoipupdate = { fields: [
  bool('enable'), { key: 'container_image', type: 'image' }, { key: 'account_id', type: 'string', pattern: /^[0-9]{1,12}$/ },
  { key: 'license_key', type: 'secret' }, { key: 'edition_ids', type: 'string', pattern: /^[A-Za-z0-9 -]{1,200}$/ },
  { key: 'frequency_hours', type: 'int', min: 1, max: 8760 }, { key: 'geoip_host_path', type: 'path', suggest: 'geoip' },
] };
S['error-pages'] = { fields: [
  bool('enable'), { key: 'container_image', type: 'image' }, { key: 'template_name', type: 'string', pattern: /^[A-Za-z0-9._-]{1,60}$/ },
] };
S.goaccess = { fields: [
  { key: 'container_image', type: 'image' }, { key: 'log_format', type: 'string' }, { key: 'refresh_seconds', type: 'int', min: 1, max: 3600 },
] };
S.git = { fields: [
  { key: 'repo_url', type: 'url' }, { key: 'branch', type: 'string', pattern: /^[A-Za-z0-9._\/-]{1,100}$/ },
  { key: 'backup_branch', type: 'string', pattern: /^[A-Za-z0-9._\/-]{1,100}$/ }, { key: 'token', type: 'secret' },
  { key: 'user_name', type: 'string' }, { key: 'user_email', type: 'email' },
] };
S.crowdsec = { fields: [
  { key: 'url', type: 'url' }, { key: 'api_key', type: 'secret' }, { key: 'prometheus_url', type: 'url' }, bool('local_only'),
  { key: 'machine_id', type: 'string', pattern: /^[A-Za-z0-9._-]{1,100}$/ }, { key: 'machine_password', type: 'secret' },
] };
S.analyzer = { fields: [
  bool('enable'), { key: 'container_image', type: 'image' }, { key: 'container_name', type: 'string', pattern: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/ },
  { key: 'port', type: 'int', min: 1, max: 65535 }, { key: 'shipper_url', type: 'url' },
  { key: 'host_logs_path', type: 'path', suggest: 'logs' }, { key: 'host_data_path', type: 'path', suggest: 'analyzer' },
  { key: 'host_geoip_path', type: 'path', suggest: 'geoip' }, { key: 'log_pattern', type: 'regex' }, { key: 'waf_log_pattern', type: 'regex' },
  { key: 'bruteforce_min_failures', type: 'int', min: 1, max: 1000000 }, { key: 'scan_min_requests', type: 'int', min: 1, max: 1000000 },
  { key: 'flood_min_requests', type: 'int', min: 1, max: 1000000 }, { key: 'ignore_status', type: 'string', pattern: /^[0-9, ]{0,60}$/ },
  { key: 'learning_days', type: 'int', min: 1, max: 365 }, { key: 'sigma_threshold', type: 'number', min: 1, max: 100 },
  { key: 'notify_min_severity', type: 'enum', options: ['low', 'medium', 'high', 'critical'] },
  { key: 'alert_retention_days', type: 'int', min: 1, max: 3650 }, { key: 'waf_retention_days', type: 'int', min: 1, max: 3650 },
  bool('rule_bruteforce_enable'), bool('rule_scan_enable'), bool('rule_flood_enable'),
  bool('rule_scraping_enable'), bool('rule_volumetric_enable'), bool('rule_country_traffic_enable'),
] };
S.agents = { fields: [
  bool('enable'), { key: 'offline_after_sec', type: 'int', min: 10, max: 86400 }, { key: 'max_vhosts_per_agent', type: 'int', min: 1, max: 10000 },
  bool('tunnel_enable'), { key: 'tunnel_target', type: 'url' }, { key: 'certbot_retry_minutes', type: 'int', min: 1, max: 1440 },
] };
S.godns = { fields: [
  bool('enable'), { key: 'container_image', type: 'image' }, { key: 'container_name', type: 'string', pattern: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/ },
  { key: 'port', type: 'int', min: 1, max: 65535 }, { key: 'config_format', type: 'enum', options: ['yaml', 'json'] },
  { key: 'config_host_path', type: 'path', suggest: 'config' },
] };
S.blocklists = { fields: [
  bool('enable'), { key: 'interval_cron', type: 'cron' }, { key: 'analyzer_interval_cron', type: 'cron' },
  { key: 'block_action', type: 'enum', options: ['deny_403', 'drop_444'] }, bool('hit_logging_enable'),
  { key: 'hit_logging_method', type: 'string', pattern: /^[a-z_]{1,30}$/ },
  bool('public_enable'), { key: 'public_token', type: 'secret' }, { key: 'public_sources', type: 'string', pattern: /^[A-Za-z0-9_., -]{1,300}$/ },
] };

// Deja pourvus d'un formulaire propre.
S.intelligence = { dedicated: 'intelligence' };
S.logstore = { dedicated: 'logstore' };
// Structure imbriquee / listes : edition brute pour l'instant (formulaires a venir, un lot par fichier).
const P = (why) => ({ pending: why });
S.challenge = { fields: [
  bool('challenge_enable'), { key: 'challenge_engine', type: 'enum', options: ['builtin', 'anubis'] },
  { key: 'challenge_upstream', type: 'string', pattern: /^[A-Za-z0-9._:-]{1,200}$/ }, { key: 'challenge_resolver', type: 'string', pattern: /^[A-Za-z0-9._:-]{1,100}$/ },
  { key: 'challenge_exempt_path_regex', type: 'regex' }, { key: 'challenge_exempt_ua_regex', type: 'regex' }, bool('challenge_fail_open'),
  bool('enable'), { key: 'container_image', type: 'image' }, { key: 'secret', type: 'secret' },
  { key: 'difficulty_bits', type: 'int', min: 8, max: 64 }, { key: 'cookie_hours', type: 'int', min: 1, max: 720 },
  { key: 'language', type: 'string', pattern: /^(auto|[a-z]{2})$/ }, bool('goodbots'), { key: 'goodbots_extra', type: 'string' },
  bool('autoblock'), { key: 'autoblock_threshold', type: 'int', min: 3, max: 100000 }, { key: 'autoblock_window_minutes', type: 'int', min: 1, max: 1440 },
  { key: 'autoblock_hours', type: 'int', min: 1, max: 720 }, { key: 'offenders_hours', type: 'int', min: 1, max: 168 },
  { key: 'anubis_difficulty', type: 'int', min: 1, max: 8 }, { key: 'redirect_domains', type: 'string' },
  { key: 'cookie_domain', type: 'string', pattern: /^[A-Za-z0-9.-]{1,100}$/ }, { key: 'shipper_url', type: 'url' },
], note: 'regenerate' };
S.waf = { fields: [
  bool('enable'), bool('accept_limits'), { key: 'container_name', type: 'string', pattern: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/ },
  { key: 'container_image', type: 'image' }, { key: 'port', type: 'int', min: 1, max: 65535 },
  { key: 'host_data_path', type: 'path', suggest: 'waf' }, { key: 'host_rules_path', type: 'path', suggest: 'waf_rules' },
  { key: 'host_logs_path', type: 'path', suggest: 'logs' }, { key: 'shipper_url', type: 'url' },
  { key: 'log_pattern', type: 'regex' }, { key: 'waf_log_pattern', type: 'regex' },
  { key: 'crs_version', type: 'string', pattern: /^v?[0-9]+\.[0-9]+\.[0-9]+$/ }, { key: 'hit_retention_days', type: 'int', min: 1, max: 3650 },
] };
S.hub = { fields: [
  { key: 'hub_url', type: 'url' }, bool('backup_enable'), bool('backup_include_secrets'), { key: 'retention_days', type: 'int', min: 1, max: 3650 },
  { key: 'push_timeout_s', type: 'int', min: 1, max: 600 }, bool('expose_ips'),
] };
S.backup = { fields: [
  bool('s3_enable'), { key: 's3_endpoint', type: 'url' }, { key: 's3_region', type: 'string', pattern: /^[A-Za-z0-9-]{1,40}$/ },
  { key: 's3_bucket', type: 'string', pattern: /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/ }, { key: 's3_prefix', type: 'string', pattern: /^[A-Za-z0-9._\/-]{0,100}$/ },
  bool('s3_path_style'), bool('s3_allow_insecure'), { key: 's3_access_key', type: 'secret' }, { key: 's3_secret_key', type: 'secret' },
  { key: 's3_keep', type: 'int', min: 0, max: 10000 }, { key: 's3_timeout_s', type: 'int', min: 5, max: 600 },
  bool('s3_include_ngxops'), bool('s3_include_secrets'), bool('auto_local'), bool('auto_git'), bool('auto_s3'),
] };
S['docker-autoconfig'] = { fields: [
  bool('enable'), bool('require_approval'), { key: 'poll_interval_sec', type: 'int', min: 5, max: 3600 }, bool('events_enable'),
  { key: 'events_debounce_ms', type: 'int', min: 0, max: 60000 }, { key: 'certbot_retry_minutes', type: 'int', min: 1, max: 1440 },
] };
S['deploy-tokens'] = P('liste de jetons (gérée par la page Déploiement)');

module.exports = { SCHEMAS: S };
