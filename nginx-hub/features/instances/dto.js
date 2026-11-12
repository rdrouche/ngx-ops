'use strict';
/** Projection publique d'une ligne `instances` : jamais de token, résumé réduit en liste. */

function parseJson(s, d) { try { return s ? JSON.parse(s) : d; } catch { return d; } }

function brief(s) {
  if (!s) return null;
  const components = {};
  for (const [k, c] of Object.entries(s.components || {})) components[k] = c.state;
  return {
    schema: s.schema,
    generated_at: s.generated_at,
    version: s.instance.version,
    hostname: s.instance.hostname,
    nginx_status: s.nginx.status,
    nginx_version: s.nginx.version,
    vhosts: s.vhosts.count,
    traffic_available: s.traffic_24h.available !== false,
    requests: s.traffic_24h.requests || 0,
    errors: s.traffic_24h.errors || 0,
    bytes: s.traffic_24h.bytes || 0,
    humans: s.traffic_24h.humans,
    robots: s.traffic_24h.robots,
    blocked: s.traffic_24h.blocked,
    alerts_active: s.alerts.active,
    alerts_critical: s.alerts.critical,
    connections: s.nginx.connections || 0,
    certs_expiring: (s.certs_expiring || []).length,
    mfa_accounts: s.mfa ? s.mfa.accounts : null,
    components,
  };
}

function deepLink(row, config) {
  const p = String(config.ui.dashboard_deeplink_path || '/');
  return row.base_url + (p.startsWith('/') ? p : '/' + p);
}

function toDto(row, config, { detail = false } = {}) {
  const summary = parseJson(row.last_summary, null);
  const dto = {
    id: row.id,
    slug: row.slug,
    name: row.name,
    url: row.base_url,
    deeplink: deepLink(row, config),
    tags: parseJson(row.tags, []),
    enabled: !!row.enabled,
    status: row.enabled ? row.status : 'disabled',
    token_hint: row.token_hint,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_contact_at: row.last_contact_at,
    last_ok_at: row.last_ok_at,
    latency_ms: row.last_latency_ms,
    consecutive_failures: row.consecutive_failures,
    last_error: row.last_error,
    summary: brief(summary),
  };
  if (detail) dto.detail = summary;
  return dto;
}

module.exports = { toDto, brief, parseJson };
