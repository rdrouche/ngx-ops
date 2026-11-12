'use strict';
/**
 * Migrations versionnées — UNE seule source (SQL au dialecte SQLite), traduite mécaniquement pour PostgreSQL.
 * RÈGLE D'ÉVOLUTION : on n'édite jamais une migration publiée ; on en ajoute une nouvelle (ADD COLUMN / nouvelle table).
 * Pour un besoin propre à un dialecte : champ `pg_after` (SQL PostgreSQL exécuté après la traduction).
 */
const MIGRATIONS = [
  {
    version: 1,
    name: 'initial',
    sql: `
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pass_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        mfa_secret_enc TEXT,
        mfa_enabled INTEGER NOT NULL DEFAULT 0,
        mfa_last_step INTEGER NOT NULL DEFAULT 0,
        failed_count INTEGER NOT NULL DEFAULT 0,
        locked_until INTEGER NOT NULL DEFAULT 0,
        disabled INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE sessions (
        id_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        state TEXT NOT NULL,
        csrf TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        ip TEXT
      );
      CREATE INDEX idx_sessions_exp ON sessions(expires_at);
      CREATE TABLE instances (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        base_url TEXT NOT NULL,
        token_enc TEXT NOT NULL,
        token_hint TEXT NOT NULL DEFAULT '',
        tags TEXT NOT NULL DEFAULT '[]',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'unknown',
        last_contact_at INTEGER,
        last_ok_at INTEGER,
        last_latency_ms INTEGER,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        last_summary TEXT
      );
      CREATE TABLE samples (
        instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
        ts INTEGER NOT NULL,
        ok INTEGER NOT NULL,
        latency_ms INTEGER,
        req_humans INTEGER,
        req_robots INTEGER,
        alerts_active INTEGER,
        vhosts INTEGER
      );
      CREATE INDEX idx_samples_inst_ts ON samples(instance_id, ts);
      CREATE INDEX idx_samples_ts ON samples(ts);
      CREATE TABLE audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        actor TEXT,
        action TEXT NOT NULL,
        target TEXT,
        ip TEXT,
        detail TEXT
      );
      CREATE INDEX idx_audit_ts ON audit(ts);
    `,
    pg_after: 'CREATE UNIQUE INDEX idx_users_username_lower ON users(lower(username));',
  },
  {
    version: 2,
    name: 'users_must_change_password',
    sql: 'ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;',
  },
  {
    version: 3,
    name: 'backups',
    sql: `
      ALTER TABLE samples ADD COLUMN req_total INTEGER;
      ALTER TABLE samples ADD COLUMN req_errors INTEGER;
      ALTER TABLE samples ADD COLUMN bytes_out INTEGER;
      ALTER TABLE instances ADD COLUMN push_token_sha256 TEXT;
      ALTER TABLE instances ADD COLUMN push_token_hint TEXT;
      ALTER TABLE instances ADD COLUMN backup_token_enc TEXT;
      ALTER TABLE instances ADD COLUMN backup_token_hint TEXT;
      ALTER TABLE instances ADD COLUMN backup_expected_since INTEGER;
      ALTER TABLE instances ADD COLUMN last_backup_at INTEGER;
      ALTER TABLE instances ADD COLUMN last_backup_try_at INTEGER;
      ALTER TABLE instances ADD COLUMN last_backup_error TEXT;
      CREATE UNIQUE INDEX idx_instances_push_sha ON instances(push_token_sha256);
      CREATE TABLE backups (
        id TEXT PRIMARY KEY,
        instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
        source TEXT NOT NULL,
        received_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        encrypted INTEGER NOT NULL DEFAULT 0,
        files INTEGER,
        dashboard_version TEXT,
        remote_instance_id TEXT,
        retention_days INTEGER,
        manifest TEXT
      );
      CREATE UNIQUE INDEX idx_backups_inst_sha ON backups(instance_id, sha256);
      CREATE INDEX idx_backups_inst_time ON backups(instance_id, received_at);
      CREATE INDEX idx_backups_exp ON backups(expires_at);
      CREATE INDEX idx_backups_sha ON backups(sha256);
    `,
  },
  {
    version: 4,
    name: 'modules_alerts',
    sql: `
      CREATE TABLE instance_modules (
        instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
        module TEXT NOT NULL,
        status TEXT NOT NULL,
        fetched_at INTEGER NOT NULL,
        last_ok_at INTEGER,
        error TEXT,
        expose_ips INTEGER NOT NULL DEFAULT 0,
        parts_errors TEXT,
        payload TEXT,
        PRIMARY KEY (instance_id, module)
      );
      CREATE TABLE hub_alerts (
        instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
        remote_id INTEGER NOT NULL,
        ts INTEGER NOT NULL,
        type TEXT,
        severity TEXT,
        summary TEXT,
        vhost TEXT,
        country TEXT,
        acked INTEGER NOT NULL DEFAULT 0,
        ip_count INTEGER NOT NULL DEFAULT 0,
        evidence TEXT,
        ips TEXT,
        PRIMARY KEY (instance_id, remote_id)
      );
      CREATE INDEX idx_hub_alerts_ts ON hub_alerts(ts);
      CREATE INDEX idx_hub_alerts_sev ON hub_alerts(severity, acked);
      ALTER TABLE instances ADD COLUMN alerts_last_id INTEGER NOT NULL DEFAULT 0;
    `,
  },
  // { version: 5, name: '…', sql: 'ALTER TABLE … ADD COLUMN …' }  ← évolutions futures ici
];

/** SQL SQLite → SQL PostgreSQL (types uniquement ; pas de logique). */
function toPostgres(sql) {
  return sql
    .replace(/INTEGER PRIMARY KEY AUTOINCREMENT/g, 'BIGSERIAL PRIMARY KEY')
    .replace(/\bINTEGER\b/g, 'BIGINT')
    .replace(/ COLLATE NOCASE/g, '')
    .replace(/\bREAL\b/g, 'DOUBLE PRECISION')
    .replace(/\bBLOB\b/g, 'BYTEA');
}

function render(m, dialect) {
  if (dialect === 'postgres') return toPostgres(m.sql) + (m.pg_after ? '\n' + m.pg_after : '');
  return m.sql;
}

module.exports = { MIGRATIONS, render, toPostgres };
