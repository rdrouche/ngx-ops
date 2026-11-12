'use strict';
/**
 * Couche de stockage : une interface asynchrone commune à SQLite (défaut) et PostgreSQL (option).
 *   store.get(sql, params) → ligne | undefined      store.all(sql, params) → lignes
 *   store.run(sql, params) → { changes }            store.insert(sql, params) → id (colonne « id » auto-générée)
 *   store.tx(async (t) => …) → transaction ; t a la même interface
 * Requêtes : placeholders « ? », SQL portable (pas de COLLATE NOCASE, pas de AUTOINCREMENT hors migrations).
 */
const path = require('node:path');
const fs = require('node:fs');
const { SqliteStore } = require('./sqlite');
const { MIGRATIONS, render } = require('./migrations');

function readSecretFile(file) { return fs.readFileSync(file, 'utf8').replace(/\r?\n$/, ''); }

/** Mot de passe PostgreSQL : jamais dans le YAML — variable d'environnement ou fichier (secret Docker). */
function pgPassword(env = process.env) {
  if (env.HUB_DB_PASSWORD_FILE) return readSecretFile(env.HUB_DB_PASSWORD_FILE);
  return env.HUB_DB_PASSWORD || undefined;
}

async function openStore(config, { file, env = process.env } = {}) {
  const s = config.storage || {};
  let store;
  if (file || s.driver !== 'postgres') {
    store = new SqliteStore(file || path.join(config.server.data_dir, s.sqlite_file || 'hub.sqlite'));
  } else {
    const { PostgresStore } = require('./postgres');
    const p = s.postgres;
    const ssl = p.ssl === 'disable' ? false : { rejectUnauthorized: p.ssl !== 'require' };
    store = new PostgresStore({
      host: p.host, port: p.port, database: p.database, user: p.user, password: pgPassword(env),
      max: p.pool_max, ssl, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30_000, statement_timeout: 30_000,
    });
  }
  await migrate(store);
  return store;
}

async function migrate(store) {
  await store.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT, applied_at ' + (store.dialect === 'postgres' ? 'BIGINT' : 'INTEGER') + ')');
  const done = new Set((await store.all('SELECT version FROM schema_migrations')).map((r) => Number(r.version)));
  for (const m of MIGRATIONS) {
    if (done.has(m.version)) continue;
    try {
      await store.tx(async (t) => {
        await t.exec(render(m, store.dialect));
        await t.run('INSERT INTO schema_migrations(version,name,applied_at) VALUES (?,?,?)', [m.version, m.name, Date.now()]);
      });
    } catch (e) { throw new Error(`migration ${m.version} échouée : ${e.message}`); }
  }
}

async function schemaVersion(store) {
  const r = await store.get('SELECT MAX(version) AS v FROM schema_migrations');
  return Number(r && r.v) || 0;
}

module.exports = { openStore, schemaVersion, MIGRATIONS, pgPassword };
