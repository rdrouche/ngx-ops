'use strict';
/** Adaptateur SQLite (node:sqlite, WAL). Même interface asynchrone que l'adaptateur PostgreSQL. */
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

class SqliteStore {
  constructor(file) {
    this.dialect = 'sqlite';
    if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(file);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;');
    if (file !== ':memory:') { try { fs.chmodSync(file, 0o600); } catch { /* best effort */ } }
    this.cache = new Map();
    this.lock = Promise.resolve();
  }

  stmt(sql) {
    let s = this.cache.get(sql);
    if (!s) { s = this.db.prepare(sql); if (this.cache.size < 200) this.cache.set(sql, s); }
    return s;
  }

  async get(sql, p = []) { return this.stmt(sql).get(...p); }
  async all(sql, p = []) { return this.stmt(sql).all(...p); }
  async run(sql, p = []) { const r = this.stmt(sql).run(...p); return { changes: Number(r.changes) }; }
  async insert(sql, p = []) { const r = this.stmt(sql).run(...p); return Number(r.lastInsertRowid); }
  async exec(sql) { this.db.exec(sql); }

  /**
   * Transaction. Connexion unique : les transactions sont sérialisées et le corps `fn` ne doit faire QUE des appels
   * au store (pas d'attente externe : réseau, timers) pour ne pas intercaler d'autres requêtes.
   */
  tx(fn) {
    const next = this.lock.then(async () => {
      this.db.exec('BEGIN IMMEDIATE');
      try { const r = await fn(this); this.db.exec('COMMIT'); return r; } catch (e) { this.db.exec('ROLLBACK'); throw e; }
    });
    this.lock = next.catch(() => {});
    return next;
  }

  async close() { try { this.db.close(); } catch { /* déjà fermée */ } }
}

module.exports = { SqliteStore };
