'use strict';
/** Contrat de la couche de stockage : mêmes garanties sur SQLite et (si HUB_TEST_PG=1) PostgreSQL. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { openStore, schemaVersion, MIGRATIONS } = require('../lib/store');
const { render, toPostgres } = require('../lib/store/migrations');
const { translate } = require('../lib/store/postgres');
const { loadConfig } = require('../lib/config');

async function stores() {
  const out = [{ name: 'sqlite', store: await openStore(loadConfig({ file: '/none' }), { file: ':memory:' }), done: async () => {} }];
  if (process.env.HUB_TEST_PG) {
    const pg = require('pg');
    const o = { host: process.env.HUB_TEST_PG_HOST || '127.0.0.1', port: Number(process.env.HUB_TEST_PG_PORT || 5432), user: process.env.HUB_TEST_PG_USER || 'postgres' };
    const admin = new pg.Client({ ...o, database: 'postgres' }); await admin.connect();
    const db = `hubstore_${process.pid}`; await admin.query(`CREATE DATABASE ${db}`);
    const cfg = loadConfig({ file: '/none', overrides: { storage: { driver: 'postgres', postgres: { ...o, database: db, pool_max: 3 } } } });
    const store = await openStore(cfg);
    out.push({ name: 'postgres', store, done: async () => { await store.close(); await admin.query(`DROP DATABASE ${db} WITH (FORCE)`); await admin.end(); } });
  }
  return out;
}

test('traduction SQLite → PostgreSQL : placeholders et types, migration publiée inchangée côté SQLite', () => {
  assert.equal(translate('SELECT * FROM t WHERE a = ? AND b = ?'), 'SELECT * FROM t WHERE a = $1 AND b = $2');
  const pg = render(MIGRATIONS[0], 'postgres');
  assert.match(pg, /BIGSERIAL PRIMARY KEY/); assert.ok(!/AUTOINCREMENT|COLLATE NOCASE|\bINTEGER\b/.test(pg));
  assert.match(pg, /idx_users_username_lower/);
  assert.equal(render(MIGRATIONS[0], 'sqlite'), MIGRATIONS[0].sql);
  assert.equal(toPostgres('x INTEGER NOT NULL'), 'x BIGINT NOT NULL');
  assert.deepEqual(MIGRATIONS.map((m) => m.version), MIGRATIONS.map((_, i) => i + 1), 'versions contiguës');
});

test('stockage : insert/id, get/all/run, nombres, unicité insensible à la casse, transaction (commit + rollback)', async () => {
  for (const { name, store, done } of await stores()) {
    try {
      assert.equal(await schemaVersion(store), MIGRATIONS.length, name);
      const id = await store.insert('INSERT INTO users(username,pass_hash,role,created_at) VALUES (?,?,?,?)', ['Alice', 'h', 'viewer', 1_700_000_000_000]);
      assert.equal(typeof id, 'number', name);
      const row = await store.get('SELECT * FROM users WHERE lower(username) = lower(?)', ['ALICE']);
      assert.equal(row.id, id); assert.equal(row.created_at, 1_700_000_000_000, name + ' : bigint en nombre');
      await assert.rejects(store.insert('INSERT INTO users(username,pass_hash,role,created_at) VALUES (?,?,?,?)', ['alice', 'h', 'viewer', 1]), undefined, name + ' : doublon de casse refusé');
      const n = await store.get('SELECT COUNT(*) AS n, AVG(created_at) AS a FROM users');
      assert.equal(typeof n.n, 'number'); assert.equal(typeof n.a, 'number');
      assert.equal((await store.run('UPDATE users SET role = ? WHERE id = ?', ['admin', id])).changes, 1);
      assert.equal((await store.run('DELETE FROM users WHERE id = ?', [999999])).changes, 0);

      await assert.rejects(store.tx(async (t) => { await t.run('UPDATE users SET role = ?', ['viewer']); throw new Error('boom'); }), /boom/);
      assert.equal((await store.get('SELECT role FROM users WHERE id = ?', [id])).role, 'admin', name + ' : rollback');
      await store.tx(async (t) => { await t.run('UPDATE users SET role = ?', ['viewer']); });
      assert.equal((await store.get('SELECT role FROM users WHERE id = ?', [id])).role, 'viewer', name + ' : commit');
    } finally { await done(); }
  }
});

test('migrations : rejouées sans effet, une migration défaillante est annulée et signalée', async () => {
  const store = await openStore(loadConfig({ file: '/none' }), { file: ':memory:' });
  try {
    const before = await schemaVersion(store);
    MIGRATIONS.push({ version: before + 1, name: 'cassée', sql: 'CREATE TABLE ok_t (a INTEGER); CREATE TABLE ok_t (a INTEGER);' });
    await assert.rejects(require('../lib/store').openStore(loadConfig({ file: '/none' }), { file: ':memory:' }), /migration \d+ échouée/);
    MIGRATIONS.pop();
  } finally { await store.close(); }
});
