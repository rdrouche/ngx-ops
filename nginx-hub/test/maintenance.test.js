'use strict';
// #96 : maintenance de la base du Hub (PostgreSQL : VACUUM ANALYZE, faux pool ; SQLite : vraie base temporaire).
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeApp, login } = require('./helpers');
const { createMaintenance, quoteIdent } = require('../lib/store/maintenance');

const P = '/api/hub/v1';
const PW = 'correct horse battery';
const SILENT = { debug() {}, info() {}, warn() {}, error() {} };

function fakePool({ lock = true, tables = ['audit', 'weird"name'], failOn = null } = {}) {
  const q = []; let released = 0;
  const client = {
    async query(sql, p) {
      q.push(sql);
      if (failOn && sql.includes(failOn)) throw new Error('boom');
      if (sql.includes('pg_try_advisory_lock')) return { rows: [{ ok: lock }] };
      if (sql.includes('pg_tables')) return { rows: tables.map((tablename) => ({ tablename })) };
      return { rows: [] };
    },
    release() { released += 1; },
  };
  return { db: { dialect: 'postgres', pool: { connect: async () => client }, all: async () => [] }, q, released: () => released };
}

test('quoteIdent double les guillemets (aucune injection par nom de table)', () => {
  assert.equal(quoteIdent('a"b'), '"a""b"');
});

test('VACUUM (ANALYZE) de chaque table du catalogue, sans délai d\'instruction, verrou pris puis libéré', async () => {
  const f = fakePool();
  const m = createMaintenance({ db: f.db, logger: SILENT });
  const r = await m.run('manual');
  assert.equal(r.ok, true);
  assert.equal(r.report.tables, 2);
  assert.ok(f.q[0].includes('SET statement_timeout = 0'));
  assert.ok(f.q.includes('VACUUM (ANALYZE) "audit"'));
  assert.ok(f.q.includes('VACUUM (ANALYZE) "weird""name"'));
  assert.ok(f.q.some((s) => s.includes('pg_advisory_unlock')) && f.q.at(-1) === 'RESET statement_timeout');
  assert.equal(f.released(), 1);
});

test('verrou pris ailleurs : rien n\'est vacuumé et le dernier rapport n\'est pas écrasé', async () => {
  const ok = fakePool();
  const m = createMaintenance({ db: ok.db, logger: SILENT });
  await m.run('manual');
  const busy = fakePool({ lock: false });
  const m2 = createMaintenance({ db: busy.db, logger: SILENT });
  assert.deepEqual(await m2.run('manual'), { ok: false, reason: 'busy' });
  assert.ok(!busy.q.some((s) => s.startsWith('VACUUM')));
  assert.equal(busy.released(), 1);
});

test('une erreur SQL est signalée sans fuite et libère la connexion', async () => {
  const f = fakePool({ failOn: 'VACUUM' });
  const m = createMaintenance({ db: f.db, logger: SILENT });
  assert.deepEqual(await m.run('manual'), { ok: false, reason: 'error' });
  assert.equal(f.released(), 1);
});

test('moteur inconnu : non pris en charge, aucune planification', async () => {
  const m = createMaintenance({ db: { dialect: 'autre' }, logger: SILENT });
  assert.equal(m.supported, false);
  assert.deepEqual(await m.run('manual'), { ok: false, reason: 'unsupported' });
  assert.equal((await m.status()).supported, false);
  m.start(() => assert.fail('aucune tâche ne doit être planifiée'));
});

test('SQLite réel : checkpoint, optimize, VACUUM manuel qui libère l\'espace, quick_check', async () => {
  const { SqliteStore } = require('../lib/store/sqlite');
  const os = require('node:os'); const path = require('node:path'); const fs = require('node:fs');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubmaint-'));
  const db = new SqliteStore(path.join(dir, 'm.sqlite'));
  try {
    await db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
    await db.tx(async (d) => { for (let i = 0; i < 2000; i++) await d.run('INSERT INTO t (v) VALUES (?)', ['x'.repeat(2000)]); });
    await db.run('DELETE FROM t');
    const m = createMaintenance({ db, logger: SILENT });
    assert.equal(m.supported, true);
    const before = await m.status();
    assert.equal(before.engine, 'sqlite');
    assert.ok(before.free_bytes > 1_000_000, 'espace libre après suppression');
    const r = await m.run('manual');
    assert.equal(r.ok, true);
    assert.equal(r.report.vacuumed, true);
    assert.equal(r.report.integrity, 'ok');
    assert.ok(r.report.freed_bytes > 1_000_000);
    const after = await m.status();
    assert.equal(after.running, false);
    assert.ok(after.free_bytes < before.free_bytes);
    assert.equal(after.last.error, null);
    // planifié : sous le seuil, pas de VACUUM
    const r2 = await m.run('schedule');
    assert.equal(r2.report.vacuumed, false);
    // reste utilisable (verrou des transactions libéré)
    await db.tx(async (d) => { await d.run('INSERT INTO t (v) VALUES (?)', ['ok']); });
    assert.equal((await db.get('SELECT count(*) AS n FROM t')).n, 1);
  } finally { await db.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('routes : admin seulement ; SQLite → supported:true, POST 202', { skip: !!process.env.HUB_TEST_PG }, async () => {
  const e = await makeApp();
  try {
    await e.users.create({ username: 'root', password: PW, role: 'admin' });
    await e.users.create({ username: 'lecteur', password: PW, role: 'viewer' });
    const viewer = (await login(e.base, 'lecteur', PW)).c;
    assert.equal((await viewer.get(`${P}/system/maintenance`)).status, 403);
    assert.equal((await viewer.post(`${P}/system/maintenance`)).status, 403);
    const admin = (await login(e.base, 'root', PW)).c;
    const st = await admin.get(`${P}/system/maintenance`);
    assert.equal(st.status, 200);
    assert.equal(st.json.supported, true);
    assert.equal(st.json.engine, 'sqlite');
    const run = await admin.post(`${P}/system/maintenance`);
    assert.equal(run.status, 202);
  } finally { await e.app.stop(); }
});

test('PostgreSQL réel (HUB_TEST_PG=1) : VACUUM ANALYZE des tables du Hub et état', { skip: !process.env.HUB_TEST_PG }, async () => {
  const e = await makeApp();
  try {
    const m = e.app.ctx.services.get('maintenance');
    assert.equal(m.supported, true);
    const r = await m.run('manual');
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(r.report.tables >= 3);
    const st = await m.status();
    assert.equal(st.supported, true);
    assert.equal(st.running, false);
    assert.equal(st.last.error, null);
    const names = st.tables.map((t) => t.name);
    assert.ok(names.includes('audit') && names.includes('sessions'), names.join(','));
    assert.ok(st.tables.every((t) => t.size_bytes > 0));
    assert.ok(st.tables.some((t) => t.last_vacuum), 'dernier vacuum renseigné après le passage');
  } finally { await e.app.stop(); }
});
