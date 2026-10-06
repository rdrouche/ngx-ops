'use strict';
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const dm = require('../lib/db-maintenance');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nlib/db-maintenance.js — compactage SQLite');
const { DatabaseSync } = require('node:sqlite');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dbm-'));
const db = new DatabaseSync(path.join(dir, 'x.db'));
db.exec('PRAGMA auto_vacuum = INCREMENTAL'); db.exec('PRAGMA journal_mode = WAL'); db.exec('CREATE TABLE junk(x TEXT)');
const ins = db.prepare('INSERT INTO junk VALUES (?)');
const fill = () => { db.exec('BEGIN'); for (let i = 0; i < 20000; i++) ins.run('x'.repeat(500) + i); db.exec('COMMIT'); };
fill(); db.exec('DELETE FROM junk');
check('pages libres apres DELETE', () => assert.ok(dm.freeStats(db).freePct > 50));
check('off : rien', () => assert.strictEqual(dm.compactIfNeeded(db, { mode: 'off', log() {} }).ran, false));
check('seuil non atteint : rien', () => assert.strictEqual(dm.compactIfNeeded(db, { minFreeMb: 9999, log() {} }).ran, false));
check('auto au-dessus des seuils : VACUUM, fichier reduit', () => {
  const r = dm.compactIfNeeded(db, { mode: 'auto', minFreeMb: 1, minFreePct: 10, log() {} });
  assert.ok(r.ran && r.after.sizeBytes < r.before.sizeBytes);
  assert.strictEqual(dm.freeStats(db).freePages, 0);
});
check('maintain recupere les pages libres (incremental_vacuum)', () => {
  fill(); db.exec('DELETE FROM junk'); const b = dm.freeStats(db).freePages;
  dm.maintain(db, { pages: 100000 }); assert.ok(dm.freeStats(db).freePages < b);
});
check('register ne leve jamais', () => assert.doesNotThrow(() => dm.register(db, 't', { DB_COMPACT_ON_START: 'off' })));
db.close();
console.log(`\n${pass} ok, ${fail} ko`); process.exit(fail ? 1 : 0);
