'use strict';
// v12.74.0 — Maintenance SQLite : recuperer l espace libere par les purges.
// Un DELETE ne reduit pas le fichier (pages libres reutilisables seulement).
//   - compactIfNeeded(db, opts) : au demarrage, VACUUM si la part de pages libres depasse les seuils
//     (bascule aussi la base en auto_vacuum=INCREMENTAL, applique par le VACUUM).
//   - maintain(db) : periodique, checkpoint WAL (TRUNCATE) + incremental_vacuum (rapide, non bloquant longtemps).
// Mode DB_COMPACT_ON_START : auto (defaut, seuils) | always | off.

const fs = require('fs');

function pragma(db, sql) {
  try { return db.prepare(`PRAGMA ${sql}`).get() || {}; } catch { return {}; }
}
function firstVal(o) { const k = Object.keys(o)[0]; return k ? Number(o[k]) : 0; }

/** Etat de la base : taille, pages libres, part reclamable. */
function freeStats(db) {
  const pageSize = firstVal(pragma(db, 'page_size')) || 4096;
  const pageCount = firstVal(pragma(db, 'page_count'));
  const freePages = firstVal(pragma(db, 'freelist_count'));
  return {
    pageSize, pageCount, freePages,
    sizeBytes: pageSize * pageCount,
    freeBytes: pageSize * freePages,
    freePct: pageCount ? Math.round((freePages / pageCount) * 100) : 0,
    autoVacuum: firstVal(pragma(db, 'auto_vacuum')),
  };
}

function compactIfNeeded(db, { mode = 'auto', minFreeMb = 16, minFreePct = 20, label = 'db', log = console.log } = {}) {
  const m = String(mode || 'auto').toLowerCase();
  if (m === 'off' || m === 'false' || m === '0') return { ran: false, reason: 'off' };
  const before = freeStats(db);
  const need = m === 'always' || m === 'true' || m === '1'
    || (before.freeBytes >= minFreeMb * 1024 * 1024 && before.freePct >= minFreePct);
  if (!need) return { ran: false, reason: 'below-threshold', before };
  const t0 = Date.now();
  try {
    try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch {}
    db.exec('PRAGMA auto_vacuum = INCREMENTAL');
    db.exec('VACUUM');
    try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch {}
  } catch (e) {
    log(`[db] ${label}: compactage impossible (${e.message})`);
    return { ran: false, reason: 'error', error: e.message, before };
  }
  const after = freeStats(db);
  const r = { ran: true, ms: Date.now() - t0, before, after, reclaimedBytes: Math.max(0, before.sizeBytes - after.sizeBytes) };
  log(`[db] ${label}: compactage ${Math.round(before.sizeBytes / 1048576)} Mo -> ${Math.round(after.sizeBytes / 1048576)} Mo en ${r.ms} ms`);
  return r;
}

/** Entretien leger periodique. */
function maintain(db, { pages = 2000 } = {}) {
  try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch {}
  try {
    if (freeStats(db).autoVacuum === 2) db.exec(`PRAGMA incremental_vacuum(${Math.max(1, pages | 0)})`);
  } catch {}
  return freeStats(db);
}

/** Taille des fichiers .db/-wal/-shm d une base (pour affichage). */
function fileBytes(dbPath) {
  let n = 0;
  for (const suf of ['', '-wal', '-shm']) { try { n += fs.statSync(dbPath + suf).size; } catch {} }
  return n;
}

/**
 * Dashboard : compactage au demarrage (selon DB_COMPACT_ON_START / seuils) puis entretien toutes les 6 h.
 * A appeler une fois la base ouverte et purgee. Ne leve jamais.
 */
function register(db, label, cfg) {
  try {
    compactIfNeeded(db, {
      mode: cfg.DB_COMPACT_ON_START, minFreeMb: cfg.DB_COMPACT_MIN_FREE_MB,
      minFreePct: cfg.DB_COMPACT_MIN_FREE_PCT, label,
    });
    const t = setInterval(() => { try { maintain(db); } catch {} }, 6 * 3_600_000);
    if (t.unref) t.unref();
  } catch (e) { console.warn(`[db] ${label}: maintenance indisponible:`, e.message); }
}

module.exports = { freeStats, compactIfNeeded, maintain, fileBytes, register };
