'use strict';
/**
 * Maintenance PostgreSQL du Hub (#96) : VACUUM (ANALYZE) périodique des tables, en plus de l'autovacuum
 * (statistiques fraîches, espace récupéré après les purges d'audit, sessions et sauvegardes).
 * SQLite (#96) : checkpoint WAL (TRUNCATE), PRAGMA optimize, VACUUM si l'espace libre le justifie (toujours en
 * manuel), contrôle quick_check ; sérialisé avec les transactions du store. La liste des tables vient du catalogue (schéma courant), jamais d'une
 * requête ; verrou consultatif : un seul passage même avec plusieurs Hub sur la même base.
 */
const LOCK_KEY = 7310002;
const SQLITE_VACUUM_MIN_FREE = 8 * 1024 * 1024; // espace libre à partir duquel le passage planifié compacte
const quoteIdent = (s) => `"${String(s).replace(/"/g, '""')}"`;

function createMaintenance({ db, logger, intervalMs = 24 * 3_600_000, now = Date.now }) {
  const isSqlite = db.dialect === 'sqlite' && typeof db.exec === 'function' && typeof db.get === 'function';
  const supported = isSqlite || (db.dialect === 'postgres' && !!db.pool);
  const state = { running: false, last: null };
  let timer = null; let first = null;

  async function sqliteSizes() {
    const pc = Number((await db.get('PRAGMA page_count')).page_count);
    const fl = Number((await db.get('PRAGMA freelist_count')).freelist_count);
    const ps = Number((await db.get('PRAGMA page_size')).page_size);
    return { size_bytes: pc * ps, free_bytes: fl * ps };
  }

  async function runSqlite(trigger) {
    const rep = { trigger, started_at: now(), duration_ms: 0, tables: 0, vacuumed: false, integrity: null, freed_bytes: 0, error: null };
    // Chaîné au verrou des transactions : aucun VACUUM au milieu d'une transaction du Hub.
    const job = (db.lock || Promise.resolve()).then(async () => {
      const before = await sqliteSizes();
      await db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
      await db.exec('PRAGMA optimize');
      if (trigger === 'manual' || before.free_bytes >= SQLITE_VACUUM_MIN_FREE || (before.size_bytes > 0 && before.free_bytes / before.size_bytes >= 0.2)) {
        await db.exec('VACUUM');
        rep.vacuumed = true;
        rep.freed_bytes = Math.max(0, before.size_bytes - (await sqliteSizes()).size_bytes);
      }
      rep.integrity = String((await db.get('PRAGMA quick_check')).quick_check) === 'ok' ? 'ok' : 'échec';
      if (rep.integrity !== 'ok') logger.warn('maintenance SQLite : quick_check en échec');
    });
    db.lock = job.catch(() => {});
    await job;
    return { ok: true, report: rep };
  }

  async function run(trigger = 'manual') {
    if (!supported) return { ok: false, reason: 'unsupported' };
    if (state.running) return { ok: false, reason: 'busy' };
    state.running = true;
    if (isSqlite) {
      const t0 = now();
      try { const r = await runSqlite(trigger); r.report.duration_ms = now() - t0; state.last = r.report; return r; }
      catch (e) {
        logger.warn('maintenance SQLite', { err: e });
        state.last = { trigger, started_at: t0, duration_ms: now() - t0, tables: 0, vacuumed: false, integrity: null, freed_bytes: 0, error: 'échec' };
        return { ok: false, reason: 'error' };
      } finally { state.running = false; }
    }
    const rep = { trigger, started_at: now(), duration_ms: 0, tables: 0, error: null };
    let client = null; let locked = false;
    try {
      client = await db.pool.connect();
      // Hors délai d'instruction du pool (30 s) : un VACUUM peut durer. Remis à zéro en sortie.
      await client.query('SET statement_timeout = 0');
      const lk = await client.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_KEY]);
      locked = lk.rows[0].ok === true;
      if (!locked) { rep.skip = true; return { ok: false, reason: 'busy' }; } // un autre passage tourne : on ne masque pas son rapport
      const t = await client.query("SELECT tablename FROM pg_tables WHERE schemaname = current_schema() ORDER BY tablename");
      for (const r of t.rows) { await client.query(`VACUUM (ANALYZE) ${quoteIdent(r.tablename)}`); rep.tables += 1; }
      return { ok: true, report: rep };
    } catch (e) {
      rep.error = 'échec';
      logger.warn('maintenance PostgreSQL', { err: e });
      return { ok: false, reason: 'error' };
    } finally {
      if (client) {
        try { if (locked) await client.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]); await client.query('RESET statement_timeout'); } catch { /* connexion perdue */ }
        client.release();
      }
      rep.duration_ms = now() - rep.started_at;
      if (!rep.skip) state.last = rep;
      state.running = false;
    }
  }

  async function status() {
    if (isSqlite) {
      return { supported: true, engine: 'sqlite', enabled: intervalMs > 0, every_hours: Math.round(intervalMs / 3_600_000), running: state.running, last: state.last, ...(await sqliteSizes()), tables: [] };
    }
    if (!supported) return { supported: false, enabled: false, running: false, last: null, tables: [] };
    const tables = await db.all(`
      SELECT c.relname AS name, pg_total_relation_size(c.oid) AS size_bytes,
             COALESCE(t.n_live_tup, 0) AS live_rows, COALESCE(t.n_dead_tup, 0) AS dead_rows,
             COALESCE(t.last_vacuum, t.last_autovacuum) AS last_vacuum, COALESCE(t.last_analyze, t.last_autoanalyze) AS last_analyze
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = current_schema()
      LEFT JOIN pg_stat_user_tables t ON t.relid = c.oid
      WHERE c.relkind IN ('r','p') ORDER BY pg_total_relation_size(c.oid) DESC`);
    return {
      supported: true, engine: 'postgres', enabled: intervalMs > 0, every_hours: Math.round(intervalMs / 3_600_000), running: state.running, last: state.last,
      tables: tables.map((r) => ({ name: r.name, size_bytes: Number(r.size_bytes), live_rows: Number(r.live_rows), dead_rows: Number(r.dead_rows),
        last_vacuum: r.last_vacuum ? new Date(r.last_vacuum).toISOString() : null, last_analyze: r.last_analyze ? new Date(r.last_analyze).toISOString() : null })),
    };
  }

  function start(onStop) {
    if (!supported || !(intervalMs > 0)) return;
    // Premier passage ~10 min après le démarrage (pas de VACUUM pendant l'amorçage), puis à intervalle fixe.
    first = setTimeout(() => { run('schedule').catch(() => {}); timer = setInterval(() => { run('schedule').catch(() => {}); }, intervalMs); timer.unref(); }, 10 * 60_000);
    first.unref();
    if (onStop) onStop(() => { clearTimeout(first); clearInterval(timer); });
  }

  return { run, status, start, supported };
}

module.exports = { createMaintenance, quoteIdent };
