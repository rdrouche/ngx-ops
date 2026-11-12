'use strict';
/**
 * Adaptateur PostgreSQL (option). Dépendance `pg` chargée UNIQUEMENT si storage.driver = postgres :
 * l'installation par défaut reste sans aucune dépendance npm.
 * Les requêtes sont écrites avec des « ? » (dialecte commun) et traduites en $1, $2…
 */
function translate(sql) { let i = 0; return sql.replace(/\?/g, () => `$${++i}`); }

class PgExecutor {
  constructor(q) { this.q = q; }
  async get(sql, p = []) { const r = await this.q(translate(sql), p); return r.rows[0]; }
  async all(sql, p = []) { const r = await this.q(translate(sql), p); return r.rows; }
  async run(sql, p = []) { const r = await this.q(translate(sql), p); return { changes: r.rowCount || 0 }; }
  async insert(sql, p = []) { const r = await this.q(translate(sql) + ' RETURNING id', p); return Number(r.rows[0].id); }
  async exec(sql) { await this.q(sql); }
}

class PostgresStore extends PgExecutor {
  constructor(opts) {
    let pg;
    try { pg = require('pg'); } catch {
      throw new Error("storage.driver=postgres exige le paquet « pg » (npm install pg ; l'image Docker le fournit avec --build-arg WITH_PG=1)");
    }
    // bigint (int8) et numeric arrivent en chaîne par défaut : les horodatages en ms et AVG() doivent être des nombres.
    pg.types.setTypeParser(20, (v) => Number(v));
    pg.types.setTypeParser(1700, (v) => Number(v));
    const pool = new pg.Pool(opts);
    pool.on('error', () => { /* connexion inactive perdue : le pool la remplace */ });
    super((sql, p) => pool.query(sql, p));
    this.dialect = 'postgres';
    this.pool = pool;
  }

  async tx(fn) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const r = await fn(new PgExecutor((sql, p) => client.query(sql, p)));
      await client.query('COMMIT');
      return r;
    } catch (e) { try { await client.query('ROLLBACK'); } catch { /* connexion perdue */ } throw e; } finally { client.release(); }
  }

  async close() { await this.pool.end(); }
}

module.exports = { PostgresStore, translate };
