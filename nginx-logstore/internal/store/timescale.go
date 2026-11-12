package store

import (
	"context"
	"fmt"
	"strconv"
)

// aggSelect produit la requête d'agrégat (identique en mode TimescaleDB et en
// mode simple, seule la fonction de bucket change).
func aggSelect(bucketExpr string) string {
	return `SELECT ` + bucketExpr + ` AS bucket,
    instance_id,
    COALESCE(site, '') AS site,
    source,
    action,
    count(*)::bigint AS requests,
    (count(*) FILTER (WHERE status BETWEEN 200 AND 299))::bigint AS s2xx,
    (count(*) FILTER (WHERE status BETWEEN 300 AND 399))::bigint AS s3xx,
    (count(*) FILTER (WHERE status BETWEEN 400 AND 499))::bigint AS s4xx,
    (count(*) FILTER (WHERE status BETWEEN 500 AND 599))::bigint AS s5xx,
    COALESCE(sum(bytes), 0)::bigint AS bytes
FROM events
GROUP BY 1, 2, 3, 4, 5`
}

var aggregates = []struct{ name, bucket string }{
	{"events_1h", "1 hour"},
	{"events_1d", "1 day"},
}

// setupTimescale configure hypertable, compression, agrégats continus et
// politiques. Idempotent. Renvoie false (sans erreur bloquante) si
// l'extension n'est pas disponible.
func (s *Store) setupTimescale(ctx context.Context) (bool, error) {
	var avail bool
	if err := s.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_available_extensions WHERE name='timescaledb')`).Scan(&avail); err != nil {
		return false, err
	}
	if !avail {
		return false, nil
	}
	if _, err := s.admin.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS timescaledb`); err != nil {
		return false, fmt.Errorf("CREATE EXTENSION timescaledb : %w", err)
	}
	steps := []string{
		`SELECT create_hypertable('events', 'ts', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE, migrate_data => TRUE)`,
		`ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'instance_id, site', timescaledb.compress_orderby = 'ts DESC')`,
		`SELECT add_compression_policy('events', INTERVAL '2 days', if_not_exists => TRUE)`,
	}
	for _, q := range steps {
		if _, err := s.admin.Exec(ctx, q); err != nil {
			return false, fmt.Errorf("%.60s… : %w", q, err)
		}
	}
	for _, a := range aggregates {
		var isCagg bool
		if err := s.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM timescaledb_information.continuous_aggregates WHERE view_name=$1)`, a.name).Scan(&isCagg); err != nil {
			return false, err
		}
		if !isCagg {
			// Une vue du mode simple (passage dev -> TimescaleDB) est remplacée.
			if _, err := s.admin.Exec(ctx, `DROP VIEW IF EXISTS `+a.name); err != nil {
				return false, err
			}
			q := `CREATE MATERIALIZED VIEW ` + a.name + ` WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS ` +
				aggSelect(`time_bucket(INTERVAL '`+a.bucket+`', ts)`) + ` WITH NO DATA`
			if _, err := s.admin.Exec(ctx, q); err != nil {
				return false, fmt.Errorf("agrégat %s : %w", a.name, err)
			}
		}
		// La fenêtre de rafraîchissement reste plus courte que la rétention brute :
		// les cumuls survivent à la suppression des chunks.
		q := `SELECT add_continuous_aggregate_policy('` + a.name + `', start_offset => INTERVAL '3 days', end_offset => INTERVAL '1 hour', schedule_interval => INTERVAL '30 minutes', if_not_exists => TRUE)`
		if _, err := s.admin.Exec(ctx, q); err != nil {
			return false, fmt.Errorf("politique %s : %w", a.name, err)
		}
	}
	return true, nil
}

// setupPlainViews crée des vues équivalentes sans TimescaleDB (dev/test).
func (s *Store) setupPlainViews(ctx context.Context) error {
	for _, a := range aggregates {
		unit := "hour"
		if a.bucket == "1 day" {
			unit = "day"
		}
		q := `CREATE OR REPLACE VIEW ` + a.name + ` AS ` + aggSelect(`date_trunc('`+unit+`', ts)`)
		if _, err := s.admin.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// applyRetention (re)programme les politiques TimescaleDB. En mode simple, la
// purge est faite par Maintain.
func (s *Store) applyRetention(ctx context.Context, c Settings) error {
	if !s.timescale {
		return nil
	}
	steps := []struct {
		rel  string
		days int
	}{
		{"events", c.RetentionDays},
		{"events_1h", c.AggRetentionDays},
		{"events_1d", c.AggRetentionDays},
	}
	for _, st := range steps {
		if _, err := s.admin.Exec(ctx, `SELECT remove_retention_policy('`+st.rel+`', if_exists => TRUE)`); err != nil {
			return err
		}
		if _, err := s.admin.Exec(ctx, `SELECT add_retention_policy('`+st.rel+`', INTERVAL '`+strconv.Itoa(st.days)+` days')`); err != nil {
			return err
		}
	}
	return nil
}
