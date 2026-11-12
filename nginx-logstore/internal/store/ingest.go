package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"ngxops/logstore/internal/model"
)

var eventColumns = []string{
	"ts", "instance_id", "source", "action", "site", "ip", "ip_key", "method", "path",
	"query_hash", "status", "bytes", "rt_ms", "ua", "referer_host", "country", "bot_class", "rule", "extra",
}

// Ingest enregistre un lot de façon idempotente : un (instance, batchID) déjà
// vu n'écrit rien et renvoie duplicate=true. Le lot est atomique.
func (s *Store) Ingest(ctx context.Context, instanceID, instanceName, batchID string, rows []model.Row) (duplicate bool, err error) {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	ct, err := tx.Exec(ctx, `INSERT INTO ingest_batches(instance_id, batch_id, accepted) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, instanceID, batchID, len(rows))
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 0 {
		return true, nil
	}
	if len(rows) > 0 {
		src := pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
			r := rows[i]
			return []any{
				r.TS, instanceID, r.Source, r.Action, ptr(r.Site), r.IP, ptr(r.IPKey), ptr(r.Method), ptr(r.Path),
				ptr(r.QueryHash), ptr16(r.Status), ptr64(r.Bytes), ptr32(r.RTMs), ptr(r.UA), ptr(r.RefererHost),
				ptr(r.Country), ptr(r.BotClass), ptr(r.Rule), jsonOrNil(r.Extra),
			}, nil
		})
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"events"}, eventColumns, src); err != nil {
			return false, err
		}
	}
	var name any
	if instanceName != "" {
		name = instanceName
	}
	if _, err := tx.Exec(ctx, `INSERT INTO instances(id, name, events_total) VALUES ($1,$2,$3)
        ON CONFLICT (id) DO UPDATE SET last_seen = now(), events_total = instances.events_total + EXCLUDED.events_total,
        name = COALESCE(EXCLUDED.name, instances.name)`, instanceID, name, len(rows)); err != nil {
		return false, err
	}
	return false, tx.Commit(ctx)
}

func ptr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
func ptr16(p *int16) any {
	if p == nil {
		return nil
	}
	return *p
}
func ptr32(p *int32) any {
	if p == nil {
		return nil
	}
	return *p
}
func ptr64(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
func jsonOrNil(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}
