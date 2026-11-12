package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Maintenance PostgreSQL (#96) : VACUUM (ANALYZE) périodique des tables, en
// plus de la purge (Maintain) et des politiques TimescaleDB (compression,
// rétention). L'autovacuum de PostgreSQL reste actif ; cette tâche couvre ce
// qu'il laisse : statistiques fraîches après purge massive, tables de
// service (lots d'ingestion, jetons) très mises à jour.

// ErrMaintenanceBusy : une maintenance est déjà en cours (ici ou ailleurs).
var ErrMaintenanceBusy = errors.New("maintenance déjà en cours")

// maintenanceTables est une liste fermée (jamais de nom venant d'une requête).
var maintenanceTables = []string{"events", "ingest_batches", "api_tokens", "instances", "settings"}

const maintenanceLockKey = 7_424_001 // verrou consultatif : un seul VACUUM à la fois, même avec plusieurs réplicas

// MaintenanceReport décrit une exécution.
type MaintenanceReport struct {
	Trigger    string    `json:"trigger"` // schedule | manual
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Tables     []string  `json:"tables"`
	Error      string    `json:"error,omitempty"`
}

// TableStat : état d'une table (pg_stat_user_tables).
type TableStat struct {
	Name          string     `json:"name"`
	SizeBytes     int64      `json:"size_bytes"`
	LiveTuples    int64      `json:"live_tuples"`
	DeadTuples    int64      `json:"dead_tuples"`
	LastVacuum    *time.Time `json:"last_vacuum,omitempty"`
	LastAutovac   *time.Time `json:"last_autovacuum,omitempty"`
	LastAnalyze   *time.Time `json:"last_analyze,omitempty"`
	LastAutoanaly *time.Time `json:"last_autoanalyze,omitempty"`
}

// MaintenanceStatus : dernier passage, exécution en cours et état des tables.
type MaintenanceStatus struct {
	Running bool               `json:"running"`
	Last    *MaintenanceReport `json:"last,omitempty"`
	Tables  []TableStat        `json:"tables"`
	// Compression TimescaleDB de la table events (absent en mode simple).
	Compression *CompressionStat `json:"compression,omitempty"`
}

// CompressionStat résume la compression TimescaleDB.
type CompressionStat struct {
	CompressedChunks int64 `json:"compressed_chunks"`
	TotalChunks      int64 `json:"total_chunks"`
	BytesBefore      int64 `json:"bytes_before"`
	BytesAfter       int64 `json:"bytes_after"`
}

type maintState struct {
	mu      sync.Mutex
	running bool
	last    *MaintenanceReport
}

// RunMaintenance purge puis exécute VACUUM (ANALYZE) sur les tables du service.
// Ne renvoie ErrMaintenanceBusy que si une autre exécution est en cours.
func (s *Store) RunMaintenance(ctx context.Context, trigger string) (MaintenanceReport, error) {
	rep := MaintenanceReport{Trigger: trigger, StartedAt: time.Now().UTC(), Tables: []string{}}
	s.maint.mu.Lock()
	if s.maint.running {
		s.maint.mu.Unlock()
		return rep, ErrMaintenanceBusy
	}
	s.maint.running = true
	s.maint.mu.Unlock()
	defer func() {
		rep.DurationMS = time.Since(rep.StartedAt).Milliseconds()
		s.maint.mu.Lock()
		s.maint.running = false
		r := rep
		s.maint.last = &r
		s.maint.mu.Unlock()
	}()

	if err := s.Maintain(ctx); err != nil {
		rep.Error = "purge : échec"
		return rep, err
	}
	// Connexion dédiée : VACUUM ne s'exécute pas dans une transaction et peut
	// dépasser le statement_timeout du pool.
	conn, err := s.admin.Acquire(ctx)
	if err != nil {
		rep.Error = "connexion indisponible"
		return rep, err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, maintenanceLockKey).Scan(&got); err != nil {
		rep.Error = "verrou : échec"
		return rep, err
	}
	if !got {
		rep.Error = ErrMaintenanceBusy.Error()
		return rep, ErrMaintenanceBusy
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, maintenanceLockKey)
		_, _ = conn.Exec(context.Background(), `RESET statement_timeout`)
	}()
	if _, err := conn.Exec(ctx, `SET statement_timeout = 0`); err != nil {
		rep.Error = "réglage de session : échec"
		return rep, err
	}
	for _, t := range maintenanceTables {
		if _, err := conn.Exec(ctx, `VACUUM (ANALYZE) `+t); err != nil {
			rep.Error = fmt.Sprintf("VACUUM %s : échec", t)
			return rep, fmt.Errorf("VACUUM %s : %w", t, err)
		}
		rep.Tables = append(rep.Tables, t)
	}
	return rep, nil
}

// MaintenanceDue indique si une exécution planifiée est due (jamais exécutée
// depuis le démarrage, ou intervalle écoulé).
func (s *Store) MaintenanceDue(interval time.Duration) bool {
	s.maint.mu.Lock()
	defer s.maint.mu.Unlock()
	if s.maint.running {
		return false
	}
	if s.maint.last == nil {
		return time.Since(s.started) >= 10*time.Minute
	}
	return time.Since(s.maint.last.StartedAt) >= interval
}

// MaintenanceStatus collecte l'état (lecture seule).
func (s *Store) MaintenanceStatus(ctx context.Context) (MaintenanceStatus, error) {
	st := MaintenanceStatus{Tables: []TableStat{}}
	s.maint.mu.Lock()
	st.Running = s.maint.running
	if s.maint.last != nil {
		l := *s.maint.last
		st.Last = &l
	}
	s.maint.mu.Unlock()

	rows, err := s.read.Query(ctx, `
SELECT c.relname,
       pg_total_relation_size(c.oid)::bigint,
       COALESCE(t.n_live_tup, 0)::bigint, COALESCE(t.n_dead_tup, 0)::bigint,
       t.last_vacuum, t.last_autovacuum, t.last_analyze, t.last_autoanalyze
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
LEFT JOIN pg_stat_user_tables t ON t.relid = c.oid
WHERE c.relkind IN ('r', 'p') AND c.relname = ANY($1)
ORDER BY c.relname`, maintenanceTables)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var t TableStat
		if err := rows.Scan(&t.Name, &t.SizeBytes, &t.LiveTuples, &t.DeadTuples, &t.LastVacuum, &t.LastAutovac, &t.LastAnalyze, &t.LastAutoanaly); err != nil {
			return st, err
		}
		t.LastVacuum, t.LastAutovac, t.LastAnalyze, t.LastAutoanaly = utcPtr(t.LastVacuum), utcPtr(t.LastAutovac), utcPtr(t.LastAnalyze), utcPtr(t.LastAutoanaly)
		st.Tables = append(st.Tables, t)
	}
	if err := rows.Err(); err != nil {
		return st, err
	}
	if s.timescale {
		var c CompressionStat
		// Meilleur effort : la vue peut être vide ou absente selon la version.
		if err := s.read.QueryRow(ctx, `SELECT count(*) FILTER (WHERE is_compressed)::bigint, count(*)::bigint FROM timescaledb_information.chunks WHERE hypertable_name = 'events'`).Scan(&c.CompressedChunks, &c.TotalChunks); err == nil {
			_ = s.read.QueryRow(ctx, `SELECT COALESCE(before_compression_total_bytes,0)::bigint, COALESCE(after_compression_total_bytes,0)::bigint FROM hypertable_compression_stats('events')`).Scan(&c.BytesBefore, &c.BytesAfter)
			st.Compression = &c
		}
	}
	return st, nil
}

// MaintenanceRunning : une maintenance est en cours dans ce processus.
func (s *Store) MaintenanceRunning() bool {
	s.maint.mu.Lock()
	defer s.maint.mu.Unlock()
	return s.maint.running
}
