package store

import (
	"context"
	"fmt"
	"time"
)

// Vérifications de santé du stockage (#96) : compression, rétention, agrégats
// continus et respect effectif de la rétention. Lecture seule, meilleur effort :
// une vérification impossible est « unknown », jamais une erreur de l'API.

// Check : résultat d'une vérification. Status : ok | warn | fail | na | unknown.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type tsJob struct {
	proc      string
	after     string // drop_after ou compress_after
	lastRun   string
	lastOK    *time.Time
	failures  int64
	scheduled bool
}

// jobsOf liste les politiques TimescaleDB d'une (hyper)table.
// Selon la version, un agrégat continu y apparaît sous le nom de sa vue ou de
// son hypertable de matérialisation : on accepte les deux.
func (s *Store) jobsOf(ctx context.Context, names ...string) ([]tsJob, error) {
	rows, err := s.admin.Query(ctx, `
SELECT j.proc_name, COALESCE(j.config->>'drop_after', j.config->>'compress_after', ''), j.scheduled,
       COALESCE(st.last_run_status, ''), st.last_successful_finish, COALESCE(st.total_failures, 0)::bigint
FROM timescaledb_information.jobs j
LEFT JOIN timescaledb_information.job_stats st ON st.job_id = j.job_id
WHERE j.hypertable_name = ANY($1)`, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tsJob
	for rows.Next() {
		var j tsJob
		if err := rows.Scan(&j.proc, &j.after, &j.scheduled, &j.lastRun, &j.lastOK, &j.failures); err != nil {
			return nil, err
		}
		j.lastOK = utcPtr(j.lastOK)
		out = append(out, j)
	}
	return out, rows.Err()
}

func findJob(jobs []tsJob, proc string) *tsJob {
	for i := range jobs {
		if jobs[i].proc == proc {
			return &jobs[i]
		}
	}
	return nil
}

func jobHealth(j *tsJob, maxAge time.Duration) (status, detail string) {
	switch {
	case !j.scheduled:
		return "warn", "politique désactivée"
	case j.lastRun == "Failed" || j.failures > 0 && j.lastRun != "Success":
		return "fail", fmt.Sprintf("dernière exécution en échec (%d échecs au total)", j.failures)
	case j.lastOK == nil:
		return "warn", "jamais exécutée pour l'instant"
	case time.Since(*j.lastOK) > maxAge:
		return "warn", "dernier succès " + j.lastOK.Format(time.RFC3339) + " (trop ancien)"
	}
	return "ok", "dernier succès " + j.lastOK.Format(time.RFC3339)
}

// Checks exécute les vérifications.
func (s *Store) Checks(ctx context.Context) []Check {
	set := s.Settings()
	var out []Check
	add := func(name, status, detail string) { out = append(out, Check{name, status, detail}) }

	// Rétention effectivement appliquée (vrai aussi en mode simple).
	var oldest *time.Time
	if err := s.admin.QueryRow(ctx, `SELECT min(ts) FROM events`).Scan(&oldest); err != nil {
		add("retention_effective", "unknown", "lecture impossible")
	} else if oldest == nil {
		add("retention_effective", "ok", "aucun événement")
	} else {
		age := time.Since(*oldest)
		limit := time.Duration(set.RetentionDays+2) * 24 * time.Hour // marge : granularité des chunks
		if age > limit {
			add("retention_effective", "warn", fmt.Sprintf("événement le plus ancien : %d jours pour une rétention de %d", int(age.Hours()/24), set.RetentionDays))
		} else {
			add("retention_effective", "ok", fmt.Sprintf("événement le plus ancien : %d jours (rétention %d)", int(age.Hours()/24), set.RetentionDays))
		}
	}

	if !s.timescale {
		add("timescaledb", "na", "mode PostgreSQL simple : pas de compression ni de cumuls longs, purge par la maintenance")
		return out
	}

	var comp bool
	if err := s.admin.QueryRow(ctx, `SELECT COALESCE(bool_or(compression_enabled), false) FROM timescaledb_information.hypertables WHERE hypertable_name = 'events'`).Scan(&comp); err != nil {
		add("compression", "unknown", "lecture impossible")
	} else if !comp {
		add("compression", "fail", "compression non activée sur events")
	} else if jobs, err := s.jobsOf(ctx, "events"); err != nil {
		add("compression", "unknown", "politiques illisibles")
	} else if j := findJob(jobs, "policy_compression"); j == nil {
		add("compression", "fail", "aucune politique de compression")
	} else {
		st, d := jobHealth(j, 26*time.Hour)
		if j.after != "2 days" && st == "ok" {
			st, d = "warn", "compression après "+j.after+" (attendu 2 days)"
		}
		add("compression", st, d)
	}
	if jobs, err := s.jobsOf(ctx, "events"); err == nil {
		if j := findJob(jobs, "policy_retention"); j == nil {
			add("retention_events", "fail", "aucune politique de rétention sur events")
		} else if want := fmt.Sprintf("%d days", set.RetentionDays); j.after != want {
			add("retention_events", "warn", "politique : "+j.after+", réglage : "+want)
		} else {
			st, d := jobHealth(j, 26*time.Hour)
			add("retention_events", st, d)
		}
	}

	for _, a := range aggregates {
		var mat string
		if err := s.admin.QueryRow(ctx, `SELECT materialization_hypertable_name FROM timescaledb_information.continuous_aggregates WHERE view_name = $1`, a.name).Scan(&mat); err != nil {
			add("aggregate_"+a.name, "fail", "agrégat continu absent")
			continue
		}
		jobs, err := s.jobsOf(ctx, a.name, mat)
		if err != nil {
			add("aggregate_"+a.name, "unknown", "politiques illisibles")
			continue
		}
		if j := findJob(jobs, "policy_refresh_continuous_aggregate"); j == nil {
			add("aggregate_"+a.name, "fail", "aucune politique de rafraîchissement")
		} else {
			st, d := jobHealth(j, 3*time.Hour) // planifié toutes les 30 min
			add("aggregate_"+a.name, st, d)
		}
		if j := findJob(jobs, "policy_retention"); j == nil {
			add("retention_"+a.name, "fail", "aucune politique de rétention")
		} else if want := fmt.Sprintf("%d days", set.AggRetentionDays); j.after != want {
			add("retention_"+a.name, "warn", "politique : "+j.after+", réglage : "+want)
		} else {
			st, d := jobHealth(j, 26*time.Hour)
			add("retention_"+a.name, st, d)
		}
	}
	return out
}
