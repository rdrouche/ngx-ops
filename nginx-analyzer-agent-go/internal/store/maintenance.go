package store

import (
	"fmt"
	"strings"
	"time"
)

// v12.74.0 - maintenance SQLite : recuperer l'espace libere par les purges.
// Un DELETE ne reduit pas le fichier. CompactOnStart() fait un VACUUM quand la
// part de pages libres depasse les seuils ; Maintain() (periodique) fait un
// checkpoint WAL + optimize + incremental_vacuum + quick_check (#100). Parite : lib/db-maintenance.js.

// FreeStats decrit l'occupation de la base.
type FreeStats struct {
	PageSize, PageCount, FreePages int64
	SizeBytes, FreeBytes           int64
	FreePct                        int
	AutoVacuum                     int
}

func (s *Store) freeStatsLocked() FreeStats {
	var f FreeStats
	if s.db == nil {
		return f
	}
	_ = s.db.QueryRow(`PRAGMA page_size`).Scan(&f.PageSize)
	_ = s.db.QueryRow(`PRAGMA page_count`).Scan(&f.PageCount)
	_ = s.db.QueryRow(`PRAGMA freelist_count`).Scan(&f.FreePages)
	_ = s.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&f.AutoVacuum)
	f.SizeBytes = f.PageSize * f.PageCount
	f.FreeBytes = f.PageSize * f.FreePages
	if f.PageCount > 0 {
		f.FreePct = int(float64(f.FreePages) / float64(f.PageCount) * 100)
	}
	return f
}

// FreeStats expose l'etat d'occupation.
func (s *Store) FreeStats() FreeStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.freeStatsLocked()
}

// CompactResult : Ran=false si rien n'a ete fait (Reason dit pourquoi).
type CompactResult struct {
	Ran           bool
	Reason        string
	Before, After FreeStats
	Ms            int64
}

// CompactOnStart : mode auto (seuils) | always | off.
func (s *Store) CompactOnStart(mode string, minFreeMb, minFreePct int) CompactResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return CompactResult{Reason: "memory"}
	}
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "off" || m == "false" || m == "0" {
		return CompactResult{Reason: "off"}
	}
	before := s.freeStatsLocked()
	need := m == "always" || m == "true" || m == "1" ||
		(before.FreeBytes >= int64(minFreeMb)*1024*1024 && before.FreePct >= minFreePct)
	if !need {
		return CompactResult{Reason: "below-threshold", Before: before}
	}
	t0 := time.Now()
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	if _, err := s.db.Exec(`PRAGMA auto_vacuum = INCREMENTAL`); err == nil {
		if _, err := s.db.Exec(`VACUUM`); err != nil {
			fmt.Printf("[db] analyzer: compactage impossible (%v)\n", err)
			return CompactResult{Reason: "error", Before: before}
		}
	}
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	after := s.freeStatsLocked()
	r := CompactResult{Ran: true, Before: before, After: after, Ms: time.Since(t0).Milliseconds()}
	fmt.Printf("[db] analyzer: compactage %d Mo -> %d Mo en %d ms\n", before.SizeBytes/1048576, after.SizeBytes/1048576, r.Ms)
	return r
}

// Maintain : checkpoint WAL + incremental_vacuum (si auto_vacuum=INCREMENTAL).
func (s *Store) Maintain() FreeStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return FreeStats{}
	}
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	_, _ = s.db.Exec(`PRAGMA optimize`) // #100 : statistiques du planificateur a jour
	if s.freeStatsLocked().AutoVacuum == 2 {
		_, _ = s.db.Exec(`PRAGMA incremental_vacuum(2000)`)
	}
	var qc string
	if err := s.db.QueryRow(`PRAGMA quick_check`).Scan(&qc); err == nil && qc != "ok" {
		fmt.Printf("[db] analyzer: quick_check en echec : %.200s\n", qc)
	}
	return s.freeStatsLocked()
}
