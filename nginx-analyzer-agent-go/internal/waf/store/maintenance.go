package store

import (
	"fmt"
	"strings"
	"time"
)

// Maintenance SQLite de waf.db (#100) : les purges de retention liberent des pages
// sans reduire le fichier. Meme logique que internal/store/maintenance.go :
// CompactOnStart (VACUUM si les seuils sont depasses) et Maintain (periodique :
// checkpoint WAL, PRAGMA optimize, incremental_vacuum, controle quick_check).
// La base n'a qu'une connexion : ces ordres attendent la fin du lot d'ecriture en cours.

// CompactOnStart : mode auto (seuils) | always | off. Renvoie true si un VACUUM a eu lieu.
func (s *Store) CompactOnStart(mode string, minFreeMb, minFreePct int) bool {
	if !s.OK() {
		return false
	}
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "off" || m == "false" || m == "0" {
		return false
	}
	size, free, pct, _ := s.freeStats()
	if !(m == "always" || m == "true" || m == "1" || (free >= int64(minFreeMb)*1024*1024 && pct >= minFreePct)) {
		return false
	}
	t0 := time.Now()
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	if _, err := s.db.Exec(`PRAGMA auto_vacuum = INCREMENTAL`); err != nil {
		return false
	}
	if _, err := s.db.Exec(`VACUUM`); err != nil {
		fmt.Printf("[db] waf: compactage impossible (%v)\n", err)
		return false
	}
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	after, _, _, _ := s.freeStats()
	fmt.Printf("[db] waf: compactage %d Mo -> %d Mo en %d ms\n", size/1048576, after/1048576, time.Since(t0).Milliseconds())
	return true
}

// Maintain : entretien leger periodique. Renvoie le resultat de quick_check ("ok" si sain).
func (s *Store) Maintain() string {
	if !s.OK() || s.closing.Load() {
		return ""
	}
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	_, _ = s.db.Exec(`PRAGMA optimize`)
	if _, _, _, av := s.freeStats(); av == 2 {
		_, _ = s.db.Exec(`PRAGMA incremental_vacuum(2000)`)
	}
	var res string
	if err := s.db.QueryRow(`PRAGMA quick_check`).Scan(&res); err != nil {
		return ""
	}
	if res != "ok" {
		fmt.Printf("[db] waf: quick_check en echec : %.200s\n", res)
	}
	return res
}

// freeStats : taille, octets libres, part libre (%), mode auto_vacuum.
func (s *Store) freeStats() (size, free int64, pct, autoVacuum int) {
	var ps, pc, fl int64
	_ = s.db.QueryRow(`PRAGMA page_size`).Scan(&ps)
	_ = s.db.QueryRow(`PRAGMA page_count`).Scan(&pc)
	_ = s.db.QueryRow(`PRAGMA freelist_count`).Scan(&fl)
	_ = s.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&autoVacuum)
	if pc > 0 {
		pct = int(float64(fl) / float64(pc) * 100)
	}
	return ps * pc, ps * fl, pct, autoVacuum
}
