package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaintenanceCompactsAndChecks(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.DoSync(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`CREATE TABLE junk (v TEXT)`); err != nil {
			return err
		}
		for i := 0; i < 3000; i++ {
			if _, err := tx.Exec(`INSERT INTO junk (v) VALUES (?)`, strings.Repeat("x", 2000)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DoSync(func(tx *sql.Tx) error { _, err := tx.Exec(`DELETE FROM junk`); return err }); err != nil {
		t.Fatal(err)
	}
	before, free, pct, _ := s.freeStats()
	if free < 1<<20 || pct < 20 {
		t.Fatalf("espace libre attendu apres suppression : %d octets, %d %%", free, pct)
	}
	if s.CompactOnStart("off", 0, 0) {
		t.Fatal("mode off : aucun compactage")
	}
	if !s.CompactOnStart("auto", 1, 20) {
		t.Fatal("mode auto au-dessus des seuils : compactage attendu")
	}
	after, _, _, av := s.freeStats()
	if after >= before || av != 2 {
		t.Fatalf("taille %d -> %d, auto_vacuum=%d", before, after, av)
	}
	if got := s.Maintain(); got != "ok" {
		t.Fatalf("quick_check = %q", got)
	}
	if s.CompactOnStart("auto", 16, 20) {
		t.Fatal("sous les seuils : pas de compactage")
	}
}

func TestMaintenanceDisabledStoreIsNoop(t *testing.T) {
	s := Disabled()
	if s.CompactOnStart("always", 0, 0) || s.Maintain() != "" {
		t.Fatal("Store nul : aucune action")
	}
}
