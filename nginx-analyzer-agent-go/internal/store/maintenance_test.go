package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCompactOnStartReclaimsSpace(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "m.db"))
	defer s.Close()
	if s.db == nil {
		t.Skip("sqlite indisponible")
	}
	if s.FreeStats().AutoVacuum != 2 {
		t.Fatalf("nouvelle base attendue en auto_vacuum incremental")
	}
	_, _ = s.db.Exec(`CREATE TABLE junk(x TEXT)`)
	pad := strings.Repeat("x", 500)
	tx, _ := s.db.Begin()
	for i := 0; i < 20000; i++ {
		_, _ = tx.Exec(`INSERT INTO junk VALUES (?)`, pad)
	}
	_ = tx.Commit()
	_, _ = s.db.Exec(`DELETE FROM junk`)
	if s.FreeStats().FreePct < 50 {
		t.Fatalf("pages libres attendues apres DELETE: %+v", s.FreeStats())
	}
	if r := s.CompactOnStart("off", 1, 10); r.Ran {
		t.Fatal("off ne doit rien faire")
	}
	if r := s.CompactOnStart("auto", 9999, 10); r.Ran {
		t.Fatal("seuil non atteint")
	}
	r := s.CompactOnStart("auto", 1, 10)
	if !r.Ran || r.After.SizeBytes >= r.Before.SizeBytes {
		t.Fatalf("compactage attendu: %+v", r)
	}
	if s.FreeStats().FreePages != 0 {
		t.Fatalf("plus de pages libres attendues")
	}
}

func TestHourlyBytes(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "h.db"))
	defer s.Close()
	if s.db == nil {
		t.Skip("sqlite indisponible")
	}
	_, _ = s.db.Exec(`INSERT INTO traffic (bucket,grain,vhost,country,status,method,requests,bytes) VALUES
		(7200,'minute','a','FR',2,'GET',1,100),(7260,'minute','a','FR',2,'GET',1,50),(3600,'hour','a','FR',2,'GET',5,1000),(7200,'minute','b','FR',2,'GET',1,7)`)
	got := map[string]int64{}
	for _, r := range s.HourlyBytes(0, 10_000_000) {
		got[r.Vhost+"@"+string(rune('0'+r.HourMs/3_600_000))] = r.Bytes
	}
	if got["a@2"] != 150 || got["a@1"] != 1000 || got["b@2"] != 7 {
		t.Fatalf("agregation horaire inattendue: %v", got)
	}
}

// #66 : sur une fenetre recente il n'existe que des lignes au grain "minute" ;
// Series au grain "hour" (et "day") doit les regrouper, sans doubler les lignes
// deja promues.
func TestSeriesHourAggregatesFinerGrains(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "series.db"))
	defer s.Close()
	if s.db == nil {
		t.Skip("sqlite indisponible")
	}
	_, _ = s.db.Exec(`INSERT INTO traffic (bucket,grain,vhost,country,status,method,requests,bytes) VALUES
		(7200,'minute','a','FR',2,'GET',1,100),(7260,'minute','a','FR',4,'GET',2,50),
		(3600,'hour','a','FR',2,'GET',5,1000),(7200,'minute','b','FR',2,'GET',1,7),
		(86400,'day','a','FR',2,'GET',9,9)`)
	h := s.Series("hour", 0, 20_000_000, "")
	got := map[int64]SeriesPoint{}
	for _, p := range h {
		got[p.Bucket] = p
	}
	if len(h) != 2 || got[7200].Requests != 4 || got[7200].Errors != 2 || got[7200].Bytes != 157 || got[3600].Requests != 5 {
		t.Fatalf("serie horaire inattendue: %+v", h)
	}
	if v := s.Series("hour", 0, 20_000_000, "b"); len(v) != 1 || v[0].Requests != 1 {
		t.Fatalf("filtre vhost: %+v", v)
	}
	if m := s.Series("minute", 0, 20_000_000, ""); len(m) != 2 {
		t.Fatalf("le grain minute reste exact: %+v", m)
	}
	if d := s.Series("day", 0, 200_000_000, ""); len(d) != 2 || d[0].Requests != 9 || d[1].Requests != 9 {
		t.Fatalf("serie jour: %+v", d)
	}
}
