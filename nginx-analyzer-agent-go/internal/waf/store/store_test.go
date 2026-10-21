package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sub", "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mkHit(ts int64, ip, vhost string, rule, score int, mode string) Hit {
	return Hit{TS: ts, Vhost: vhost, IP: ip, Method: "GET", URI: "/x?id=1'", Status: 404, UA: "ua", Score: score, Mode: mode, Format: "combined",
		Rules: []HitRule{{ID: rule, Msg: "m", Severity: "CRITICAL", Score: score, Data: "d", Tags: []string{"attack-sqli"}, Category: "sqli"}}}
}

func TestHitsRoundTripAndFilters(t *testing.T) {
	s := open(t)
	now := time.Now().UnixMilli()
	hits := []Hit{
		mkHit(now-3000, "1.1.1.1", "a.com", 942100, 5, "observe"),
		mkHit(now-2000, "1.1.1.1", "a.com", 941110, 10, "remediate"),
		mkHit(now-1000, "2.2.2.2", "b.com", 942100, 5, "observe"),
	}
	hits[1].PossiblySucceeded = true
	s.Do(func(tx *sql.Tx) error { return InsertHits(tx, hits) })
	s.Flush()
	ctx := context.Background()
	total, got, err := s.QueryHits(ctx, HitFilter{Limit: 10})
	if err != nil || total != 3 || len(got) != 3 {
		t.Fatalf("%v %d %d", err, total, len(got))
	}
	if got[0].IP != "2.2.2.2" { // desc
		t.Fatalf("ordre desc: %+v", got[0])
	}
	if got[1].Rules[0].ID != 941110 || got[1].Rules[0].Tags[0] != "attack-sqli" || !got[1].PossiblySucceeded {
		t.Fatalf("regles: %+v", got[1])
	}
	check := func(f HitFilter, want int) {
		t.Helper()
		f.Limit = 10
		tot, hs, err := s.QueryHits(ctx, f)
		if err != nil || tot != want || len(hs) != want {
			t.Errorf("%+v : %v total=%d len=%d (attendu %d)", f, err, tot, len(hs), want)
		}
	}
	check(HitFilter{IP: "1.1.1.1"}, 2)
	check(HitFilter{Vhost: "b.com"}, 1)
	check(HitFilter{Rule: 942100}, 2)
	check(HitFilter{MinScore: 6}, 1)
	check(HitFilter{Mode: "remediate"}, 1)
	check(HitFilter{Since: now - 2500}, 2)
	check(HitFilter{Until: now - 2500}, 1)
	check(HitFilter{IP: "1.1.1.1", Rule: 941110, Mode: "remediate"}, 1)
	_, page, _ := s.QueryHits(ctx, HitFilter{Limit: 1, Offset: 1, Asc: true})
	if len(page) != 1 || page[0].Rules[0].ID != 941110 {
		t.Fatalf("pagination asc: %+v", page)
	}
	// injection SQL via filtre : traite comme valeur
	check(HitFilter{IP: "1.1.1.1' OR '1'='1"}, 0)
}

func TestStats(t *testing.T) {
	s := open(t)
	now := time.Now().UnixMilli()
	s.Do(func(tx *sql.Tx) error {
		if err := InsertHits(tx, []Hit{mkHit(now-1000, "1.1.1.1", "a.com", 942100, 5, "observe"), mkHit(now-500, "1.1.1.1", "a.com", 942100, 5, "observe"), mkHit(now-400, "2.2.2.2", "b.com", 941110, 5, "observe")}); err != nil {
			return err
		}
		return AddReqStats(tx, []ReqStat{{Bucket: now / 60000, Vhost: "a.com", Requests: 10, Hits: 2}, {Bucket: now / 60000, Vhost: "b.com", Requests: 5, Hits: 1}})
	})
	s.Do(func(tx *sql.Tx) error {
		return AddReqStats(tx, []ReqStat{{Bucket: now / 60000, Vhost: "a.com", Requests: 5, Hits: 0}})
	}) // additif
	s.Flush()
	st, err := s.QueryStats(context.Background(), now-3600000, now, 5)
	if err != nil {
		t.Fatal(err)
	}
	if st.Requests != 20 || st.HitRequests != 3 || st.IPs != 2 {
		t.Fatalf("%+v", st)
	}
	if len(st.TopRules) != 2 || st.TopRules[0].ID != 942100 || st.TopRules[0].Count != 2 || st.TopRules[0].Msg != "m" {
		t.Fatalf("topRules %+v", st.TopRules)
	}
	if st.TopIPs[0].IP != "1.1.1.1" || st.TopIPs[0].Hits != 2 {
		t.Fatalf("topIps %+v", st.TopIPs)
	}
	if st.TopVhosts[0].Vhost != "a.com" || st.TopVhosts[0].Requests != 15 {
		t.Fatalf("topVhosts %+v", st.TopVhosts)
	}
	if len(st.ByCategory) != 1 || st.ByCategory[0].Count != 3 {
		t.Fatalf("categories %+v", st.ByCategory)
	}
	if len(st.Timeline) < 12 {
		t.Fatalf("serie: %d", len(st.Timeline))
	}
	tot := 0
	for _, p := range st.Timeline {
		tot += p.Requests
	}
	if tot != 20 {
		t.Fatalf("serie: total %d", tot)
	}
	if got := s.RuleHits(context.Background(), now-1000000)[942100]; got != 2 {
		t.Fatalf("hits7d: %d", got)
	}
	if s.HitsByVhost(context.Background(), now-3600000)["a.com"] != 2 {
		t.Fatal("hits par vhost")
	}
}

func TestAlertsListsOffsets(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i := int64(1); i <= 3; i++ {
		ev, _ := json.Marshal(map[string]any{"score": 10 * i})
		a := AlertRow{ID: i, TS: 1000 + i, Severity: "low", IP: "1.1.1.1", Vhost: "a.com", Evidence: ev}
		s.Do(func(tx *sql.Tx) error { return InsertAlert(tx, a) })
	}
	s.Flush()
	if s.MaxAlertID(ctx) != 3 {
		t.Fatal("MaxAlertID")
	}
	rows, _ := s.QueryAlerts(ctx, 1, 0, true, 10)
	if len(rows) != 2 || rows[0].ID != 2 {
		t.Fatalf("asc sinceId: %+v", rows)
	}
	rows, _ = s.QueryAlerts(ctx, 0, 3, false, 10)
	if len(rows) != 2 || rows[0].ID != 2 || rows[1].ID != 1 {
		t.Fatalf("desc beforeId: %+v", rows)
	}
	if err := s.AckAlerts([]int64{2}); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.QueryAlerts(ctx, 0, 0, true, 10)
	if rows[0].Ack || !rows[1].Ack {
		t.Fatalf("ack: %+v", rows)
	}

	now := time.Now().UnixMilli()
	s.DoSync(func(tx *sql.Tx) error {
		if err := UpsertListed(tx, ListedRow{IP: "1.1.1.1", List: "block", Score: 30, Hits: 3, Since: now, Until: now + 10000, Vhosts: []string{"a.com"}, TopRules: []int{942100}}); err != nil {
			return err
		}
		if err := UpsertListed(tx, ListedRow{IP: "2.2.2.2", List: "challenge", Score: 12, Hits: 2, Since: now, Until: now - 1, Vhosts: []string{}, TopRules: []int{}}); err != nil {
			return err
		}
		return SetGrace(tx, "3.3.3.3", now+5000)
	})
	ls := s.LoadListed(ctx, now)
	if len(ls) != 1 || ls[0].IP != "1.1.1.1" || ls[0].TopRules[0] != 942100 {
		t.Fatalf("listes: %+v", ls)
	}
	if g := s.LoadGrace(ctx, now); g["3.3.3.3"] == 0 {
		t.Fatal("grace")
	}
	s.DoSync(func(tx *sql.Tx) error { return DeleteListed(tx, "1.1.1.1", "") })
	if len(s.LoadListed(ctx, now)) != 0 {
		t.Fatal("DeleteListed")
	}

	o := NewOffsets(nil, false)
	if _, _, _, ok := o.GetOffset("f"); ok {
		t.Fatal("offset inconnu")
	}
	o.SetOffset("f", 12, 345, "combined")
	o.SetOffset("f", 12, 345, "combined") // pas de re-ecriture
	d := o.TakeDirty()
	if len(d) != 1 || o.TakeDirty() != nil {
		t.Fatal("dirty")
	}
	s.DoSync(func(tx *sql.Tx) error { return SaveOffsets(tx, d) })
	if r := s.LoadOffsets(ctx)["f"]; r.Inode != 12 || r.Offset != 345 || r.Format != "combined" {
		t.Fatalf("offsets: %+v", r)
	}
	if _, _, _, ok := NewOffsets(nil, true).GetOffset("nouveau"); !ok {
		t.Fatal("fromStart")
	}
	s.DoSync(func(tx *sql.Tx) error {
		return SaveVhosts(tx, []VhostRow{{Name: "a.com", Lines: 5, LastSeen: now, Format: "vhost"}})
	})
	if v := s.LoadVhosts(ctx); len(v) != 1 || v[0].Lines != 5 {
		t.Fatalf("vhosts: %+v", v)
	}
}

func TestPurge(t *testing.T) {
	s := open(t)
	now := time.Now().UnixMilli()
	old := now - 40*24*3600000
	s.Do(func(tx *sql.Tx) error {
		if err := InsertHits(tx, []Hit{mkHit(old, "1.1.1.1", "a.com", 942100, 5, "observe"), mkHit(now, "2.2.2.2", "a.com", 942100, 5, "observe")}); err != nil {
			return err
		}
		ev, _ := json.Marshal(map[string]any{})
		if err := InsertAlert(tx, AlertRow{ID: 1, TS: old, Severity: "low", IP: "x", Vhost: "v", Evidence: ev}); err != nil {
			return err
		}
		return InsertAlert(tx, AlertRow{ID: 2, TS: now, Severity: "low", IP: "x", Vhost: "v", Evidence: ev})
	})
	s.Purge(now, 30, 90)
	s.Flush()
	tot, _, _ := s.QueryHits(context.Background(), HitFilter{Limit: 10})
	if tot != 1 {
		t.Fatalf("hits apres purge: %d", tot)
	}
	rows, _ := s.QueryAlerts(context.Background(), 0, 0, true, 10)
	if len(rows) != 2 { // alerte de 40 j conservee (retention 90 j)
		t.Fatalf("alertes: %d", len(rows))
	}
	if r := s.scalar(context.Background(), `SELECT COUNT(*) FROM waf_hit_rules`); r != 1 {
		t.Fatalf("hit_rules: %d", r)
	}
}

func TestBatchingDoesNotBlockAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	for i := 0; i < 5000; i++ {
		h := mkHit(int64(i), "1.1.1.1", "a.com", 942100, 5, "observe")
		if !s.Do(func(tx *sql.Tx) error { return InsertHits(tx, []Hit{h}) }) {
			t.Fatal("file saturee")
		}
	}
	if time.Since(t0) > 2*time.Second {
		t.Fatalf("Do bloque : %v", time.Since(t0))
	}
	s.Close() // vide la file
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	tot, _, _ := s2.QueryHits(context.Background(), HitFilter{Limit: 1})
	if tot != 5000 {
		t.Fatalf("persistance: %d", tot)
	}
}

func TestDisabledStore(t *testing.T) {
	s := Disabled()
	if s.OK() || s.Do(func(*sql.Tx) error { return nil }) {
		t.Fatal("store desactive")
	}
	s.Flush()
	if s.MaxAlertID(context.Background()) != 0 {
		t.Fatal("lecture")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
