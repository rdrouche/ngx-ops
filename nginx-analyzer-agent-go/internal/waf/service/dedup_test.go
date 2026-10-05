package service

import (
	"testing"
	"time"

	"nginx-analyzer-go/internal/waf/logsource"
)

func mkEntry(json bool, ip, uri string, ts int64) *logsource.Entry {
	return &logsource.Entry{IP: ip, Method: "GET", URI: uri, Status: 404, TS: ts, WafJSON: json}
}

func TestDedupInactiveWithoutJSON(t *testing.T) {
	d := newDedup()
	if !d.admit(mkEntry(false, "1.1.1.1", "/a", 1000), time.Now()) {
		t.Fatal("sans journal waf_json suivi, une ligne combined doit passer tout de suite")
	}
}

func TestDedupCombinedThenJSON(t *testing.T) {
	d := newDedup()
	d.jsonActive.Store(true)
	now := time.Now()
	if d.admit(mkEntry(false, "1.1.1.1", "/a", 5000), now) {
		t.Fatal("la combined doit etre retenue")
	}
	if !d.admit(mkEntry(true, "1.1.1.1", "/a", 5200), now) { // meme seconde
		t.Fatal("la waf_json doit toujours passer")
	}
	if got := d.flush(now.Add(5 * time.Second)); len(got) != 0 {
		t.Fatalf("la combined jumelle aurait du etre supprimee, %d restantes", len(got))
	}
	if d.skipped.Load() != 1 {
		t.Fatalf("skipped = %d", d.skipped.Load())
	}
}

func TestDedupJSONThenCombined(t *testing.T) {
	d := newDedup()
	d.jsonActive.Store(true)
	now := time.Now()
	d.admit(mkEntry(true, "1.1.1.1", "/a", 5000), now)
	if d.admit(mkEntry(false, "1.1.1.1", "/a", 5000), now) {
		t.Fatal("combined jumelle d'une waf_json deja vue : ecartee")
	}
	if len(d.flush(now.Add(5*time.Second))) != 0 || d.skipped.Load() != 1 {
		t.Fatal("rien ne doit etre analyse en double")
	}
}

func TestDedupLonelyCombinedReleased(t *testing.T) {
	d := newDedup()
	d.jsonActive.Store(true) // un vhost sans journal waf_json : sa combined est analysee apres la retenue
	now := time.Now()
	d.admit(mkEntry(false, "2.2.2.2", "/b", 9000), now)
	if len(d.flush(now.Add(time.Second))) != 0 {
		t.Fatal("trop tot : encore retenue")
	}
	if got := d.flush(now.Add(dedupHold + time.Second)); len(got) != 1 {
		t.Fatalf("la combined sans jumelle doit etre liberee, got %d", len(got))
	}
}

func TestDedupRepeatedIdenticalRequestsKeepCounts(t *testing.T) {
	d := newDedup()
	d.jsonActive.Store(true)
	now := time.Now()
	for i := 0; i < 3; i++ {
		d.admit(mkEntry(false, "3.3.3.3", "/c", 7000), now)
	}
	d.admit(mkEntry(true, "3.3.3.3", "/c", 7000), now) // une seule jumelle
	got := d.flush(now.Add(dedupHold + time.Second))
	if len(got) != 2 {
		t.Fatalf("3 combined + 1 json : 2 combined doivent rester, got %d", len(got))
	}
}
