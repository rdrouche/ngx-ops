package service

import (
	"encoding/json"
	"testing"

	"nginx-analyzer-go/internal/waf/store"
	"nginx-analyzer-go/internal/wire"
)

func TestHitEventMapping(t *testing.T) {
	h := store.Hit{TS: 1762711200000, Vhost: "a.example", IP: "203.0.113.5", Method: "GET",
		URI: "/search?q=<script>", Status: 200, UA: "curl/8", Score: 8, Mode: "detect", PossiblySucceeded: true,
		Rules: []store.HitRule{{ID: 942100, Score: 5, Category: "sqli"}, {ID: 941100, Score: 3, Category: "xss"}}}
	ev := hitEvent(h)
	if ev.Source != wire.SourceWAF || ev.Action != wire.ActionLogged || ev.Site != "a.example" ||
		ev.Path != "/search" || ev.Query != "q=<script>" || ev.Rule != "942100" || ev.Status != 200 {
		t.Fatalf("événement inattendu : %+v", ev)
	}
	if !wire.ValidSource(ev.Source) || !wire.ValidAction(ev.Action) {
		t.Fatal("source ou action invalide pour le log store")
	}
	if ev.Extra["score"] != 8 || ev.Extra["possibly_succeeded"] != true {
		t.Fatalf("extra = %v", ev.Extra)
	}
	b, _ := json.Marshal(ev.Extra)
	if len(b) > 4096 {
		t.Fatalf("extra trop gros : %d", len(b))
	}
}

func TestHitEventExtraIsBounded(t *testing.T) {
	var rules []store.HitRule
	for i := 0; i < 500; i++ {
		rules = append(rules, store.HitRule{ID: 900000 + i, Score: 1, Category: "x"})
	}
	ev := hitEvent(store.Hit{TS: 1, IP: "198.51.100.1", Rules: rules})
	if n := len(ev.Extra["rules"].([]int)); n != maxExtraRules {
		t.Fatalf("règles = %d", n)
	}
	b, _ := json.Marshal(ev.Extra)
	if len(b) > 4096 {
		t.Fatalf("extra = %d octets", len(b))
	}
}

type sink struct{ evs []wire.Event }

func (s *sink) Emit(e wire.Event) { s.evs = append(s.evs, e) }

func TestEmitHitNilIsNoop(t *testing.T) {
	(&Service{}).emitHit(store.Hit{}) // Decisions nil : ne doit pas paniquer
	s := &Service{cfg: Config{Decisions: &sink{}}}
	s.emitHit(store.Hit{TS: 1, IP: "198.51.100.1"})
	if len(s.cfg.Decisions.(*sink).evs) != 1 {
		t.Fatal("hit non émis")
	}
}
