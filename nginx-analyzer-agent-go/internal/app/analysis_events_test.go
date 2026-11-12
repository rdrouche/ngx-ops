package app

import (
	"strings"
	"testing"

	"nginx-analyzer-go/internal/store"
	"nginx-analyzer-go/internal/wire"
)

func TestAlertEvent(t *testing.T) {
	long := strings.Repeat("é", 500)
	ev := AlertEvent(store.Alert{
		ID: 7, Ts: 1_762_900_000_000, Type: "bruteforce", Severity: "high", IP: "203.0.113.9", Vhost: "a.example", Summary: long,
		Evidence: map[string]any{"authFailures": 21, "distinctPaths": 3, "samples": []any{"GET /secret"}, "ruleName": "x", "country": "FR", "nested": map[string]any{"a": 1}},
	})
	if ev.Source != wire.SourceAnalysis || ev.Action != wire.ActionLogged || ev.Rule != "bruteforce" || ev.IP != "203.0.113.9" || ev.Site != "a.example" {
		t.Fatalf("événement inattendu : %+v", ev)
	}
	if ev.TS.IsZero() || ev.TS.Year() < 2025 {
		t.Fatalf("horodatage : %v", ev.TS)
	}
	if s := ev.Extra["summary"].(string); len([]rune(s)) != analysisSummaryMax {
		t.Fatalf("résumé non borné : %d", len([]rune(s)))
	}
	if ev.Extra["severity"] != "high" || ev.Extra["authFailures"] != 21 || ev.Extra["country"] != "FR" || ev.Extra["alert_id"] != int64(7) {
		t.Fatalf("extra : %v", ev.Extra)
	}
	for _, k := range []string{"samples", "nested"} {
		if _, ok := ev.Extra[k]; ok {
			t.Fatalf("%s ne doit pas être expédié", k)
		}
	}
	if !wire.ValidSource(ev.Source) {
		t.Fatal("source inconnue du contrat")
	}
}

func TestAlertEventCustomRuleAndNoEvidence(t *testing.T) {
	ev := AlertEvent(store.Alert{Type: "custom_4", Severity: "low", Evidence: map[string]any{"ruleName": "wp-probe", "matches": 12}})
	if ev.Rule != "custom:wp-probe" || ev.Extra["matches"] != 12 {
		t.Fatalf("règle perso : %+v", ev)
	}
	ev = AlertEvent(store.Alert{Type: "volumetric", Severity: "medium"})
	if ev.Rule != "volumetric" || ev.IP != "" || ev.TS.IsZero() {
		t.Fatalf("sans preuve : %+v", ev)
	}
}

func TestStoreAlertHook(t *testing.T) {
	s := store.New("")
	var got []store.Alert
	s.SetAlertHook(func(a store.Alert) { got = append(got, a) })
	s.AddAlert(store.AlertInput{Type: "scan", Severity: "medium", Summary: "x", Evidence: map[string]any{"ip": "198.51.100.2", "vhost": "b.example"}})
	if len(got) != 1 || got[0].IP != "198.51.100.2" || got[0].Vhost != "b.example" || got[0].ID == 0 {
		t.Fatalf("hook : %+v", got)
	}
}
