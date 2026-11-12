package model

import (
	"strings"
	"testing"
	"time"

	"ngxops/logstore/internal/ipmode"
	"ngxops/logstore/pkg/wire"
)

var now = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func params(mode ipmode.Mode) Params {
	return Params{Now: now, MaxAge: 30 * 24 * time.Hour, Mode: mode, T: ipmode.New(strings.Repeat("k", 32))}
}

func valid() wire.Event {
	return wire.Event{TS: now.Add(-time.Minute), Source: "access", Action: "allowed", Site: "Example.COM", IP: "198.51.100.4",
		Method: "get", Path: "/a", Query: "token=secret", Status: 200, Bytes: 12, UA: "ua", Referer: "https://Ref.Example/x?y=1", Country: "fr"}
}

func TestNormalizeOK(t *testing.T) {
	r, err := Normalize(valid(), params(ipmode.Clear))
	if err != nil {
		t.Fatal(err)
	}
	if *r.Site != "example.com" || *r.Method != "GET" || *r.Country != "FR" || *r.RefererHost != "ref.example" {
		t.Fatalf("normalisation: %+v", r)
	}
	if r.QueryHash == nil || strings.Contains(*r.QueryHash, "secret") || len(*r.QueryHash) != 16 {
		t.Fatalf("la query ne doit être conservée que sous forme d'empreinte: %v", r.QueryHash)
	}
}

func TestNormalizeRejects(t *testing.T) {
	cases := map[string]func(*wire.Event){
		"bad_ts":       func(e *wire.Event) { e.TS = time.Time{} },
		"ts_in_future": func(e *wire.Event) { e.TS = now.Add(time.Hour) },
		"too_old":      func(e *wire.Event) { e.TS = now.Add(-40 * 24 * time.Hour) },
		"bad_source":   func(e *wire.Event) { e.Source = "x" },
		"bad_action":   func(e *wire.Event) { e.Action = "x" },
		"bad_method":   func(e *wire.Event) { e.Method = "GET /;drop" },
		"bad_status":   func(e *wire.Event) { e.Status = 999 },
		"bad_bytes":    func(e *wire.Event) { e.Bytes = -1 },
		"bad_country":  func(e *wire.Event) { e.Country = "FRA" },
		"bad_ip":       func(e *wire.Event) { e.IP = "zzz" },
		"extra_too_large": func(e *wire.Event) {
			e.Extra = map[string]any{"k": strings.Repeat("x", MaxExtra+1)}
		},
	}
	for want, mut := range cases {
		e := valid()
		mut(&e)
		if _, err := Normalize(e, params(ipmode.Clear)); err == nil || err.Error() != want {
			t.Errorf("%s: obtenu %v", want, err)
		}
	}
}

func TestNormalizeSanitizes(t *testing.T) {
	e := valid()
	e.Path = "/a\r\nX-Injected: 1\x00" + strings.Repeat("é", MaxPath)
	e.UA = "bad\x1b[31mUA\xff"
	r, err := Normalize(e, params(ipmode.Clear))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(*r.Path, "\r\n\x00") || len(*r.Path) > MaxPath {
		t.Fatalf("chemin mal nettoyé (%d octets)", len(*r.Path))
	}
	if strings.ContainsRune(*r.UA, 0x1b) {
		t.Fatalf("UA: %q", *r.UA)
	}
}

func TestNormalizeIPModes(t *testing.T) {
	r, _ := Normalize(valid(), params(ipmode.Pseudonymized))
	if r.IP != nil || r.IPKey == nil {
		t.Fatalf("pseudonymized: %+v", r)
	}
	if _, err := Normalize(valid(), Params{Now: now, Mode: ipmode.Pseudonymized, T: ipmode.New("")}); err == nil || err.Error() != "ip_mode_unavailable" {
		t.Fatalf("sans clé: %v", err)
	}
}
