package shipper

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"nginx-analyzer-go/internal/wire"
)

func TestListLookupURLValidation(t *testing.T) {
	if l, err := NewListLookup("", ""); l != nil || err != nil {
		t.Fatalf("URL vide = désactivé : %v %v", l, err)
	}
	for _, bad := range []string{"ftp://a", "http://exemple.org:9", "http://u:p@analyzer:3000", "http://analyzer:3000/x", "::"} {
		if _, err := NewListLookup(bad, "t"); err == nil {
			t.Errorf("%q devrait être refusée", bad)
		}
	}
	for _, ok := range []string{"http://analyzer:3000", "http://127.0.0.1:3000", "http://10.0.0.5:3000", "https://analyzer.exemple.org"} {
		if _, err := NewListLookup(ok, "t"); err != nil {
			t.Errorf("%q devrait être acceptée : %v", ok, err)
		}
	}
}

func TestListLookupCacheTokenAndApply(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Analyzer-Token") != "secret" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Query().Get("ip") {
		case "198.51.100.5":
			_, _ = w.Write([]byte(`{"sources":["spamhaus","abuse"],"synced":true}`))
		default:
			_, _ = w.Write([]byte(`{"sources":[],"synced":true}`))
		}
	}))
	defer srv.Close()
	l, err := NewListLookup(srv.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	ev := wire.Event{IP: "198.51.100.5", Source: wire.SourceBlocklist}
	l.Apply(&ev)
	if ev.Rule != "spamhaus" || len(ev.Extra["lists"].([]string)) != 2 {
		t.Fatalf("attribution inattendue : %+v", ev)
	}
	l.Apply(&ev)
	l.Names("203.0.113.1")
	l.Names("203.0.113.1")
	if n := calls.Load(); n != 2 {
		t.Fatalf("cache : %d appels au lieu de 2", n)
	}
	none := wire.Event{IP: "203.0.113.1"}
	l.Apply(&none)
	if none.Rule != "" || none.Extra != nil {
		t.Fatalf("IP inconnue : %+v", none)
	}
}

func TestListLookupNeverBlocksAndCoolsDown(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer srv.Close()
	l, _ := NewListLookup(srv.URL, "x")
	now := time.Now()
	l.now = func() time.Time { return now }
	if l.Names("198.51.100.5") != nil || l.Names("198.51.100.6") != nil {
		t.Fatal("échec = aucune liste")
	}
	if calls.Load() != 1 {
		t.Fatalf("coupe-circuit : %d appels", calls.Load())
	}
	now = now.Add(lookupCooldown + time.Second)
	l.Names("198.51.100.7")
	if calls.Load() != 2 {
		t.Fatalf("reprise après délai : %d appels", calls.Load())
	}
	var nilL *ListLookup
	if nilL.Names("1.2.3.4") != nil {
		t.Fatal("nil-safe")
	}
	nilL.Apply(&wire.Event{IP: "1.2.3.4"})
}
