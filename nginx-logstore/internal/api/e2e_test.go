package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ngxops/logstore/pkg/logsink"
	"ngxops/logstore/pkg/wire"
)

func eventsCount(e *env) int {
	_, m := e.get("/v1/events?limit=500&since=2h", e.read)
	if m == nil {
		return -1
	}
	return len(m["events"].([]any))
}

// Producteur réel (logsink) -> API réelle -> PostgreSQL réel.
func TestEndToEndSinkToStore(t *testing.T) {
	e := newEnv(t, nil)
	sink, err := logsink.New(logsink.Config{
		URL: e.ts.URL, Token: e.write, InstanceName: "web1", SpoolDir: t.TempDir(), AllowInsecure: true,
		FlushInterval: 20 * time.Millisecond, PollInterval: 10 * time.Millisecond, MinBackoff: 20 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sink.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	for i := 0; i < 250; i++ {
		sink.Emit(wire.Event{TS: time.Now().Add(-time.Duration(i) * time.Second), Source: "access", Action: "allowed", Site: "a.example",
			IP: "198.51.100.9", Method: "GET", Path: "/p", Query: "a=b", Status: 200, Bytes: 10, UA: "ua", Referer: "https://r.example/x"})
	}
	deadline := time.Now().Add(5 * time.Second)
	for sink.Stats().EventsSent < 250 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if st := sink.Stats(); st.EventsSent != 250 || st.Rejected != 0 {
		t.Fatalf("stats producteur: %+v", st)
	}
	_, m := e.get("/v1/instances", e.read)
	if m["instances"].([]any)[0].(map[string]any)["events_total"].(float64) != 250 {
		t.Fatalf("instances: %v", m)
	}
	_, m = e.get("/v1/events?limit=1&since=2h", e.read)
	ev := m["events"].([]any)[0].(map[string]any)
	if !strings.HasSuffix(ev["ts"].(string), "Z") {
		t.Fatalf("les dates doivent être en UTC: %v", ev["ts"])
	}
	if ev["referer_host"] != "r.example" || ev["query_hash"] == nil || ev["ip"] != "198.51.100.9" {
		t.Fatalf("événement stocké: %v", ev)
	}
}

// Réponse perdue APRÈS l'écriture côté serveur : le rejeu ne doit rien dupliquer.
func TestEndToEndLostResponseNoDuplicates(t *testing.T) {
	e := newEnv(t, nil)

	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest(r.Method, e.ts.URL+r.URL.Path, r.Body)
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		if calls.Add(1) == 1 {
			w.WriteHeader(503) // le serveur a écrit, mais le producteur ne le saura pas
			return
		}
		w.WriteHeader(resp.StatusCode)
		b, _ := io.ReadAll(resp.Body)
		_, _ = w.Write(b)
	}))
	defer proxy.Close()

	sink, err := logsink.New(logsink.Config{
		URL: proxy.URL, Token: e.write, SpoolDir: t.TempDir(), AllowInsecure: true,
		FlushInterval: 20 * time.Millisecond, PollInterval: 10 * time.Millisecond, MinBackoff: 20 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sink.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	for i := 0; i < 10; i++ {
		sink.Emit(wire.Event{TS: time.Now(), Source: "access", Action: "allowed", Site: "a.example", Status: 200})
	}
	deadline := time.Now().Add(5 * time.Second)
	for sink.Stats().BatchesSent < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatalf("un rejeu était attendu (%d appel(s))", calls.Load())
	}
	if n := eventsCount(e); n != 10 {
		t.Fatalf("attendu 10 événements (aucun doublon), obtenu %d", n)
	}
	_ = json.Valid
}
