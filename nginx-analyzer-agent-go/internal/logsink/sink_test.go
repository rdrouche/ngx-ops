package logsink

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"nginx-analyzer-go/internal/wire"
)

const tok = "lgs_test_token_do_not_log"

type call struct {
	key    string
	lines  []string
	auth   string
	gz     string
	inst   string
	status int
}

// fake est un log store minimal : le statut renvoyé est piloté par le test.
type fake struct {
	mu     sync.Mutex
	calls  []call
	handle func(n int, c call, w http.ResponseWriter) // n = rang de l'appel (0..)
	srv    *httptest.Server
}

func newFake(t *testing.T, h func(n int, c call, w http.ResponseWriter)) *fake {
	f := &fake{handle: h}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rd io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			rd = zr
		}
		var lines []string
		sc := bufio.NewScanner(rd)
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" {
				lines = append(lines, l)
			}
		}
		c := call{key: r.Header.Get(wire.HeaderIdempotencyKey), lines: lines, auth: r.Header.Get("Authorization"),
			gz: r.Header.Get("Content-Encoding"), inst: r.Header.Get(wire.HeaderInstanceName)}
		f.mu.Lock()
		n := len(f.calls)
		f.calls = append(f.calls, c)
		f.mu.Unlock()
		f.handle(n, c, w)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) snapshot() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

func ok(w http.ResponseWriter, c call) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wire.Result{Accepted: len(c.lines)})
}

func cfgFor(t *testing.T, url string) Config {
	return Config{URL: url, Token: tok, InstanceName: "web1", SpoolDir: t.TempDir(), AllowInsecure: true,
		BatchSize: 100, FlushInterval: 20 * time.Millisecond, PollInterval: 10 * time.Millisecond,
		MinBackoff: 20 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func start(t *testing.T, cfg Config) (*Sink, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	s, err := New(cfg)
	if err != nil || s == nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return s, cancel, done
}

func emit(s *Sink, n int) {
	for i := 0; i < n; i++ {
		s.Emit(wire.Event{TS: time.Now(), Source: "access", Action: "allowed", Site: "a.example", IP: "198.51.100.1", Path: "/", Status: 200})
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("délai dépassé : %s", what)
}

func spoolCount(c Config) int {
	m, _ := filepath.Glob(filepath.Join(c.SpoolDir, "*"+spoolExt))
	return len(m)
}

func TestDisabledIsNoop(t *testing.T) {
	s, err := New(Config{})
	if s != nil || err != nil {
		t.Fatalf("désactivé attendu: %v %v", s, err)
	}
	s.Emit(wire.Event{})        // ne doit pas paniquer
	s.Run(context.Background()) // rend la main immédiatement
	if (s.Stats() != Stats{}) {
		t.Fatal("stats vides")
	}
}

func TestConfigValidation(t *testing.T) {
	d := t.TempDir()
	bad := []Config{
		{URL: "http://x", Token: tok, SpoolDir: d},                     // http sans AllowInsecure
		{URL: "https://u:p@x", Token: tok, SpoolDir: d},                // identifiants dans l'URL
		{URL: "ftp://x", Token: tok, SpoolDir: d, AllowInsecure: true}, // schéma
		{URL: "https://x", SpoolDir: d},                                // sans jeton
		{URL: "https://x", Token: tok},                                 // sans tampon
		{URL: "https://", Token: tok, SpoolDir: d},                     // sans hôte
	}
	for i, c := range bad {
		if s, err := New(c); err == nil || s != nil {
			t.Errorf("cas %d accepté: %+v", i, c)
		}
	}
	if _, err := New(Config{URL: "https://x", Token: tok, SpoolDir: d}); err != nil {
		t.Fatalf("https valide refusé: %v", err)
	}
}

func TestHappyPath(t *testing.T) {
	f := newFake(t, func(_ int, c call, w http.ResponseWriter) { ok(w, c) })
	cfg := cfgFor(t, f.srv.URL)
	s, _, _ := start(t, cfg)
	emit(s, 5)
	waitFor(t, "5 événements livrés", func() bool { return s.Stats().EventsSent == 5 })

	c := f.snapshot()[0]
	if c.auth != "Bearer "+tok || c.gz != "gzip" || c.inst != "web1" || len(c.lines) != 5 {
		t.Fatalf("requête inattendue: %+v", c)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`).MatchString(c.key) {
		t.Fatalf("Idempotency-Key invalide: %q", c.key)
	}
	var ev wire.Event
	if err := json.Unmarshal([]byte(c.lines[0]), &ev); err != nil || ev.Site != "a.example" {
		t.Fatalf("ligne illisible: %v", err)
	}
	waitFor(t, "tampon vidé", func() bool { return spoolCount(cfg) == 0 })
}

func TestRetryKeepsSameIdempotencyKey(t *testing.T) {
	f := newFake(t, func(n int, c call, w http.ResponseWriter) {
		if n < 2 {
			w.WriteHeader(503)
			return
		}
		ok(w, c)
	})
	cfg := cfgFor(t, f.srv.URL)
	s, _, _ := start(t, cfg)
	emit(s, 3)
	waitFor(t, "livraison après 2 échecs", func() bool { return s.Stats().EventsSent == 3 })

	calls := f.snapshot()
	if len(calls) != 3 || calls[0].key != calls[1].key || calls[1].key != calls[2].key {
		t.Fatalf("le lot doit être rejoué avec la même clé: %+v", calls)
	}
	if spoolCount(cfg) != 0 {
		t.Fatal("tampon à vider après succès")
	}
}

func TestRetryAfterIsHonored(t *testing.T) {
	var first time.Time
	f := newFake(t, func(n int, c call, w http.ResponseWriter) {
		if n == 0 {
			first = time.Now()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		if d := time.Since(first); d < 900*time.Millisecond {
			t.Errorf("reprise trop tôt malgré Retry-After: %s", d)
		}
		ok(w, c)
	})
	s, _, _ := start(t, cfgFor(t, f.srv.URL))
	emit(s, 1)
	waitFor(t, "livraison après 429", func() bool { return s.Stats().EventsSent == 1 })
}

func TestUnauthorizedSuspendsAndKeepsData(t *testing.T) {
	f := newFake(t, func(_ int, _ call, w http.ResponseWriter) { w.WriteHeader(401) })
	cfg := cfgFor(t, f.srv.URL)
	s, _, _ := start(t, cfg)
	emit(s, 2)
	waitFor(t, "suspension", func() bool { return s.Stats().Suspended })
	time.Sleep(150 * time.Millisecond)
	if n := len(f.snapshot()); n != 1 {
		t.Fatalf("pas de martèlement après 401: %d appels", n)
	}
	if spoolCount(cfg) != 1 {
		t.Fatal("les données doivent rester sur disque pendant la suspension")
	}
}

func TestSplitOn413(t *testing.T) {
	f := newFake(t, func(_ int, c call, w http.ResponseWriter) {
		if len(c.lines) > 2 {
			w.WriteHeader(413)
			return
		}
		ok(w, c)
	})
	cfg := cfgFor(t, f.srv.URL)
	s, _, _ := start(t, cfg)
	emit(s, 6)
	waitFor(t, "6 événements livrés malgré 413", func() bool { return s.Stats().EventsSent == 6 })

	keys := map[string]bool{}
	for _, c := range f.snapshot() {
		if len(c.lines) <= 2 {
			if keys[c.key] {
				t.Fatalf("clé réutilisée pour deux lots différents: %s", c.key)
			}
			keys[c.key] = true
		}
	}
	if spoolCount(cfg) != 0 {
		t.Fatal("tampon à vider")
	}
}

func TestOther4xxDropsBatch(t *testing.T) {
	f := newFake(t, func(_ int, _ call, w http.ResponseWriter) { w.WriteHeader(400) })
	cfg := cfgFor(t, f.srv.URL)
	s, _, _ := start(t, cfg)
	emit(s, 1)
	waitFor(t, "lot abandonné", func() bool { return s.Stats().SpoolDropped == 1 && spoolCount(cfg) == 0 })
	if n := len(f.snapshot()); n != 1 {
		t.Fatalf("pas de rejeu d'un lot invalide: %d", n)
	}
}

func TestRedirectIsNeverFollowed(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
		w.WriteHeader(200)
	}))
	defer other.Close()
	f := newFake(t, func(_ int, _ call, w http.ResponseWriter) {
		w.Header().Set("Location", other.URL+"/steal")
		w.WriteHeader(307)
	})
	cfg := cfgFor(t, f.srv.URL)
	s, _, _ := start(t, cfg)
	emit(s, 1)
	waitFor(t, "redirection constatée", func() bool { return len(f.snapshot()) >= 1 })
	time.Sleep(100 * time.Millisecond)
	if leaked {
		t.Fatal("le jeton a été envoyé à l'hôte de redirection")
	}
	if spoolCount(cfg) != 1 {
		t.Fatal("données conservées en attente de correction de l'URL")
	}
}

func TestSpoolSurvivesRestart(t *testing.T) {
	cfg := cfgFor(t, "http://127.0.0.1:1") // injoignable
	s1, cancel, done := start(t, cfg)
	emit(s1, 4)
	waitFor(t, "lot écrit sur disque", func() bool { return spoolCount(cfg) == 1 })
	cancel()
	<-done

	f := newFake(t, func(_ int, c call, w http.ResponseWriter) { ok(w, c) })
	cfg.URL = f.srv.URL
	s2, _, _ := start(t, cfg)
	waitFor(t, "lot repris après redémarrage", func() bool { return s2.Stats().EventsSent == 4 })
}

func TestShutdownFlushesMemoryToDisk(t *testing.T) {
	cfg := cfgFor(t, "http://127.0.0.1:1")
	cfg.FlushInterval = time.Hour // rien n'est écrit tant qu'on n'arrête pas
	cfg.BatchSize = 1000
	s, cancel, done := start(t, cfg)
	emit(s, 7)
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if spoolCount(cfg) != 1 {
		t.Fatalf("les événements en mémoire doivent être écrits à l'arrêt: %d fichier(s)", spoolCount(cfg))
	}
}

func TestSpoolCapDropsOldest(t *testing.T) {
	cfg := cfgFor(t, "http://127.0.0.1:1")
	cfg.SpoolMaxBytes = 600
	cfg.BatchSize = 20
	s, _, _ := start(t, cfg)
	for i := 0; i < 10; i++ {
		emit(s, 20)
		time.Sleep(15 * time.Millisecond)
	}
	waitFor(t, "plafond respecté", func() bool {
		st := s.Stats()
		return st.SpoolDropped > 0 && st.SpoolBytes <= 600
	})
}

func TestQueueFullDropsAndCounts(t *testing.T) {
	cfg := cfgFor(t, "http://127.0.0.1:1")
	cfg.QueueSize = 2
	s, err := New(cfg) // pas de Run : la file se remplit
	if err != nil {
		t.Fatal(err)
	}
	emit(s, 5)
	if st := s.Stats(); st.Emitted != 2 || st.QueueDropped != 3 {
		t.Fatalf("%+v", st)
	}
}

// syncBuf : tampon de journal sûr entre goroutines (le test le lit pendant que le client écrit).
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestTokenNeverLogged(t *testing.T) {
	var logs syncBuf
	f := newFake(t, func(_ int, _ call, w http.ResponseWriter) { w.WriteHeader(401) })
	cfg := cfgFor(t, f.srv.URL)
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	s, _, _ := start(t, cfg)
	emit(s, 1)
	waitFor(t, "suspension", func() bool { return s.Stats().Suspended })
	if strings.Contains(logs.String(), tok) {
		t.Fatalf("le jeton apparaît dans les journaux: %s", logs.String())
	}
	_ = os.Stdout
}

func evs(n int) []wire.Event {
	out := make([]wire.Event, n)
	for i := range out {
		out[i] = wire.Event{TS: time.Now(), Source: "access", Action: "allowed", Site: "a.example", IP: "198.51.100.1", Path: "/", Status: 200}
	}
	return out
}

func newSink(t *testing.T, cfg Config) *Sink {
	t.Helper()
	s, err := New(cfg)
	if err != nil || s == nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestCommitIsDurableAndCarriesMeta(t *testing.T) {
	cfg := cfgFor(t, "http://127.0.0.1:1")
	s := newSink(t, cfg) // pas de Run : rien n'est envoyé
	if err := s.Commit(evs(3), `{"file":"a.log","off":123}`); err != nil {
		t.Fatal(err)
	}
	if spoolCount(cfg) != 1 {
		t.Fatalf("spool = %d, attendu 1", spoolCount(cfg))
	}
	// une nouvelle instance (redémarrage) relit la meta
	s2 := newSink(t, cfg)
	m := s2.PendingMeta()
	if len(m) != 1 || m[0] != `{"file":"a.log","off":123}` {
		t.Fatalf("meta = %v", m)
	}
}

func TestCommitRejectsMultilineMeta(t *testing.T) {
	s := newSink(t, cfgFor(t, "http://127.0.0.1:1"))
	if err := s.Commit(evs(1), "a\nb"); err == nil {
		t.Fatal("meta multiligne acceptée")
	}
}

func TestCommitUnitIsSentInSubBatchesWithDeterministicKeys(t *testing.T) {
	f := newFake(t, func(_ int, c call, w http.ResponseWriter) { ok(w, c) })
	cfg := cfgFor(t, f.srv.URL)
	cfg.BatchSize = 100
	s, _, _ := start(t, cfg)
	if err := s.Commit(evs(250), `{"off":1}`); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "250 événements envoyés", func() bool { return s.Stats().EventsSent == 250 })
	calls := f.snapshot()
	if len(calls) != 3 {
		t.Fatalf("%d appels, attendu 3", len(calls))
	}
	base := strings.TrimSuffix(calls[0].key, ".0")
	for i, c := range calls {
		if c.key != base+"."+string(rune('0'+i)) {
			t.Fatalf("clé %d = %q", i, c.key)
		}
		for _, l := range c.lines {
			if strings.HasPrefix(l, "#") {
				t.Fatalf("la ligne meta a fui vers le serveur : %q", l)
			}
		}
	}
	waitFor(t, "unité supprimée", func() bool { return spoolCount(cfg) == 0 })
}

// Coupure au milieu d'une unité : après redémarrage, tout est renvoyé avec les
// MÊMES clés, donc le serveur (qui déduplique par clé) ne stocke aucun doublon.
func TestReplayAfterPartialSendReusesKeys(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	fail := true
	h := func(_ int, c call, w http.ResponseWriter) {
		mu.Lock()
		defer mu.Unlock()
		if fail && strings.HasSuffix(c.key, ".1") { // le 2e sous-lot échoue
			w.WriteHeader(500)
			return
		}
		seen[c.key]++
		ok(w, c)
	}
	f := newFake(t, h)
	cfg := cfgFor(t, f.srv.URL)
	cfg.BatchSize = 100
	s1, cancel, done := start(t, cfg)
	if err := s1.Commit(evs(250), ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "1er sous-lot reçu", func() bool { mu.Lock(); defer mu.Unlock(); return len(seen) == 1 })
	cancel()
	<-done // « crash » : l'unité reste sur disque
	if spoolCount(cfg) != 1 {
		t.Fatalf("unité perdue : %d", spoolCount(cfg))
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	s2, _, _ := start(t, cfg)
	waitFor(t, "unité terminée", func() bool { return spoolCount(cfg) == 0 })
	_ = s2
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("clés distinctes = %d, attendu 3 (%v)", len(seen), seen)
	}
}
