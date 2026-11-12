package shipper

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nginx-analyzer-go/internal/wire"
)

const (
	wtok  = "lgs_write_token_do_not_leak"
	ltok  = "local-token-0123456789-abcdefgh"
	fname = "site.example.access.log"
)

// fakeStore simule le log store : déduplique par Idempotency-Key, compte les
// événements distincts par chemin.
type fakeStore struct {
	mu     sync.Mutex
	keys   map[string]bool
	paths  map[string]int // path -> nombre de fois stocké
	srcs   map[string]int
	down   atomic.Bool
	srv    *httptest.Server
	posted atomic.Int64
}

func newFakeStore(t *testing.T) *fakeStore {
	f := &fakeStore{keys: map[string]bool{}, paths: map[string]int{}, srcs: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.posted.Add(1)
		if f.down.Load() {
			w.WriteHeader(503)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+wtok {
			w.WriteHeader(401)
			return
		}
		var rd io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			rd = zr
		}
		key := r.Header.Get(wire.HeaderIdempotencyKey)
		var evs []wire.Event
		sc := bufio.NewScanner(rd)
		sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l == "" || l[0] == '#' {
				continue
			}
			var ev wire.Event
			if json.Unmarshal([]byte(l), &ev) == nil {
				evs = append(evs, ev)
			}
		}
		f.mu.Lock()
		dup := f.keys[key]
		if !dup {
			f.keys[key] = true
			for _, ev := range evs {
				f.paths[ev.Path]++
				f.srcs[ev.Source]++
			}
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wire.Result{Accepted: len(evs), Duplicate: dup})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeStore) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.paths[path]
}

func (f *fakeStore) distinct() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.paths)
}

// assertExactlyOnce vérifie /p/<from>..<to-1> : chaque chemin stocké exactement une fois.
func (f *fakeStore) assertExactlyOnce(t *testing.T, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		if c := f.count(fmt.Sprintf("/p/%d", i)); c != 1 {
			t.Fatalf("/p/%d stocké %d fois (attendu 1)", i, c)
		}
	}
}

type env struct {
	t    *testing.T
	logs string
	cfg  Config
	fs   *fakeStore
}

func newEnv(t *testing.T) *env {
	logs := t.TempDir()
	data := t.TempDir()
	fs := newFakeStore(t)
	cfg := Config{
		Dir: logs, Pattern: regexp.MustCompile(`(^|[._])access\.log$`), PollMs: 20,
		StateFile: filepath.Join(data, "offsets.json"), Listen: "127.0.0.1:0", LocalToken: ltok,
		WithBotClass: true, MaxQueue: 1000,
		WithBlocklist: true, BlocklistPattern: regexp.MustCompile(`^blocklist-hits\.log$`),
		BlocklistState: filepath.Join(data, "offsets-blocklist.json"),
	}
	cfg.Sink.URL = fs.srv.URL
	cfg.Sink.Token = wtok
	cfg.Sink.InstanceName = "web1"
	cfg.Sink.SpoolDir = filepath.Join(data, "spool")
	cfg.Sink.AllowInsecure = true
	cfg.Sink.BatchSize = 50
	cfg.Sink.MinBackoff = 20 * time.Millisecond
	cfg.Sink.PollInterval = 10 * time.Millisecond
	cfg.Sink.FlushInterval = 20 * time.Millisecond
	return &env{t: t, logs: logs, cfg: cfg, fs: fs}
}

func line(i int) string {
	return fmt.Sprintf(`198.51.100.7 - - [09/Nov/2026:19:00:00 +0100] "GET /p/%d?x=1 HTTP/1.1" 200 12 "-" "curl/8.0"`+"\n", i)
}

func (e *env) path() string { return filepath.Join(e.logs, fname) }

func (e *env) write(from, to int, appendMode bool) {
	e.t.Helper()
	flag := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if !appendMode {
		flag = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(e.path(), flag, 0o644)
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	for i := from; i < to; i++ {
		if _, err := f.WriteString(line(i)); err != nil {
			e.t.Fatal(err)
		}
	}
}

type running struct {
	s      *Shipper
	cancel context.CancelFunc
	done   chan struct{}
}

func (e *env) start() *running {
	e.t.Helper()
	s, err := New(e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{s: s, cancel: cancel, done: make(chan struct{})}
	go func() { _ = s.Run(ctx); close(r.done) }()
	e.t.Cleanup(func() { r.stop() })
	return r
}

func (r *running) stop() {
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(10 * time.Second):
		panic("arrêt du shipper bloqué")
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("délai dépassé : %s", what)
}

func settle() { time.Sleep(300 * time.Millisecond) }

func TestShipsAppendedLines(t *testing.T) {
	e := newEnv(t)
	e.write(0, 3, false) // historique : jamais expédié (fichier vu pour la 1re fois)
	r := e.start()
	time.Sleep(150 * time.Millisecond)
	e.write(100, 160, true)
	waitUntil(t, "60 événements", func() bool { return e.fs.distinct() == 60 })
	e.fs.assertExactlyOnce(t, 100, 160)
	if e.fs.count("/p/0") != 0 {
		t.Fatal("l'historique antérieur au démarrage a été expédié")
	}
	// l'événement porte bien les champs mappés
	r.stop()
}

func TestRestartNoLossNoDuplicate(t *testing.T) {
	e := newEnv(t)
	e.write(0, 1, false)
	r := e.start()
	time.Sleep(150 * time.Millisecond)
	e.write(1000, 1100, true)
	waitUntil(t, "1er lot", func() bool { return e.fs.distinct() == 100 })
	r.stop()
	// lignes écrites pendant l'arrêt
	e.write(1100, 1200, true)
	r2 := e.start()
	e.write(1200, 1250, true)
	waitUntil(t, "tout reçu", func() bool { return e.fs.distinct() == 250 })
	settle()
	e.fs.assertExactlyOnce(t, 1000, 1250)
	r2.stop()
}

// Le log store est en panne : tout reste dans le tampon ; au retour, une seule
// copie de chaque événement.
func TestLogstoreDownThenUp(t *testing.T) {
	e := newEnv(t)
	e.write(0, 1, false)
	e.fs.down.Store(true)
	r := e.start()
	time.Sleep(150 * time.Millisecond)
	e.write(2000, 2200, true)
	waitUntil(t, "tampon alimenté", func() bool { return r.s.sink.Stats().SpoolFiles > 0 })
	if e.fs.distinct() != 0 {
		t.Fatal("événements reçus pendant la panne")
	}
	e.fs.down.Store(false)
	waitUntil(t, "livraison après reprise", func() bool { return e.fs.distinct() == 200 })
	settle()
	e.fs.assertExactlyOnce(t, 2000, 2200)
	r.stop()
}

// Crash après Commit mais avant l'écriture du fichier d'offsets : la meta du
// tampon fait foi. On simule en supprimant le fichier d'offsets pendant que le
// tampon contient encore des unités.
func TestCrashBetweenCommitAndOffsetFile(t *testing.T) {
	e := newEnv(t)
	e.write(0, 1, false)
	e.fs.down.Store(true) // les unités restent dans le tampon
	r := e.start()
	time.Sleep(150 * time.Millisecond)
	e.write(3000, 3120, true)
	waitUntil(t, "unités en tampon", func() bool { return r.s.sink.Stats().SpoolFiles > 0 })
	waitUntil(t, "offsets écrits", func() bool { _, err := os.Stat(e.cfg.StateFile); return err == nil })
	r.stop()
	// « crash » : fichier d'offsets perdu / en retard
	if err := os.Remove(e.cfg.StateFile); err != nil {
		t.Fatal(err)
	}
	e.fs.down.Store(false)
	e.write(3120, 3150, true)
	r2 := e.start()
	waitUntil(t, "tout reçu", func() bool { return e.fs.distinct() == 150 })
	settle()
	e.fs.assertExactlyOnce(t, 3000, 3150) // ni perte (3000..3119 du tampon) ni doublon
	if r2.s.recovered == 0 {
		t.Fatal("aucune position reprise depuis le tampon")
	}
	r2.stop()
}

func TestRotation(t *testing.T) {
	e := newEnv(t)
	e.write(0, 1, false)
	r := e.start()
	time.Sleep(150 * time.Millisecond)
	e.write(4000, 4050, true)
	waitUntil(t, "avant rotation", func() bool { return e.fs.distinct() == 50 })
	// rotation : l'ancien fichier est renommé (ne correspond plus au motif), un nouveau est créé
	if err := os.Rename(e.path(), e.path()+".1"); err != nil {
		t.Fatal(err)
	}
	e.write(4050, 4100, false)
	waitUntil(t, "après rotation", func() bool { return e.fs.distinct() == 100 })
	settle()
	e.fs.assertExactlyOnce(t, 4000, 4100)
	r.stop()
}

func TestTruncation(t *testing.T) {
	e := newEnv(t)
	e.write(0, 1, false)
	r := e.start()
	time.Sleep(150 * time.Millisecond)
	e.write(5000, 5050, true)
	waitUntil(t, "avant troncature", func() bool { return e.fs.distinct() == 50 })
	// copytruncate : le fichier est vidé puis réécrit avec d'autres lignes
	e.write(5050, 5080, false)
	waitUntil(t, "après troncature", func() bool { return e.fs.distinct() == 80 })
	settle()
	e.fs.assertExactlyOnce(t, 5000, 5080)
	r.stop()
}

func TestPartialLineIsNotShippedUntilComplete(t *testing.T) {
	e := newEnv(t)
	e.write(0, 1, false)
	r := e.start()
	time.Sleep(150 * time.Millisecond)
	full := line(6000)
	f, _ := os.OpenFile(e.path(), os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(full[:40])
	time.Sleep(150 * time.Millisecond)
	if e.fs.count("/p/6000") != 0 {
		t.Fatal("ligne incomplète expédiée")
	}
	f.WriteString(full[40:])
	f.Close()
	waitUntil(t, "ligne complétée", func() bool { return e.fs.count("/p/6000") == 1 })
	r.stop()
}

func TestEventMapping(t *testing.T) {
	m := Mapper{BotClass: true}
	ev, ok := m.Map(parseOne(t, `203.0.113.9 - - [09/Nov/2026:19:00:00 +0100] "POST /a/b?q=1&r=2 HTTP/1.1" 404 77 "https://ref.example/x?y=1" "Googlebot/2.1"`))
	if !ok {
		t.Fatal("ligne rejetée")
	}
	if ev.Source != wire.SourceAccess || ev.Action != wire.ActionAllowed || ev.Method != "POST" ||
		ev.Path != "/a/b" || ev.Query != "q=1&r=2" || ev.Status != 404 || ev.Bytes != 77 || ev.IP != "203.0.113.9" {
		t.Fatalf("mapping inattendu : %+v", ev)
	}
	if ev.BotClass != "good" {
		t.Fatalf("bot_class = %q", ev.BotClass)
	}
	if ev.TS.UTC().Format(time.RFC3339) != "2026-11-09T18:00:00Z" || ev.TS.Location() != time.UTC {
		t.Fatalf("ts = %v", ev.TS)
	}
	ev2, _ := m.Map(parseOne(t, `203.0.113.9 - - [09/Nov/2026:19:00:00 +0100] "GET / HTTP/1.1" 200 1 "-" "-"`))
	if ev2.UA != "" || ev2.Referer != "" || ev2.BotClass != "" {
		t.Fatalf("« - » doit devenir vide : %+v", ev2)
	}
}

func TestStatusLeaksNoSecret(t *testing.T) {
	e := newEnv(t)
	e.write(0, 1, false)
	e.cfg.Sink.URL = strings.Replace(e.fs.srv.URL, "http://", "http://", 1)
	r := e.start()
	b, _ := json.Marshal(r.s.Status())
	for _, secret := range []string{wtok, ltok, "Bearer", e.cfg.Sink.SpoolDir} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("/status expose %q", secret)
		}
	}
	r.stop()
}

// ---- Store avec un committer défaillant ----

type flaky struct {
	mu    sync.Mutex
	fail  bool
	units [][]wire.Event
	metas []string
}

func (f *flaky) Commit(evs []wire.Event, meta string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return fmt.Errorf("disque plein")
	}
	f.units = append(f.units, evs)
	f.metas = append(f.metas, meta)
	return nil
}
func (f *flaky) set(v bool) { f.mu.Lock(); f.fail = v; f.mu.Unlock() }

func ev(i int) wire.Event {
	return wire.Event{TS: time.Now(), Source: "access", Action: "allowed", Path: fmt.Sprintf("/p/%d", i)}
}

func TestStoreOffsetDoesNotAdvanceWithoutCommit(t *testing.T) {
	f := &flaky{fail: true}
	s := NewStore(filepath.Join(t.TempDir(), "o.json"), f, 100, nil)
	s.SetOffset("a.log", 1, 0, "combined") // enregistrement initial (aucun événement)
	s.Add(ev(1))
	s.Add(ev(2))
	s.SetOffset("a.log", 1, 500, "combined")
	if _, off, _, _ := s.GetOffset("a.log"); off != 0 {
		t.Fatalf("offset avancé sans commit : %d", off)
	}
	if s.QueueLen() != 2 {
		t.Fatalf("file = %d", s.QueueLen())
	}
	f.set(false)
	s.Retry()
	if _, off, _, _ := s.GetOffset("a.log"); off != 500 {
		t.Fatalf("offset = %d après reprise", off)
	}
	if len(f.units) != 1 || len(f.units[0]) != 2 {
		t.Fatalf("unités = %v", f.units)
	}
	var m metaRec
	if err := json.Unmarshal([]byte(f.metas[0]), &m); err != nil || m.O != 500 || m.F != "a.log" {
		t.Fatalf("meta = %q", f.metas[0])
	}
}

func TestStoreQueueIsBounded(t *testing.T) {
	f := &flaky{fail: true}
	s := NewStore(filepath.Join(t.TempDir(), "o.json"), f, 10, nil)
	for u := 0; u < 5; u++ {
		for i := 0; i < 6; i++ {
			s.Add(ev(u*10 + i))
		}
		s.SetOffset("a.log", 1, int64((u+1)*100), "combined")
	}
	if s.QueueLen() > 10+6 {
		t.Fatalf("file non bornée : %d", s.QueueLen())
	}
	if s.QueueDrop.Load() == 0 {
		t.Fatal("aucun abandon compté")
	}
}

func TestStoreCorruptStateIsReported(t *testing.T) {
	p := filepath.Join(t.TempDir(), "o.json")
	os.WriteFile(p, []byte("{pas du json"), 0o600)
	if err := NewStore(p, &flaky{}, 10, nil).Load(); err == nil {
		t.Fatal("état corrompu accepté")
	}
}

func TestStateFilePermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "o.json")
	s := NewStore(p, &flaky{}, 10, nil)
	s.SetOffset("a.log", 1, 5, "combined")
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", st.Mode().Perm())
	}
}
