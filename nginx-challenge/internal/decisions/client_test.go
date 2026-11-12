package decisions

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nginx-challenge/internal/wire"
)

const tok = "local-token-0123456789-abcdefgh"

func cfg(url string) Config {
	return Config{URL: url, Token: tok, Flush: 10 * time.Millisecond, Backoff: 10 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func ev(i int) wire.Event {
	return wire.Event{TS: time.Now(), Source: "waf", Action: "logged", IP: "198.51.100.1", Path: "/x"}
}

func run(t *testing.T, c *Client) (cancel func()) {
	ctx, cn := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	return func() { cn(); <-done }
}

func TestDisabledIsNoop(t *testing.T) {
	c, err := New(Config{})
	if c != nil || err != nil {
		t.Fatal("doit être nil sans URL")
	}
	c.Emit(ev(0))
	c.Run(context.Background())
	_ = c.Stats()
}

func TestURLValidation(t *testing.T) {
	bad := []string{"ftp://shipper:9181", "http://shipper:9181/x", "http://u:p@shipper:9181", "http://example.com:9181", "http://8.8.8.8:9181", "://x", "shipper:9181"}
	for _, u := range bad {
		if _, err := New(cfg(u)); err == nil {
			t.Errorf("%q accepté", u)
		}
	}
	good := []string{"http://shipper:9181", "http://127.0.0.1:9181", "http://localhost:9181", "http://10.1.2.3:9181", "http://172.20.0.5:9181", "https://ship.example.com", "http://[::1]:9181"}
	for _, u := range good {
		if _, err := New(cfg(u)); err != nil {
			t.Errorf("%q refusé : %v", u, err)
		}
	}
	c := cfg("http://shipper:9181")
	c.Token = "court"
	if _, err := New(c); err == nil {
		t.Error("jeton court accepté")
	}
}

func TestSendsBatchWithToken(t *testing.T) {
	var mu sync.Mutex
	var got []string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		auth = r.Header.Get("Authorization")
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			got = append(got, sc.Text())
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	c, err := New(cfg(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	stop := run(t, c)
	for i := 0; i < 5; i++ {
		c.Emit(ev(i))
	}
	deadline := time.Now().Add(3 * time.Second)
	for c.Stats().Sent < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 5 || auth != "Bearer "+tok {
		t.Fatalf("lignes=%d auth=%q", len(got), auth)
	}
}

func TestRetriesThenRecovers(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	c, _ := New(cfg(srv.URL))
	stop := run(t, c)
	c.Emit(ev(1))
	deadline := time.Now().Add(3 * time.Second)
	for c.Stats().Sent < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	if s := c.Stats(); s.Sent != 1 || s.SendDropped != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestDropsAfterRetriesAndCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	c, _ := New(cfg(srv.URL))
	stop := run(t, c)
	c.Emit(ev(1))
	deadline := time.Now().Add(3 * time.Second)
	for c.Stats().SendDropped < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	if s := c.Stats(); s.SendDropped != 1 || !s.Failing {
		t.Fatalf("stats = %+v", s)
	}
}

func TestClientErrorIsNotRetried(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1); w.WriteHeader(401) }))
	defer srv.Close()
	c, _ := New(cfg(srv.URL))
	stop := run(t, c)
	c.Emit(ev(1))
	deadline := time.Now().Add(3 * time.Second)
	for c.Stats().Rejected < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	if n.Load() != 1 {
		t.Fatalf("%d appels, attendu 1", n.Load())
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, 307)
	}))
	defer srv.Close()
	c, _ := New(cfg(srv.URL))
	stop := run(t, c)
	c.Emit(ev(1))
	time.Sleep(300 * time.Millisecond)
	stop()
	if hits.Load() != 0 {
		t.Fatal("redirection suivie : le jeton aurait fui")
	}
}

func TestQueueFullDropsWithoutBlocking(t *testing.T) {
	c, _ := New(Config{URL: "http://shipper:9181", Token: tok, QueueSize: 3})
	for i := 0; i < 10; i++ {
		c.Emit(ev(i)) // pas de Run : la file se remplit
	}
	if s := c.Stats(); s.Emitted != 3 || s.QueueDropped != 7 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestShutdownFlushesRemaining(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		n.Add(int32(strings.Count(string(b), "\n")))
		w.WriteHeader(202)
	}))
	defer srv.Close()
	c := cfg(srv.URL)
	c.Flush = time.Hour // seul l'arrêt déclenche l'envoi
	cl, _ := New(c)
	stop := run(t, cl)
	for i := 0; i < 4; i++ {
		cl.Emit(ev(i))
	}
	time.Sleep(50 * time.Millisecond)
	stop()
	if n.Load() != 4 {
		t.Fatalf("envoyés à l'arrêt = %d", n.Load())
	}
}

func TestTokenNeverLogged(t *testing.T) {
	var sb strings.Builder
	var mu sync.Mutex
	lg := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return sb.Write(p) }), nil))
	c := cfg("http://127.0.0.1:1")
	c.Logger = lg
	cl, _ := New(c)
	stop := run(t, cl)
	cl.Emit(ev(1))
	time.Sleep(200 * time.Millisecond)
	stop()
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(sb.String(), tok) || strings.Contains(sb.String(), "127.0.0.1") {
		t.Fatalf("secret ou URL dans les journaux : %s", sb.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
