package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type env struct {
	svc   *Service
	logs  string
	data  string
	rules string
}

func newEnv(t testing.TB, rules string, mut func(*Config)) *env {
	t.Helper()
	e := &env{logs: t.TempDir(), data: t.TempDir(), rules: rules}
	cfg := Config{
		Version: "test", LogsDir: e.logs,
		LogPattern:    regexp.MustCompile(`(^|[._])access\.log$`),
		WafLogPattern: regexp.MustCompile(`(^|[._-])wafemu\.log$`),
		DataDir:       e.data, RulesDir: rules, CRSVersion: "v4.8.0",
		PollMs: 20, ReadFromStart: true,
	}
	if mut != nil {
		mut(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = s
	t.Cleanup(s.Close)
	return e
}

func (e *env) start(t testing.TB) {
	t.Helper()
	e.svc.Start()
	waitFor(t, 30*time.Second, "moteur pret", func() bool { return e.svc.eng.Ready() })
}

func waitFor(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	dl := time.Now().Add(d)
	for time.Now().Before(dl) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("delai depasse : %s", what)
}

func (e *env) write(t testing.TB, name string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(e.logs, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
}

// settle attend que n lignes lues par le tailer aient traverse tout le pipeline.
func (e *env) settle(t testing.TB, lines int) {
	t.Helper()
	waitFor(t, 60*time.Second, fmt.Sprintf("%d lignes lues", lines), func() bool { return e.svc.src.Load().Status().Lines >= lines })
	if !e.svc.Sync(60 * time.Second) {
		t.Fatal("Sync a expire")
	}
}

func ts() string { return time.Now().Format("02/Jan/2006:15:04:05 -0700") }

func combined(ip, method, uri string, status int, ua string) string {
	return fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d 512 "-" "%s"`, ip, ts(), method, uri, status, ua)
}

func vhostLine(vhost, ip, method, uri string, status int, ua string) string {
	return fmt.Sprintf(`%s %s - - [%s] "%s %s HTTP/1.1" %d 512 "-" "%s"`, vhost, ip, ts(), method, uri, status, ua)
}

func jsonLine(vhost, ip, method, uri string, status int, ua string, extra string) string {
	return fmt.Sprintf(`{"t":"%s","vhost":"%s","ip":"%s","m":"%s","u":"%s","p":"HTTP/1.1","s":%d,"ua":"%s","ref":""%s}`,
		time.Now().Format(time.RFC3339), vhost, ip, method, strings.ReplaceAll(uri, `"`, `\"`), status, ua, extra)
}

func put(t testing.TB, s *Service, body string) {
	t.Helper()
	if _, err := s.UpdateSettings([]byte(body)); err != nil {
		t.Fatalf("PUT %s : %v", body, err)
	}
}

func (e *env) hits(t testing.TB, f func(*HitQ)) (int, []HitView) {
	t.Helper()
	q := &HitQ{Limit: 500}
	if f != nil {
		f(q)
	}
	tot, hs, err := e.svc.QueryHits(context.Background(), q.filter())
	if err != nil {
		t.Fatal(err)
	}
	var out []HitView
	for _, h := range hs {
		v := HitView{IP: h.IP, Vhost: h.Vhost, Score: h.Score, Mode: h.Mode, URI: h.URI}
		for _, r := range h.Rules {
			v.Rules = append(v.Rules, r.ID)
		}
		out = append(out, v)
	}
	return tot, out
}
