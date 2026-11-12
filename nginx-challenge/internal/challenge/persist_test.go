package challenge

import (
	"net"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func testRedis(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server absent")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cmd := exec.Command(bin, "--port", strconv.Itoa(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	addr := "127.0.0.1:" + strconv.Itoa(port)
	for i := 0; i < 60; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "redis://" + addr + "/0"
}

func newTestServer(t *testing.T, autoblock bool) *Server {
	t.Helper()
	cfg := Config{Bits: 8, CookieName: "nc", CookieTTL: time.Hour, TokenTTL: time.Minute, RateLimit: 30,
		Secret: []byte("0123456789abcdef0123456789abcdef"), Offenders: DefaultOffendersConfig()}
	cfg.Offenders.Autoblock = autoblock
	cfg.Offenders.Threshold = 3
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPersistSurvivesRestart(t *testing.T) {
	url := testRedis(t)
	a := newTestServer(t, true)
	pa, err := NewPersister(url, "", "t", a)
	if err != nil || pa == nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		a.stats.Inc(func(c *Counts) { c.Redirected++ })
		a.off.Record("203.0.113.9", "bot/1.0", "example.com", func(c *Counts) { c.Redirected++ })
	}
	a.off.Record("198.51.100.4", "", "", func(c *Counts) { c.Solved++ })
	if !a.off.Banned("203.0.113.9") {
		t.Fatal("blocage attendu avant redémarrage")
	}
	exp := time.Now().Add(time.Minute)
	if !a.used.add("tok-1", exp) {
		t.Fatal("add")
	}
	pa.Save(true)

	// « redémarrage » : nouveau serveur vide, même Redis
	b := newTestServer(t, true)
	pb, _ := NewPersister(url, "", "t", b)
	if err := pb.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := b.stats.Snapshot(24).Total.Redirected; got != 4 {
		t.Errorf("stats restaurées = %d, attendu 4", got)
	}
	if !b.off.Banned("203.0.113.9") {
		t.Error("blocage non restauré")
	}
	if b.off.LatestSeq() != a.off.LatestSeq() || len(b.off.BanEvents(0, 10)) != 1 {
		t.Error("séquence / journal des blocages non restaurés")
	}
	if rep := b.off.Report(24, 1, 10, false); len(rep) != 1 {
		t.Errorf("rapport = %d IP, attendu 1", len(rep))
	}
	if b.used.add("tok-1", exp) {
		t.Error("jeton déjà utilisé accepté après redémarrage (rejeu)")
	}
}

func TestPersistDisabledAndUnreachable(t *testing.T) {
	s := newTestServer(t, false)
	if p, err := NewPersister("", "", "", s); p != nil || err != nil {
		t.Fatal("sans URL : nil attendu")
	}
	if _, err := NewPersister("http://x", "", "", s); err == nil {
		t.Fatal("URL invalide acceptée")
	}
	p, _ := NewPersister("redis://127.0.0.1:1/0", "", "", s)
	if err := p.Restore(); err == nil {
		t.Fatal("Redis injoignable : erreur attendue")
	}
	done := make(chan struct{})
	go func() { p.Save(true); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Save bloque quand Redis est injoignable")
	}
}
