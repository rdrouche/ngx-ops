package shipper

import (
	"context"
	"net"
	"testing"
	"time"

	"nginx-analyzer-go/internal/decisions"
	"nginx-analyzer-go/internal/wire"
)

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// Producteur (client decisions) -> API locale du shipper -> tampon -> log store.
func TestDecisionsEndToEnd(t *testing.T) {
	e := newEnv(t)
	e.cfg.Listen = freeAddr(t)
	e.write(0, 1, false)
	r := e.start()
	defer r.stop()
	waitUntil(t, "API locale en écoute", func() bool {
		c, err := net.DialTimeout("tcp", e.cfg.Listen, 100*time.Millisecond)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	cl, err := decisions.New(decisions.Config{URL: "http://" + e.cfg.Listen, Token: ltok, Flush: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { cl.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	for i := 0; i < 5; i++ {
		cl.Emit(wire.Event{TS: time.Now(), Source: wire.SourceWAF, Action: wire.ActionLogged, Site: "a.example",
			IP: "198.51.100.9", Path: "/p/" + string(rune('a'+i)), Rule: "942100"})
	}
	waitUntil(t, "5 décisions au log store", func() bool {
		e.fs.mu.Lock()
		defer e.fs.mu.Unlock()
		return e.fs.srcs[wire.SourceWAF] == 5
	})
	if s := cl.Stats(); s.Sent != 5 || s.Rejected != 0 {
		t.Fatalf("stats client = %+v", s)
	}
}

func TestDecisionsWrongTokenIsRejected(t *testing.T) {
	e := newEnv(t)
	e.cfg.Listen = freeAddr(t)
	e.write(0, 1, false)
	r := e.start()
	defer r.stop()
	waitUntil(t, "API locale", func() bool {
		c, err := net.DialTimeout("tcp", e.cfg.Listen, 100*time.Millisecond)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	cl, _ := decisions.New(decisions.Config{URL: "http://" + e.cfg.Listen, Token: "mauvais-jeton-0123456789-abcdefgh", Flush: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { cl.Run(ctx); close(done) }()
	cl.Emit(wire.Event{TS: time.Now(), Source: wire.SourceWAF, Action: wire.ActionLogged, IP: "198.51.100.9"})
	waitUntil(t, "rejet compté", func() bool { return cl.Stats().Rejected == 1 })
	cancel()
	<-done
	e.fs.mu.Lock()
	defer e.fs.mu.Unlock()
	if e.fs.srcs[wire.SourceWAF] != 0 {
		t.Fatal("événement accepté avec un mauvais jeton")
	}
}
