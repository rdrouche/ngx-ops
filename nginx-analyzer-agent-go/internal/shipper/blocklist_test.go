package shipper

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/wire"
)

func (e *env) blPath() string { return filepath.Join(e.logs, "blocklist-hits.log") }

func blLine(i int) string {
	return fmt.Sprintf("2026-11-09T19:00:00+01:00 198.51.100.5 site.example \"GET /b/%d?x=1 HTTP/1.1\" 403\n", i)
}

func (e *env) writeBL(from, to int, appendMode bool) {
	e.t.Helper()
	flag := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if !appendMode {
		flag = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(e.blPath(), flag, 0o644)
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	for i := from; i < to; i++ {
		if _, err := f.WriteString(blLine(i)); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) blCount() int {
	e.fs.mu.Lock()
	defer e.fs.mu.Unlock()
	return e.fs.srcs[wire.SourceBlocklist]
}

func TestMapBlocklist(t *testing.T) {
	be, ok := parse.BlocklistParseLine(`2026-11-09T19:00:00+01:00 198.51.100.5 site.example "GET /a/b?q=1 HTTP/1.1" 403`, "blocklist", "")
	if !ok {
		t.Fatal("ligne non analysée")
	}
	ev, ok := MapBlocklist(be)
	if !ok {
		t.Fatal("rejetée")
	}
	if ev.Source != wire.SourceBlocklist || ev.Action != wire.ActionBlocked || ev.Site != "site.example" ||
		ev.IP != "198.51.100.5" || ev.Method != "GET" || ev.Path != "/a/b" || ev.Query != "q=1" || ev.Status != 403 {
		t.Fatalf("événement = %+v", ev)
	}
	if ev.TS.UTC().Format(time.RFC3339) != "2026-11-09T18:00:00Z" || ev.Rule != "" {
		t.Fatalf("ts=%v rule=%q", ev.TS, ev.Rule)
	}
	if !wire.ValidSource(ev.Source) || !wire.ValidAction(ev.Action) {
		t.Fatal("invalide pour le log store")
	}
	if _, ok := MapBlocklist(parse.BlocklistEntry{}); ok {
		t.Fatal("entrée vide acceptée")
	}
}

func TestBlocklistFileIsShippedExactlyOnce(t *testing.T) {
	e := newEnv(t)
	e.write(0, 1, false)
	e.writeBL(0, 1, false) // historique : non expédié (fichier vu pour la 1re fois)
	r := e.start()
	time.Sleep(150 * time.Millisecond)
	e.writeBL(100, 140, true)
	e.write(7000, 7020, true) // les deux suiveurs travaillent en parallèle
	waitUntil(t, "40 hits blocklist + 20 accès", func() bool { return e.blCount() == 40 && e.fs.distinct() >= 60 })
	settle()
	if e.blCount() != 40 {
		t.Fatalf("blocklist = %d", e.blCount())
	}
	for i := 100; i < 140; i++ {
		if c := e.fs.count(fmt.Sprintf("/b/%d", i)); c != 1 {
			t.Fatalf("/b/%d stocké %d fois", i, c)
		}
	}
	e.fs.assertExactlyOnce(t, 7000, 7020)
	r.stop()
}

// Deux suiveurs, un seul tampon : après un « crash » avec tampon plein, chacun reprend SES positions,
// sans perte ni doublon, et sans mélanger les états.
func TestBothFollowersRecoverFromSharedSpool(t *testing.T) {
	e := newEnv(t)
	e.write(0, 1, false)
	e.writeBL(0, 1, false)
	e.fs.down.Store(true)
	r := e.start()
	time.Sleep(150 * time.Millisecond)
	e.write(8000, 8050, true)
	e.writeBL(200, 230, true)
	waitUntil(t, "unités en tampon", func() bool { return r.s.sink.Stats().SpoolFiles >= 2 })
	waitUntil(t, "offsets écrits", func() bool {
		_, a := os.Stat(e.cfg.StateFile)
		_, b := os.Stat(e.cfg.BlocklistState)
		return a == nil && b == nil
	})
	r.stop()
	os.Remove(e.cfg.StateFile)
	os.Remove(e.cfg.BlocklistState)
	e.fs.down.Store(false)
	e.write(8050, 8060, true)
	e.writeBL(230, 240, true)
	r2 := e.start()
	waitUntil(t, "tout reçu", func() bool { return e.blCount() == 40 && e.fs.distinct() >= 100 })
	settle()
	e.fs.assertExactlyOnce(t, 8000, 8060)
	for i := 200; i < 240; i++ {
		if c := e.fs.count(fmt.Sprintf("/b/%d", i)); c != 1 {
			t.Fatalf("/b/%d stocké %d fois", i, c)
		}
	}
	// états séparés : aucun fichier de l'autre suiveur dans chaque fichier d'offsets
	var a, b stateFile
	ba, _ := os.ReadFile(e.cfg.StateFile)
	bb, _ := os.ReadFile(e.cfg.BlocklistState)
	_ = json.Unmarshal(ba, &a)
	_ = json.Unmarshal(bb, &b)
	for f := range a.Files {
		if strings.Contains(f, "blocklist-hits") {
			t.Fatalf("état access pollué par %s", f)
		}
	}
	for f := range b.Files {
		if strings.Contains(f, ".access.log") {
			t.Fatalf("état blocklist pollué par %s", f)
		}
	}
	r2.stop()
}

func TestBlocklistDisabled(t *testing.T) {
	e := newEnv(t)
	e.cfg.WithBlocklist = false
	e.write(0, 1, false)
	e.writeBL(0, 1, false)
	r := e.start()
	time.Sleep(150 * time.Millisecond)
	e.writeBL(300, 310, true)
	time.Sleep(400 * time.Millisecond)
	if e.blCount() != 0 {
		t.Fatal("blocklist expédiée alors que désactivée")
	}
	if _, ok := r.s.Status().(map[string]any)["tail_blocklist"]; ok {
		t.Fatal("suiveur blocklist présent dans le statut")
	}
	r.stop()
}

func TestStatusShowsBlocklistFollower(t *testing.T) {
	e := newEnv(t)
	e.write(0, 1, false)
	r := e.start()
	m := r.s.Status().(map[string]any)
	if _, ok := m["tail"]; !ok {
		t.Fatal("tail absent")
	}
	if _, ok := m["tail_blocklist"]; !ok {
		t.Fatal("tail_blocklist absent")
	}
	r.stop()
}
