package challenge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newOff(auto bool, thr int) (*Offenders, *time.Time) {
	cfg := DefaultOffendersConfig()
	cfg.Autoblock, cfg.Threshold = auto, thr
	o := NewOffenders(cfg)
	t := time.Unix(1_800_000_000, 0)
	o.now = func() time.Time { return t }
	return o, &t
}

func redir(c *Counts) { c.Redirected++ }

func TestOffenders_BanAfterThreshold(t *testing.T) {
	o, _ := newOff(true, 5)
	for i := 0; i < 4; i++ {
		o.Record("203.0.113.9", "curl/8", "a.example.com", redir)
	}
	if o.Banned("203.0.113.9") {
		t.Fatal("banni trop tôt")
	}
	o.Record("203.0.113.9", "curl/8", "a.example.com", redir)
	if !o.Banned("203.0.113.9") {
		t.Fatal("devrait être banni au 5e échec")
	}
	if got := o.BlocklistText(); got != "203.0.113.9\n" {
		t.Fatalf("blocklist: %q", got)
	}
	ev := o.BanEvents(0, 10)
	if len(ev) != 1 || ev[0].Attempts != 5 || ev[0].Seq != 1 {
		t.Fatalf("événements: %+v", ev)
	}
	if len(o.BanEvents(1, 10)) != 0 {
		t.Fatal("since=1 doit exclure le premier")
	}
}

func TestOffenders_SolvedIsNeverBanned(t *testing.T) {
	o, _ := newOff(true, 3)
	o.Record("198.51.100.1", "Mozilla", "a", func(c *Counts) { c.Solved++ })
	for i := 0; i < 10; i++ {
		o.Record("198.51.100.1", "Mozilla", "a", redir)
	}
	if o.Banned("198.51.100.1") {
		t.Fatal("une IP qui a résolu ne doit jamais être bannie")
	}
}

func TestOffenders_WindowAndExpiry(t *testing.T) {
	o, now := newOff(true, 3)
	o.Record("192.0.2.5", "x", "a", redir)
	o.Record("192.0.2.5", "x", "a", redir)
	*now = now.Add(2 * time.Hour) // hors fenêtre (1 h)
	o.Record("192.0.2.5", "x", "a", redir)
	if o.Banned("192.0.2.5") {
		t.Fatal("échecs hors fenêtre ignorés")
	}
	o.Record("192.0.2.5", "x", "a", redir)
	o.Record("192.0.2.5", "x", "a", redir)
	if !o.Banned("192.0.2.5") {
		t.Fatal("3 échecs dans la fenêtre : ban attendu")
	}
	*now = now.Add(25 * time.Hour)
	if o.Banned("192.0.2.5") {
		t.Fatal("ban expiré après 24 h")
	}
}

func TestOffenders_DisabledAndUnban(t *testing.T) {
	o, _ := newOff(false, 3)
	for i := 0; i < 20; i++ {
		o.Record("192.0.2.7", "x", "a", redir)
	}
	if o.Banned("192.0.2.7") {
		t.Fatal("autoblock désactivé")
	}
	if rep := o.Report(24, 3, 10, true); len(rep) != 1 || rep[0].Attempts != 20 {
		t.Fatalf("rapport: %+v", rep)
	}
	o2, _ := newOff(true, 3)
	for i := 0; i < 3; i++ {
		o2.Record("2001:db8::1", "x", "a", redir)
	}
	if !o2.Banned("2001:db8::1") || !o2.Unban("2001:db8::1") || o2.Banned("2001:db8::1") {
		t.Fatal("unban")
	}
	o2.Record("not-an-ip", "x", "a", redir) // ignoré sans paniquer
}

func TestOffenders_ReportNeverSolvedFilter(t *testing.T) {
	o, _ := newOff(false, 3)
	o.Record("192.0.2.1", "x", "a", redir)
	o.Record("192.0.2.1", "x", "a", func(c *Counts) { c.Solved++ })
	o.Record("192.0.2.2", "x", "a", redir)
	if r := o.Report(24, 1, 10, true); len(r) != 1 || r[0].IP != "192.0.2.2" {
		t.Fatalf("neverSolved: %+v", r)
	}
	if r := o.Report(24, 1, 10, false); len(r) != 2 {
		t.Fatalf("tous: %+v", r)
	}
}

func TestServer_AutoblockEndToEnd(t *testing.T) {
	cfg, _ := LoadConfig(func(k string) string {
		return map[string]string{"NC_AUTOBLOCK": "true", "NC_AUTOBLOCK_THRESHOLD": "3"}[k]
	})
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	clock := time.Now()
	s.off.now = func() time.Time { clock = clock.Add(3 * time.Second); return clock } // > anti double-comptage
	do := func(path, ip, method string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Host = "a.example.com"
		if ip != "" {
			req.Header.Set("X-Real-IP", ip)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	for i := 0; i < 3; i++ {
		if c := do("/check", "203.0.113.50", "GET").Code; c != http.StatusUnauthorized && c != http.StatusForbidden {
			t.Fatalf("check #%d = %d", i, c)
		}
	}
	if c := do("/check", "203.0.113.50", "GET").Code; c != http.StatusForbidden {
		t.Fatalf("après ban attendu 403, reçu %d", c)
	}
	if b := do("/blocklist", "", "GET"); !strings.Contains(b.Body.String(), "203.0.113.50") {
		t.Fatalf("blocklist: %q", b.Body.String())
	}
	if c := do("/blocklist", "198.51.100.2", "GET").Code; c != http.StatusNotFound {
		t.Fatalf("un visiteur ne doit pas lire /blocklist: %d", c)
	}
	if c := do("/unban?ip=203.0.113.50", "", "POST").Code; c != http.StatusOK {
		t.Fatalf("unban %d", c)
	}
	if c := do("/check", "203.0.113.50", "GET").Code; c != http.StatusUnauthorized {
		t.Fatalf("après unban 401 attendu, reçu %d", c)
	}
}

func TestConfig_AutoblockEnvValidation(t *testing.T) {
	if _, err := LoadConfig(func(k string) string { return map[string]string{"NC_AUTOBLOCK_THRESHOLD": "1"}[k] }); err == nil {
		t.Fatal("seuil 1 doit être refusé")
	}
	c, err := LoadConfig(func(k string) string { return "" })
	if err != nil || c.Offenders.Autoblock || c.Offenders.Threshold != 30 {
		t.Fatalf("défauts: %+v %v", c.Offenders, err)
	}
}

// Une navigation = document + favicon + ressources, tous renvoyés vers la page de vérification :
// ce doit compter pour UN seul échec (et jamais pour une sous-ressource déclarée par le navigateur).
func TestCheck_OneNavigationIsOneFailure(t *testing.T) {
	cfg, _ := LoadConfig(func(k string) string {
		return map[string]string{"NC_AUTOBLOCK": "true", "NC_AUTOBLOCK_THRESHOLD": "3"}[k]
	})
	s, _ := New(cfg)
	h := s.Handler()
	call := func(dest string) int {
		req := httptest.NewRequest("GET", "/check", nil)
		req.Host = "a.example.com"
		req.Header.Set("X-Real-IP", "203.0.113.77")
		if dest != "" {
			req.Header.Set("Sec-Fetch-Dest", dest)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	for i := 0; i < 20; i++ { // 20 navigations avec, chacune, document + favicon + image + fetch (même seconde)
		call("document")
		call("image")
		call("image")
		call("empty")
		call("script")
	}
	rep := s.off.Report(24, 1, 10, false)
	if len(rep) != 1 || rep[0].Redirected != 1 {
		t.Fatalf("une rafale doit compter pour 1 redirection (debounce), obtenu %+v", rep)
	}
	if c := call("document"); c == http.StatusForbidden {
		t.Fatal("un visiteur ne doit pas être bloqué par des sous-ressources")
	}
	if got := s.stats.Snapshot(24).Total.Redirected; got != 101 {
		t.Fatalf("les stats globales gardent toutes les redirections : %d", got)
	}
	if IsNavigation("image") || IsNavigation("empty") || !IsNavigation("") || !IsNavigation("document") {
		t.Fatal("IsNavigation")
	}
}
