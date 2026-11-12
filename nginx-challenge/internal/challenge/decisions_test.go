package challenge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nginx-challenge/internal/wire"
)

type rec struct {
	mu  sync.Mutex
	evs []wire.Event
}

func (r *rec) Emit(e wire.Event) { r.mu.Lock(); r.evs = append(r.evs, e); r.mu.Unlock() }
func (r *rec) snap() []wire.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]wire.Event(nil), r.evs...)
}
func (r *rec) rules() []string {
	var out []string
	for _, e := range r.snap() {
		out = append(out, e.Action+":"+e.Rule)
	}
	return out
}

func newSrv(t *testing.T, cfg Config) (*Server, *rec) {
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := &rec{}
	s.SetEmitter(r)
	return s, r
}

func TestSetEmitterNilIsNoop(t *testing.T) {
	s, _ := New(testConfig())
	s.SetEmitter(nil) // ne doit rien brancher
	h := s.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", "/check", "203.0.113.5", ""))
	if w.Code != 401 {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestEmitSolvedAndRedirect(t *testing.T) {
	s, r := newSrv(t, testConfig())
	h := s.Handler()
	// navigation sans cookie : redirigé
	c := req("GET", "/check", "203.0.113.5", "")
	c.Header.Set("Sec-Fetch-Dest", "document")
	c.Header.Set("User-Agent", "Mozilla/5.0 test")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, c)
	// la 2e navigation de la même IP dans la minute n'émet pas de 2e événement
	w = httptest.NewRecorder()
	h.ServeHTTP(w, c)
	if got := r.rules(); len(got) != 1 || got[0] != "challenged:redirected" {
		t.Fatalf("événements après 2 redirections = %v", got)
	}
	// flux complet : défi résolu
	if w := flow(t, h, "203.0.113.5"); w.Code != 200 {
		t.Fatalf("flux : %d %s", w.Code, w.Body.String())
	}
	got := r.rules()
	if got[len(got)-1] != "allowed:solved" {
		t.Fatalf("dernier événement = %v", got)
	}
	last := r.snap()[len(got)-1]
	if last.Source != wire.SourceChallenge || last.IP != "203.0.113.5" || last.Site != "app.example.com" || last.Extra["bits"] != 8 {
		t.Fatalf("événement = %+v", last)
	}
	if first := r.snap()[0]; first.UA != "Mozilla/5.0 test" {
		t.Fatalf("UA = %q", first.UA)
	}
}

func TestEmitSubResourceRedirectIsNotEmitted(t *testing.T) {
	s, r := newSrv(t, testConfig())
	c := req("GET", "/check", "203.0.113.6", "")
	c.Header.Set("Sec-Fetch-Dest", "image") // favicon / ressource : pas une navigation
	s.Handler().ServeHTTP(httptest.NewRecorder(), c)
	if len(r.snap()) != 0 {
		t.Fatalf("événement émis pour une sous-ressource : %v", r.rules())
	}
}

func TestEmitFailures(t *testing.T) {
	s, r := newSrv(t, testConfig())
	h := s.Handler()
	// défi invalide
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", Prefix+"api/verify", "203.0.113.7", `{"token":"nimporte","counter":"1","target":"/"}`))
	if w.Code != 400 {
		t.Fatalf("code = %d", w.Code)
	}
	// solution incorrecte
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", Prefix+"api/start", "203.0.113.7", ""))
	tok := between(w.Body.String(), `"token":"`, `"`)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", Prefix+"api/verify", "203.0.113.7", `{"token":"`+tok+`","counter":"zzz-faux","target":"/"}`))
	reasons := []string{}
	for _, e := range r.snap() {
		if e.Rule == "failed" {
			reasons = append(reasons, e.Extra["reason"].(string))
		}
	}
	if len(reasons) != 2 || reasons[0] != "expired_or_invalid" || reasons[1] != "wrong_solution" {
		t.Fatalf("raisons = %v (%v)", reasons, r.rules())
	}
}

func TestEmitRateLimited(t *testing.T) {
	cfg := testConfig()
	cfg.RateLimit = 1
	s, r := newSrv(t, cfg)
	h := s.Handler()
	for i := 0; i < 4; i++ {
		h.ServeHTTP(httptest.NewRecorder(), req("GET", Prefix+"api/start", "203.0.113.8", ""))
	}
	n := 0
	for _, e := range r.snap() {
		if e.Rule == "rate_limited" && e.Action == wire.ActionBlocked && e.Extra["stage"] == "start" {
			n++
		}
	}
	if n == 0 {
		t.Fatalf("aucun événement rate_limited : %v", r.rules())
	}
}

func TestEmitAutoBanOncePerBan(t *testing.T) {
	cfg := testConfig()
	cfg.Offenders = OffendersConfig{Autoblock: true, Threshold: 3, Window: time.Hour, BanFor: time.Hour, Retention: time.Hour}
	s, r := newSrv(t, cfg)
	h := s.Handler()
	for i := 0; i < 6; i++ {
		h.ServeHTTP(httptest.NewRecorder(), req("POST", Prefix+"api/verify", "198.51.100.77", `{"token":"x","counter":"1","target":"/"}`))
	}
	bans := 0
	for _, e := range r.snap() {
		if e.Rule == "auto_ban" {
			bans++
			if e.Action != wire.ActionBlocked || e.IP != "198.51.100.77" || e.Extra["attempts"] == nil {
				t.Fatalf("événement de blocage = %+v", e)
			}
		}
	}
	if bans != 1 {
		t.Fatalf("blocages émis = %d, attendu 1 (%v)", bans, r.rules())
	}
	// requêtes refusées ensuite : pas d'événement par requête
	before := len(r.snap())
	c := req("GET", "/check", "198.51.100.77", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, c)
	if w.Code != http.StatusForbidden || len(r.snap()) != before {
		t.Fatalf("code=%d, événements %d -> %d", w.Code, before, len(r.snap()))
	}
}

func TestEmitSkipsInvalidIP(t *testing.T) {
	s, r := newSrv(t, testConfig())
	c := req("GET", "/check", "pas-une-ip", "")
	c.Header.Set("Sec-Fetch-Dest", "document")
	s.Handler().ServeHTTP(httptest.NewRecorder(), c)
	if len(r.snap()) != 0 {
		t.Fatalf("événement émis sans IP valide : %v", r.rules())
	}
}

func TestLoadConfigShipper(t *testing.T) {
	env := func(k string) string {
		return map[string]string{"NC_SHIPPER_URL": " http://ngx-shipper:9181 ", "NC_SHIPPER_TOKEN": " tok "}[k]
	}
	c, err := LoadConfig(env)
	if err != nil || c.ShipperURL != "http://ngx-shipper:9181" || c.ShipperToken != "tok" {
		t.Fatalf("%+v %v", c, err)
	}
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	return s[:strings.Index(s, b)]
}
