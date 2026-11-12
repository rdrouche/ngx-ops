package api_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"ngxops/logstore/internal/api"
	"ngxops/logstore/internal/auth"
	"ngxops/logstore/internal/config"
	"ngxops/logstore/internal/ipmode"
	"ngxops/logstore/internal/store"
	"ngxops/logstore/pkg/wire"
)

const (
	adminTok = "test-admin-token-0123456789abcdef0123456789"
	pseudoK  = "0123456789abcdef0123456789abcdef"
)

type env struct {
	t     *testing.T
	ts    *httptest.Server
	st    *store.Store
	srv   *api.Server
	write string
	read  string
}

// newEnv : base de test réelle (LOGSTORE_TEST_DATABASE_URL), schéma remis à zéro.
func newEnv(t *testing.T, mut func(*config.Config)) *env {
	t.Helper()
	dsn := os.Getenv("LOGSTORE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LOGSTORE_TEST_DATABASE_URL non défini : test d'intégration ignoré")
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	c.Close(ctx)

	cfg := config.Config{
		DatabaseURL: dsn, DatabaseRead: dsn, DatabaseWrite: dsn, InsecureHTTP: true,
		IPMode: ipmode.Clear, RetentionDays: 30, PseudoKey: pseudoK,
		MaxBodyBytes: 4 << 20, MaxBatchEvents: 5000, RateRead: 1000, RateWrite: 1000, QueryTimeout: 15 * time.Second, UIEnabled: true,
	}
	if mut != nil {
		mut(&cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, store.Options{
		AdminURL: dsn, ReadURL: dsn, WriteURL: dsn, QueryTimeout: cfg.QueryTimeout,
		SeedRetentionDays: cfg.RetentionDays, SeedIPMode: cfg.IPMode, PseudoKeyPresent: true,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureBootstrapAdmin(ctx, auth.Hash(adminTok)); err != nil {
		t.Fatal(err)
	}
	srv := api.New(cfg, st, log)
	if err := srv.ReloadTokens(ctx); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, srv: srv, ts: httptest.NewServer(srv.Handler())}
	t.Cleanup(func() { e.ts.Close(); st.Close() })

	e.write = e.newToken("write", "web1")
	e.read = e.newToken("read", "")
	return e
}

func (e *env) newToken(role, inst string) string {
	e.t.Helper()
	body := fmt.Sprintf(`{"label":"t-%s","role":"%s","instance_id":%q}`, role, role, inst)
	if inst == "" {
		body = fmt.Sprintf(`{"label":"t-%s","role":"%s"}`, role, role)
	}
	code, b := e.do("POST", "/v1/tokens", adminTok, body, nil)
	if code != 201 {
		e.t.Fatalf("création jeton %s: %d %s", role, code, b)
	}
	var out struct{ Token string }
	_ = json.Unmarshal(b, &out)
	return out.Token
}

func (e *env) do(method, path, token, body string, hdr map[string]string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (e *env) get(path, token string) (int, map[string]any) {
	e.t.Helper()
	code, b := e.do("GET", path, token, "", nil)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return code, m
}

func ndjson(evs ...wire.Event) string {
	var sb strings.Builder
	for _, ev := range evs {
		b, _ := json.Marshal(ev)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func (e *env) ingest(key string, body string) (int, wire.Result) {
	e.t.Helper()
	code, b := e.do("POST", "/v1/ingest", e.write, body, map[string]string{wire.HeaderIdempotencyKey: key})
	var r wire.Result
	_ = json.Unmarshal(b, &r)
	return code, r
}

var base = time.Now().UTC().Add(-30 * time.Minute)

func acc(min int, ip, site, path string, status int, ua string) wire.Event {
	return wire.Event{TS: base.Add(time.Duration(min) * time.Minute), Source: "access", Action: "allowed", Site: site, IP: ip,
		Method: "GET", Path: path, Status: status, Bytes: 100, UA: ua, Country: "FR"}
}

func TestIngestIdempotenceAndRejects(t *testing.T) {
	e := newEnv(t, nil)
	body := ndjson(acc(1, "198.51.100.1", "a.example", "/", 200, "Mozilla")) +
		"{pas du json}\n" +
		ndjson(wire.Event{TS: base, Source: "nope", Action: "allowed"})

	code, r := e.ingest("batch-0001", body)
	if code != 200 || r.Accepted != 1 || r.RejectedTotal != 2 || r.Duplicate {
		t.Fatalf("1er envoi: %d %+v", code, r)
	}
	reasons := map[string]int{}
	for _, x := range r.Rejected {
		reasons[x.Reason] = x.Line
	}
	if reasons["bad_json"] != 2 || reasons["bad_source"] != 3 {
		t.Fatalf("lignes refusées mal numérotées: %+v", r.Rejected)
	}

	// Rejeu du même lot : aucune écriture
	code, r = e.ingest("batch-0001", body)
	if code != 200 || !r.Duplicate || r.Accepted != 0 {
		t.Fatalf("rejeu: %d %+v", code, r)
	}
	_, m := e.get("/v1/events", e.read)
	if n := len(m["events"].([]any)); n != 1 {
		t.Fatalf("attendu 1 événement après rejeu, obtenu %d", n)
	}

	// Les instances sont liées au jeton, jamais à l'événement
	_, m = e.get("/v1/instances", e.read)
	inst := m["instances"].([]any)
	if len(inst) != 1 || inst[0].(map[string]any)["id"] != "web1" || inst[0].(map[string]any)["events_total"].(float64) != 1 {
		t.Fatalf("instances: %v", inst)
	}
}

func TestIngestRequestErrors(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.MaxBodyBytes = 2048; c.MaxBatchEvents = 3 })
	ev := acc(1, "198.51.100.1", "a.example", "/", 200, "x")

	if code, _ := e.do("POST", "/v1/ingest", e.write, ndjson(ev), nil); code != 400 {
		t.Fatalf("sans Idempotency-Key: %d", code)
	}
	if code, _ := e.do("POST", "/v1/ingest", e.write, ndjson(ev), map[string]string{wire.HeaderIdempotencyKey: "court"}); code != 400 {
		t.Fatalf("clé trop courte: %d", code)
	}
	if code, _ := e.ingest("empty-0001", "\n\n"); code != 400 {
		t.Fatalf("lot vide: %d", code)
	}
	if code, _ := e.ingest("big-0001", ndjson(ev, ev, ev, ev)); code != 413 {
		t.Fatalf("trop d'événements: %d", code)
	}
	if code, _ := e.ingest("big-0002", strings.Repeat("x", 4096)); code != 413 {
		t.Fatalf("corps trop gros: %d", code)
	}

	// bombe gzip : petit une fois compressé, énorme décompressé
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(bytes.Repeat([]byte("a"), 64<<10)) // 64 Kio > 2 Kio × 8 ... plafond à 16 Kio
	_ = w.Close()
	code, _ := e.do("POST", "/v1/ingest", e.write, gz.String(), map[string]string{
		wire.HeaderIdempotencyKey: "bomb-0001", "Content-Encoding": "gzip"})
	if code != 413 {
		t.Fatalf("bombe gzip: %d", code)
	}
	if code, _ := e.do("POST", "/v1/ingest", e.write, "pas gzip", map[string]string{
		wire.HeaderIdempotencyKey: "bad-gz-0001", "Content-Encoding": "gzip"}); code != 400 {
		t.Fatalf("gzip invalide: %d", code)
	}

	// lot gzip valide
	gz.Reset()
	w = gzip.NewWriter(&gz)
	_, _ = w.Write([]byte(ndjson(ev)))
	_ = w.Close()
	code, b := e.do("POST", "/v1/ingest", e.write, gz.String(), map[string]string{
		wire.HeaderIdempotencyKey: "gzip-0001", "Content-Encoding": "gzip"})
	if code != 200 {
		t.Fatalf("gzip valide: %d %s", code, b)
	}
}

func TestQueriesAndStats(t *testing.T) {
	e := newEnv(t, nil)
	evs := []wire.Event{
		acc(1, "198.51.100.1", "a.example", "/", 200, "Mozilla/5.0"),
		acc(2, "198.51.100.1", "a.example", "/about", 200, "Mozilla/5.0"),
		acc(3, "198.51.100.2", "b.example", "/", 301, "curl/8"),
		acc(4, "198.51.100.2", "b.example", "/x", 500, "curl/8"),
		{TS: base.Add(9 * time.Minute), Source: "waf", Action: "blocked", Site: "a.example", IP: "203.0.113.9", Path: "/wp-login.php", Rule: "942100"},
	}
	for i, p := range []string{"/.env", "/admin", "/wp-admin", "/.git/config", "/phpmyadmin"} { // scanner
		evs = append(evs, acc(10+i, "203.0.113.9", "a.example", p, 404, "zgrab"))
	}
	if code, r := e.ingest("batch-q-0001", ndjson(evs...)); code != 200 || r.Accepted != len(evs) {
		t.Fatalf("ingestion: %d %+v", code, r)
	}

	count := func(q string) int {
		t.Helper()
		code, m := e.get("/v1/events?limit=500&"+q, e.read)
		if code != 200 {
			t.Fatalf("%s: %d %v", q, code, m)
		}
		return len(m["events"].([]any))
	}
	checks := map[string]int{
		"": len(evs), "site=b.example": 2, "site=B.Example": 2, "status=404": 5, "status=4xx": 5, "status=5xx": 1,
		"source=waf": 1, "action=blocked": 1, "ip=198.51.100.1": 2, "ua=curl": 2, "ua=CURL": 2, "path=wp-": 2,
		"instance=web1": len(evs), "instance=autre": 0, "source=access&status=2xx": 2,
	}
	for q, want := range checks {
		if got := count(q); got != want {
			t.Errorf("filtre %q: attendu %d, obtenu %d", q, want, got)
		}
	}

	// pagination par curseur : ordre décroissant, sans doublon ni trou
	seen := map[float64]bool{}
	var last string
	cursor := ""
	pages := 0
	for {
		code, m := e.get("/v1/events?limit=4&cursor="+cursor, e.read)
		if code != 200 {
			t.Fatalf("page: %d %v", code, m)
		}
		for _, x := range m["events"].([]any) {
			ev := x.(map[string]any)
			id := ev["id"].(float64)
			if seen[id] {
				t.Fatalf("doublon %v", id)
			}
			seen[id] = true
			ts := ev["ts"].(string)
			if last != "" && ts > last {
				t.Fatalf("ordre non décroissant: %s après %s", ts, last)
			}
			last = ts
		}
		pages++
		if m["next_cursor"] == nil {
			break
		}
		cursor = m["next_cursor"].(string)
	}
	if len(seen) != len(evs) || pages != 3 {
		t.Fatalf("pagination: %d événements en %d pages", len(seen), pages)
	}

	// historique d'IP
	_, m := e.get("/v1/ips/203.0.113.9", e.read)
	sum := m["summary"].(map[string]any)
	if sum["total"].(float64) != 6 || len(sum["by_source_action"].([]any)) != 2 {
		t.Fatalf("historique IP: %v", sum)
	}

	// visites (vue de cumul) : seulement la source access, par défaut
	_, m = e.get("/v1/stats/visits?bucket=hour&since=3h", e.read)
	var req, s4, s5 float64
	var visitors float64
	for _, p := range m["points"].([]any) {
		pt := p.(map[string]any)
		req += pt["requests"].(float64)
		s4 += pt["s4xx"].(float64)
		s5 += pt["s5xx"].(float64)
		if v, ok := pt["visitors"].(float64); ok {
			visitors += v
		}
	}
	if req != 9 || s4 != 5 || s5 != 1 || visitors < 3 {
		t.Fatalf("visites: req=%v 4xx=%v 5xx=%v visiteurs=%v (%v)", req, s4, s5, visitors, m)
	}

	// top
	_, m = e.get("/v1/stats/top?dimension=ua&limit=1", e.read)
	top := m["items"].([]any)[0].(map[string]any)
	if top["key"] != "zgrab" || top["count"].(float64) != 5 {
		t.Fatalf("top ua: %v", top)
	}
	if code, _ := e.get("/v1/stats/top?dimension=password", e.read); code != 400 {
		t.Fatalf("dimension hors liste blanche: %d", code)
	}

	// sécurité : le scanner ressort, pas les visiteurs normaux
	_, m = e.get("/v1/stats/security?min_paths=3", e.read)
	sc := m["scanners"].([]any)
	if len(sc) != 1 || sc[0].(map[string]any)["key"] != "203.0.113.9" || sc[0].(map[string]any)["distinct_paths"].(float64) != 5 {
		t.Fatalf("scanners: %v", sc)
	}
	if bl := m["blocked"].([]any); len(bl) != 1 || bl[0].(map[string]any)["source"] != "waf" {
		t.Fatalf("blocked: %v", bl)
	}

	// paramètres invalides
	for _, q := range []string{"from=hier", "since=0s", "status=999", "source=x", "action=x", "limit=0", "limit=9999", "cursor=%%%", "ip=pasune-ip"} {
		if code, _ := e.get("/v1/events?"+q, e.read); code != 400 {
			t.Errorf("%s: attendu 400, obtenu %d", q, code)
		}
	}
	if code, _ := e.get("/v1/events?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z", e.read); code != 400 {
		t.Errorf("fenêtre > 31 j: %d", code)
	}
}

func TestSQLInjectionIsInert(t *testing.T) {
	e := newEnv(t, nil)
	e.ingest("batch-i-0001", ndjson(acc(1, "198.51.100.1", "a.example", "/", 200, "x")))
	for _, q := range []string{
		"site=" + "a'%3B+DROP+TABLE+events%3B--", "ua=%27+OR+1%3D1--", "path=%25%27%3B--", "status=200%27+OR+%271%27%3D%271",
	} {
		code, _ := e.get("/v1/events?"+q, e.read)
		if code != 200 && code != 400 {
			t.Fatalf("%s: %d", q, code)
		}
	}
	_, m := e.get("/v1/events", e.read)
	if len(m["events"].([]any)) != 1 {
		t.Fatal("la table doit être intacte")
	}
}

func TestAuthAndRoles(t *testing.T) {
	e := newEnv(t, nil)
	ev := ndjson(acc(1, "198.51.100.1", "a.example", "/", 200, "x"))

	if code, _ := e.do("GET", "/v1/events", "", "", nil); code != 401 {
		t.Fatalf("sans jeton: %d", code)
	}
	if code, _ := e.do("GET", "/v1/events", "lgs_faux", "", nil); code != 401 {
		t.Fatalf("faux jeton: %d", code)
	}
	if code, _ := e.do("POST", "/v1/ingest", e.read, ev, map[string]string{wire.HeaderIdempotencyKey: "role-0001"}); code != 403 {
		t.Fatalf("read sur ingest: %d", code)
	}
	if code, _ := e.do("GET", "/v1/events", e.write, "", nil); code != 403 {
		t.Fatalf("write sur events: %d", code)
	}
	if code, _ := e.do("PUT", "/v1/settings", e.read, `{"retention_days":10}`, nil); code != 403 {
		t.Fatalf("read sur settings PUT: %d", code)
	}
	if code, _ := e.do("GET", "/v1/tokens", e.read, "", nil); code != 403 {
		t.Fatalf("read sur tokens: %d", code)
	}
	if code, _ := e.do("GET", "/v1/events", adminTok, "", nil); code != 200 {
		t.Fatalf("admin peut lire: %d", code)
	}
	if code, _ := e.do("POST", "/v1/ingest", adminTok, ev, map[string]string{wire.HeaderIdempotencyKey: "role-0002"}); code != 403 {
		t.Fatalf("admin ne doit pas écrire d'événements: %d", code)
	}

	// santé : publique, détail seulement avec jeton de lecture
	code, m := e.get("/v1/health", "")
	if code != 200 || m["detail"] != nil {
		t.Fatalf("health public: %d %v", code, m)
	}
	if _, m = e.get("/v1/health", e.read); m["detail"] == nil {
		t.Fatalf("health détaillé attendu: %v", m)
	}

	// validation de création de jetons
	bad := []string{
		`{"label":"","role":"read"}`, `{"label":"x","role":"root"}`, `{"label":"x","role":"write"}`,
		`{"label":"x","role":"write","instance_id":"Bad Name"}`,
		`{"label":"x","role":"read","extra":1}`, `pas du json`,
	}
	for _, b := range bad {
		if code, _ := e.do("POST", "/v1/tokens", adminTok, b, nil); code != 400 {
			t.Errorf("%s: attendu 400, obtenu %d", b, code)
		}
	}

	// révocation immédiate + liste sans jeton ni empreinte
	code, b := e.do("GET", "/v1/tokens", adminTok, "", nil)
	if code != 200 || bytes.Contains(b, []byte("hash")) || bytes.Contains(b, []byte(e.read)) || bytes.Contains(b, []byte(adminTok)) {
		t.Fatalf("la liste ne doit exposer ni jeton ni empreinte: %d %s", code, b)
	}
	var list struct{ Tokens []store.TokenRow }
	_ = json.Unmarshal(b, &list)
	var readID, adminID int64
	for _, tk := range list.Tokens {
		switch tk.Label {
		case "t-read":
			readID = tk.ID
		case "bootstrap":
			adminID = tk.ID
		}
	}
	if code, _ := e.do("DELETE", fmt.Sprintf("/v1/tokens/%d", readID), adminTok, "", nil); code != 204 {
		t.Fatalf("révocation: %d", code)
	}
	if code, _ := e.do("GET", "/v1/events", e.read, "", nil); code != 401 {
		t.Fatalf("jeton révoqué encore accepté: %d", code)
	}
	if code, _ := e.do("DELETE", fmt.Sprintf("/v1/tokens/%d", readID), adminTok, "", nil); code != 404 {
		t.Fatalf("double révocation: %d", code)
	}
	if code, _ := e.do("DELETE", fmt.Sprintf("/v1/tokens/%d", adminID), adminTok, "", nil); code != 409 {
		t.Fatalf("le dernier admin ne doit pas être révocable: %d", code)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.RateRead = 1 }) // burst 3
	var limited bool
	for i := 0; i < 8; i++ {
		req, _ := http.NewRequest("GET", e.ts.URL+"/v1/instances", nil)
		req.Header.Set("Authorization", "Bearer "+e.read)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if resp.StatusCode == 429 {
			if resp.Header.Get("Retry-After") == "" {
				t.Fatal("Retry-After attendu")
			}
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("429 attendu")
	}
}

func TestAuthFailureThrottle(t *testing.T) {
	e := newEnv(t, nil)
	var got429 bool
	for i := 0; i < 60; i++ {
		code, _ := e.do("GET", "/v1/events", "lgs_devine", "", nil)
		if code == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("les échecs d'authentification répétés doivent être freinés")
	}
}

func TestSettingsAndIPModes(t *testing.T) {
	e := newEnv(t, nil)
	put := func(body string) (int, map[string]any) {
		code, b := e.do("PUT", "/v1/settings", adminTok, body, nil)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return code, m
	}
	if code, m := e.get("/v1/settings", e.read); code != 200 || m["retention_days"].(float64) != 30 || m["ip_mode"] != "clear" || m["timescale"] != false {
		t.Fatalf("réglages par défaut: %d %v", code, m)
	}
	for _, b := range []string{`{"retention_days":3}`, `{"retention_days":90}`, `{"agg_retention_days":1}`, `{"ip_mode":"x"}`, `{"inconnu":1}`} {
		if code, _ := put(b); code != 400 {
			t.Errorf("%s: attendu 400, obtenu %d", b, code)
		}
	}
	if code, m := put(`{"retention_days":14}`); code != 200 || m["retention_days"].(float64) != 14 {
		t.Fatalf("PUT: %d %v", code, m)
	}

	// mode tronqué
	put(`{"ip_mode":"truncated"}`)
	e.ingest("mode-trunc-01", ndjson(acc(1, "198.51.100.77", "a.example", "/", 200, "x")))
	_, m := e.get("/v1/events?ip=198.51.100.200", e.read) // même /24
	evs := m["events"].([]any)
	if len(evs) != 1 || evs[0].(map[string]any)["ip"] != "198.51.100.0/24" {
		t.Fatalf("mode tronqué: %v", evs)
	}

	// mode pseudonymisé : plus d'adresse en base, recherche par IP toujours possible
	put(`{"ip_mode":"pseudonymized"}`)
	e.ingest("mode-pseudo-01", ndjson(acc(2, "192.0.2.55", "a.example", "/", 200, "x")))
	_, m = e.get("/v1/events?ip=192.0.2.55", e.read)
	evs = m["events"].([]any)
	if len(evs) != 1 {
		t.Fatalf("recherche par IP en mode pseudonymisé: %v", evs)
	}
	row := evs[0].(map[string]any)
	if row["ip"] != nil || row["ip_key"] == nil || strings.Contains(fmt.Sprint(row), "192.0.2.55") {
		t.Fatalf("l'adresse ne doit plus apparaître: %v", row)
	}
	_, m = e.get("/v1/ips/"+row["ip_key"].(string), e.read) // accès direct par clé
	if m["summary"].(map[string]any)["total"].(float64) != 1 || m["ip_mode"] != "pseudonymized" {
		t.Fatalf("historique par clé: %v", m)
	}
}

func TestPseudonymizedRequiresKey(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.PseudoKey = "" })
	code, b := e.do("PUT", "/v1/settings", adminTok, `{"ip_mode":"pseudonymized"}`, nil)
	if code != 409 || !bytes.Contains(b, []byte("pseudonymization_key_missing")) {
		t.Fatalf("attendu 409 sans clé: %d %s", code, b)
	}
}

func TestErrorsLeakNothing(t *testing.T) {
	e := newEnv(t, nil)
	for _, p := range []string{"/v1/events?from=x", "/v1/inexistant", "/v1/ips/%00"} {
		_, b := e.do("GET", p, e.read, "", nil)
		for _, bad := range []string{"postgres", "SQLSTATE", "pgx", e.read, adminTok} {
			if bytes.Contains(b, []byte(bad)) {
				t.Fatalf("%s: la réponse contient %q : %s", p, bad, b)
			}
		}
	}
}

// #62 : corrélation par IP entre instances et sources (jeton read, fenêtre ≤ 7 j, aucun chemin ni UA dans la réponse).
func TestIPCorrelation(t *testing.T) {
	e := newEnv(t, nil)
	w2 := e.newToken("write", "web2")
	ev := func(min int, src, act, ip string) wire.Event {
		return wire.Event{TS: base.Add(time.Duration(min) * time.Minute), Source: src, Action: act, Site: "a.example", IP: ip, Path: "/secret-path", UA: "secret-agent", Status: 404}
	}
	if code, r := e.ingest("batch-c-0001", ndjson(
		ev(1, "access", "allowed", "203.0.113.9"), ev(2, "access", "allowed", "203.0.113.9"), ev(3, "access", "allowed", "198.51.100.5"),
		ev(4, "access", "allowed", "192.0.2.77"), ev(5, "waf", "blocked", "192.0.2.77"), ev(6, "challenge", "challenged", "192.0.2.77"))); code != 200 || r.Accepted != 6 {
		t.Fatalf("ingestion web1: %d %+v", code, r)
	}
	body := ndjson(ev(7, "waf", "blocked", "203.0.113.9"))
	req, _ := http.NewRequest("POST", e.ts.URL+"/v1/ingest", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+w2)
	req.Header.Set(wire.HeaderIdempotencyKey, "batch-c-0002")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("ingestion web2: %v %v", err, resp)
	}

	code, m := e.get("/v1/stats/ips?since=2h&min_instances=2", e.read)
	if code != 200 {
		t.Fatalf("ips: %d %v", code, m)
	}
	items := m["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("attendu 1 IP vue par 2 instances, obtenu %v", items)
	}
	x := items[0].(map[string]any)
	if x["key"] != "203.0.113.9" || x["instance_count"].(float64) != 2 || x["blocked"].(float64) != 1 || x["events"].(float64) != 3 {
		t.Fatalf("agrégat inattendu: %v", x)
	}
	if got := fmt.Sprint(x["instances"]); got != "[web1 web2]" {
		t.Fatalf("instances: %s", got)
	}
	_, raw := e.do("GET", "/v1/stats/ips?since=2h&min_instances=1", e.read, "", nil)
	if strings.Contains(string(raw), "secret-path") || strings.Contains(string(raw), "secret-agent") {
		t.Fatalf("chemin/UA exposés: %s", raw)
	}

	// une seule instance mais trois sources distinctes
	_, m = e.get("/v1/stats/ips?since=2h&min_instances=1&min_sources=3", e.read)
	items = m["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["key"] != "192.0.2.77" {
		t.Fatalf("min_sources=3: %v", items)
	}

	if code, _ := e.get("/v1/stats/ips?since=200h", e.read); code != 400 {
		t.Fatalf("fenêtre > 7 j doit être refusée: %d", code)
	}
	if code, _ := e.get("/v1/stats/ips?min_instances=0", e.read); code != 400 {
		t.Fatalf("min_instances=0 doit être refusé: %d", code)
	}
	if code, _ := e.get("/v1/stats/ips", e.write); code != 403 {
		t.Fatalf("jeton write ne doit pas lire: %d", code)
	}
	if code, _ := e.get("/v1/stats/ips", ""); code != 401 {
		t.Fatalf("sans jeton: %d", code)
	}
}

// #107 : campagnes = (règle, chemin) vus depuis plusieurs IP ; aucune IP en sortie.
func TestCampaigns(t *testing.T) {
	e := newEnv(t, nil)
	ev := func(min int, ip, rule string) wire.Event {
		return wire.Event{TS: base.Add(time.Duration(min) * time.Minute), Source: "waf", Action: "blocked", Site: "a.example", IP: ip, Path: "/wp-login.php", Rule: rule, Status: 403}
	}
	if code, r := e.ingest("batch-camp-01", ndjson(ev(1, "203.0.113.1", "wp-login"), ev(2, "203.0.113.2", "wp-login"), ev(3, "203.0.113.3", "wp-login"), ev(4, "198.51.100.9", "other"))); code != 200 || r.Accepted != 4 {
		t.Fatalf("ingestion: %d %+v", code, r)
	}
	code, m := e.get("/v1/stats/campaigns?since=2h&min_ips=3", e.read)
	items, _ := m["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("attendu 1 campagne: %d %v", code, m)
	}
	x := items[0].(map[string]any)
	if x["rule"] != "wp-login" || x["ip_count"].(float64) != 3 || x["blocked"].(float64) != 3 {
		t.Fatalf("agrégat inattendu: %v", x)
	}
	if _, raw := e.do("GET", "/v1/stats/campaigns?since=2h&min_ips=2", e.read, "", nil); strings.Contains(string(raw), "203.0.113") {
		t.Fatalf("IP exposée: %s", raw)
	}
	if code, _ := e.get("/v1/stats/campaigns?since=200h", e.read); code != 400 {
		t.Fatalf("fenêtre > 7 j: %d", code)
	}
	if code, _ := e.get("/v1/stats/campaigns?min_ips=1", e.read); code != 400 {
		t.Fatalf("min_ips=1: %d", code)
	}
	if code, _ := e.get("/v1/stats/campaigns", e.write); code != 403 {
		t.Fatalf("jeton write: %d", code)
	}
}

// #89 : un jeton read lié à une instance ne voit que cette instance.
func TestScopedReadToken(t *testing.T) {
	e := newEnv(t, nil)
	w2 := e.newToken("write", "web2")
	ev := func(min int, ip string) wire.Event {
		return wire.Event{TS: base.Add(time.Duration(min) * time.Minute), Source: "access", Action: "allowed", Site: "a.example", IP: ip, Path: "/p", UA: "ua", Status: 200}
	}
	if code, r := e.ingest("batch-s-0001", ndjson(ev(1, "203.0.113.9"), ev(2, "203.0.113.10"))); code != 200 || r.Accepted != 2 {
		t.Fatalf("ingestion web1: %d %+v", code, r)
	}
	req, _ := http.NewRequest("POST", e.ts.URL+"/v1/ingest", strings.NewReader(ndjson(ev(3, "198.51.100.5"))))
	req.Header.Set("Authorization", "Bearer "+w2)
	req.Header.Set(wire.HeaderIdempotencyKey, "batch-s-0002")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("ingestion web2: %v %v", err, resp)
	}
	scoped := e.newToken("read", "web2")

	_, m := e.get("/v1/events?since=2h", scoped)
	evs := m["events"].([]any)
	if len(evs) != 1 || evs[0].(map[string]any)["instance_id"] != "web2" {
		t.Fatalf("le jeton limité doit ne voir que web2: %v", evs)
	}
	if _, m = e.get("/v1/events?since=2h", e.read); len(m["events"].([]any)) != 3 {
		t.Fatalf("le jeton read global voit tout: %v", m["events"])
	}
	if code, _ := e.get("/v1/events?since=2h&instance=web1", scoped); code != 403 {
		t.Fatalf("instance étrangère explicitement demandée: %d", code)
	}
	if code, _ := e.get("/v1/events?since=2h&instance=web2", scoped); code != 200 {
		t.Fatalf("sa propre instance: %d", code)
	}
	// fiche IP : l'IP vue par web1 seulement est invisible
	_, m = e.get("/v1/ips/203.0.113.9?since=2h", scoped)
	if got := m["events"].([]any); len(got) != 0 {
		t.Fatalf("IP d'une autre instance visible: %v", got)
	}
	_, m = e.get("/v1/stats/top?since=2h&dimension=ip", scoped)
	if got := fmt.Sprint(m["items"]); strings.Contains(got, "203.0.113") {
		t.Fatalf("top : IP d'une autre instance: %s", got)
	}
	_, m = e.get("/v1/stats/visits?since=2h&bucket=hour", scoped)
	var total float64
	for _, p := range m["points"].([]any) {
		total += p.(map[string]any)["requests"].(float64)
	}
	if total != 1 {
		t.Fatalf("visites : seulement web2 (1 événement), obtenu %v (%v)", total, m["points"])
	}
	_, m = e.get("/v1/instances", scoped)
	if in := m["instances"].([]any); len(in) != 1 || in[0].(map[string]any)["id"] != "web2" {
		t.Fatalf("instances: %v", in)
	}
	if code, _ := e.get("/v1/stats/ips?since=2h", scoped); code != 403 {
		t.Fatalf("corrélation inter-instances interdite au jeton limité: %d", code)
	}
	if code, _ := e.get("/v1/stats/security?since=2h", scoped); code != 200 {
		t.Fatalf("security: %d", code)
	}
	// instance_id invalide ou sur admin : refusé
	if code, _ := e.do("POST", "/v1/tokens", adminTok, `{"label":"x","role":"read","instance_id":"../x"}`, nil); code != 400 {
		t.Fatalf("instance_id invalide: %d", code)
	}
	if code, _ := e.do("POST", "/v1/tokens", adminTok, `{"label":"x","role":"admin","instance_id":"web2"}`, nil); code != 400 {
		t.Fatalf("admin limité interdit: %d", code)
	}
}

// #91 : interface web de gestion des jetons (fichiers statiques, CSP stricte, sans secret).
func TestTokenUI(t *testing.T) {
	e := newEnv(t, nil)
	for _, p := range []string{"/ui/", "/ui/app.js", "/ui/style.css"} {
		resp, err := http.Get(e.ts.URL + p)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", p, err, resp)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Fatalf("%s: CSP trop permissive: %q", p, csp)
		}
		if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: en-têtes de sécurité manquants", p)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if p == "/ui/" && (strings.Contains(string(b), "<script>") || strings.Contains(string(b), "onclick=")) {
			t.Fatal("la page ne doit contenir aucun script inline")
		}
		if strings.Contains(string(b), adminTok) {
			t.Fatalf("%s: le jeton admin ne doit jamais figurer dans la page", p)
		}
	}
	if resp, _ := http.Get(e.ts.URL + "/ui/autre"); resp == nil || resp.StatusCode != 404 {
		t.Fatalf("chemin inconnu sous /ui/ doit renvoyer 404")
	}
	// L'interface n'ouvre aucun accès : l'API reste protégée.
	if code, _ := e.get("/v1/tokens", ""); code != 401 {
		t.Fatalf("/v1/tokens sans jeton: %d", code)
	}
	off := newEnv(t, func(c *config.Config) { c.UIEnabled = false })
	if resp, _ := http.Get(off.ts.URL + "/ui/"); resp == nil || resp.StatusCode != 404 {
		t.Fatalf("LOGSTORE_UI=false doit couper l'interface")
	}
}

func TestMaintenanceAPI(t *testing.T) {
	e := newEnv(t, nil)
	if code, _ := e.get("/v1/maintenance", e.read); code != 403 {
		t.Fatalf("lecture seule: attendu 403, obtenu %d", code)
	}
	if code, _ := e.do("POST", "/v1/maintenance", e.read, "", nil); code != 403 {
		t.Fatalf("POST avec jeton read: attendu 403, obtenu %d", code)
	}
	code, m := e.get("/v1/maintenance", adminTok)
	if code != 200 {
		t.Fatalf("GET admin: %d %v", code, m)
	}
	st := m["status"].(map[string]any)
	if st["running"] != false || len(st["tables"].([]any)) == 0 {
		t.Fatalf("état: %v", st)
	}
	if cs, _ := m["checks"].([]any); len(cs) == 0 {
		t.Fatalf("vérifications absentes: %v", m)
	}
	if code, _ := e.do("POST", "/v1/maintenance", adminTok, "", nil); code != 202 {
		t.Fatalf("POST admin: attendu 202, obtenu %d", code)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		_, m = e.get("/v1/maintenance", adminTok)
		st = m["status"].(map[string]any)
		if st["running"] == false && st["last"] != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("maintenance non terminée: %v", st)
		}
		time.Sleep(100 * time.Millisecond)
	}
	last := st["last"].(map[string]any)
	if last["trigger"] != "manual" || last["error"] != nil {
		t.Fatalf("dernier passage: %v", last)
	}
}
