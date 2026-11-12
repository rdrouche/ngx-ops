package shipper

import (
	"net/http/httptest"
	"strings"
	"testing"

	"nginx-analyzer-go/internal/wire"
)

func apiFor(t *testing.T) (*LocalAPI, *flaky) {
	f := &flaky{}
	return NewLocalAPI(ltok, f, func() any { return map[string]any{"ok": true} }), f
}

func do(a *LocalAPI, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func TestAPIHealthzIsOpen(t *testing.T) {
	a, _ := apiFor(t)
	if w := do(a, "GET", "/healthz", "", ""); w.Code != 200 {
		t.Fatalf("healthz = %d", w.Code)
	}
}

func TestAPIRequiresToken(t *testing.T) {
	a, _ := apiFor(t)
	for _, c := range []struct{ m, p string }{{"GET", "/status"}, {"POST", "/v1/events"}} {
		if w := do(a, c.m, c.p, "", ""); w.Code != 401 {
			t.Fatalf("%s %s sans jeton = %d", c.m, c.p, w.Code)
		}
		if w := do(a, c.m, c.p, "mauvais-jeton-0123456789-abcdef", ""); w.Code != 401 {
			t.Fatalf("%s %s mauvais jeton = %d", c.m, c.p, w.Code)
		}
	}
	if a.AuthFail.Load() != 4 {
		t.Fatalf("échecs comptés = %d", a.AuthFail.Load())
	}
}

func TestAPIAcceptsDecisionsDurably(t *testing.T) {
	a, f := apiFor(t)
	body := `{"source":"waf","action":"blocked","ip":"198.51.100.1","path":"/x","rule":"942100"}` + "\n" +
		`{"source":"blocklist","action":"blocked","ip":"198.51.100.2"}` + "\n"
	w := do(a, "POST", "/v1/events", ltok, body)
	if w.Code != 202 {
		t.Fatalf("code = %d : %s", w.Code, w.Body.String())
	}
	if len(f.units) != 1 || len(f.units[0]) != 2 {
		t.Fatalf("unités = %v", f.units)
	}
	if f.units[0][0].TS.IsZero() {
		t.Fatal("ts non complété")
	}
	if f.metas[0] != "" {
		t.Fatalf("meta inattendue pour une entrée locale : %q", f.metas[0])
	}
}

func TestAPIRejectsAccessSourceAndBadLines(t *testing.T) {
	a, f := apiFor(t)
	body := `{"source":"access","action":"allowed"}` + "\n" +
		`pas du json` + "\n" +
		`{"source":"zzz","action":"blocked"}` + "\n" +
		`{"source":"waf","action":"zzz"}` + "\n" +
		`{"source":"challenge","action":"challenged","ip":"198.51.100.3"}` + "\n"
	w := do(a, "POST", "/v1/events", ltok, body)
	if w.Code != 202 || len(f.units) != 1 || len(f.units[0]) != 1 || f.units[0][0].Source != wire.SourceChallenge {
		t.Fatalf("code=%d unités=%v corps=%s", w.Code, f.units, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "réservée") {
		t.Fatalf("raison absente : %s", w.Body.String())
	}
	if a.Rejected.Load() != 4 {
		t.Fatalf("rejets = %d", a.Rejected.Load())
	}
}

func TestAPIAllRejectedIs400(t *testing.T) {
	a, f := apiFor(t)
	if w := do(a, "POST", "/v1/events", ltok, `{"source":"access","action":"allowed"}`+"\n"); w.Code != 400 {
		t.Fatalf("code = %d", w.Code)
	}
	if len(f.units) != 0 {
		t.Fatal("commit inattendu")
	}
}

func TestAPIBufferFailureIs503(t *testing.T) {
	a, f := apiFor(t)
	f.set(true)
	if w := do(a, "POST", "/v1/events", ltok, `{"source":"waf","action":"blocked"}`+"\n"); w.Code != 503 {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestAPILimits(t *testing.T) {
	a, _ := apiFor(t)
	big := `{"source":"waf","action":"blocked","path":"` + strings.Repeat("a", 70<<10) + `"}` + "\n"
	if w := do(a, "POST", "/v1/events", ltok, big); w.Code != 413 {
		t.Fatalf("ligne trop longue = %d", w.Code)
	}
	many := strings.Repeat(`{"source":"waf","action":"blocked"}`+"\n", maxLocalEvents+1)
	if w := do(a, "POST", "/v1/events", ltok, many); w.Code != 413 {
		t.Fatalf("trop d'événements = %d", w.Code)
	}
	if w := do(a, "GET", "/v1/events", ltok, ""); w.Code != 405 {
		t.Fatalf("méthode = %d", w.Code)
	}
}
