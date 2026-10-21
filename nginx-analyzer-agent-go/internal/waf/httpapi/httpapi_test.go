package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"nginx-analyzer-go/internal/waf/crs"
	"nginx-analyzer-go/internal/waf/service"
	"nginx-analyzer-go/internal/waf/wtest"
)

const tok = "s3cret-token"

// failTransport : aucun acces reseau dans les tests.
type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}

type fx struct {
	svc  *service.Service
	srv  *httptest.Server
	logs string
}

func setup(t *testing.T) *fx {
	t.Helper()
	logs := t.TempDir()
	svc, err := service.New(service.Config{
		Version: "9.9.9", LogsDir: logs, DataDir: t.TempDir(), RulesDir: wtest.MiniRules(t), CRSVersion: "v4.8.0",
		LogPattern: regexp.MustCompile(`(^|[._])access\.log$`), WafLogPattern: regexp.MustCompile(`(^|[._-])wafemu\.log$`), PollMs: 20,
		Downloader: &crs.Downloader{Client: &http.Client{Transport: failTransport{}}, AllowedHosts: crs.DefaultAllowedHosts, Template: crs.DefaultURLTemplate, MaxBytes: crs.MaxDownloadBytes},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	svc.Start()
	for i := 0; i < 500 && svc.Status(t.Context()).Engine.Ready == false; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	srv := httptest.NewServer(New(svc, tok))
	t.Cleanup(srv.Close)
	return &fx{svc: svc, srv: srv, logs: logs}
}

func (f *fx) do(t *testing.T, method, path, body string, hdr map[string]string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, f.srv.URL+path, strings.NewReader(body))
	if hdr == nil {
		hdr = map[string]string{"X-WAF-Token": tok}
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (f *fx) json(t *testing.T, method, path, body string, want int) map[string]any {
	t.Helper()
	code, b, _ := f.do(t, method, path, body, nil)
	if code != want {
		t.Fatalf("%s %s : HTTP %d (attendu %d) : %s", method, path, code, want, b)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(b), &m); err != nil {
		t.Fatalf("%s %s : JSON invalide %q", method, path, b)
	}
	return m
}

func TestAuthAndRouting(t *testing.T) {
	f := setup(t)
	// sante sans token
	code, b, _ := f.do(t, "GET", "/api/health", "", map[string]string{})
	if code != 200 || !strings.Contains(b, `"status":"ok"`) || !strings.Contains(b, "9.9.9") {
		t.Fatalf("health: %d %s", code, b)
	}
	for _, p := range []string{"/api/status", "/api/settings", "/api/rules", "/api/hits", "/api/lists", "/api/alerts"} {
		for _, h := range []map[string]string{{}, {"X-WAF-Token": "mauvais"}, {"X-WAF-Token": tok + "x"}, {"X-WAF-Token": ""}, {"Authorization": "Bearer " + tok}} {
			if code, b, _ := f.do(t, "GET", p, "", h); code != 401 || !strings.Contains(b, `"error"`) {
				t.Errorf("%s %v : %d %s", p, h, code, b)
			}
		}
	}
	if code, _, _ := f.do(t, "PUT", "/api/settings", `{}`, map[string]string{}); code != 401 {
		t.Error("PUT sans token")
	}
	if code, b, _ := f.do(t, "GET", "/api/inconnu", "", nil); code != 404 || !strings.Contains(b, "error") {
		t.Errorf("404: %d %s", code, b)
	}
	code, b, h := f.do(t, "DELETE", "/api/settings", "", nil)
	if code != 405 || h.Get("Allow") == "" || !strings.Contains(b, "error") {
		t.Errorf("405: %d %s", code, b)
	}
	if code, _, h := f.do(t, "GET", "/api/status", "", nil); code != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/json") || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("en-tetes")
	}
	// sans token configure : pas d'authentification
	srv2 := httptest.NewServer(New(f.svc, ""))
	defer srv2.Close()
	resp, _ := http.Get(srv2.URL + "/api/status")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Error("token vide = pas d'auth")
	}
}

func TestStatusShape(t *testing.T) {
	f := setup(t)
	m := f.json(t, "GET", "/api/status", "", 200)
	for _, k := range []string{"version", "engine", "enabled", "crs", "effectiveParanoia", "logs", "vhostsSeen", "unreliableRules", "stats24h", "memory"} {
		if _, ok := m[k]; !ok {
			t.Errorf("cle manquante: %s", k)
		}
	}
	eng := m["engine"].(map[string]any)
	if eng["name"] != "coraza" || eng["ready"] != true || eng["error"] != nil {
		t.Errorf("engine: %v", eng)
	}
	crsM := m["crs"].(map[string]any)
	if crsM["installed"] != true || crsM["downloading"] != false {
		t.Errorf("crs: %v", crsM)
	}
	if _, ok := crsM["filesIgnored"].([]any); !ok {
		t.Error("filesIgnored doit etre un tableau")
	}
	logs := m["logs"].(map[string]any)
	for _, k := range []string{"files", "formats", "linesRead", "linesAnalyzed", "dropped", "linesPerSecond"} {
		if _, ok := logs[k]; !ok {
			t.Errorf("logs.%s", k)
		}
	}
	for _, k := range []string{"requests", "hits", "ips", "avgEvalMs"} {
		if _, ok := m["stats24h"].(map[string]any)[k]; !ok {
			t.Errorf("stats24h.%s", k)
		}
	}
	if m["memory"].(map[string]any)["rss"] == nil {
		t.Error("memory.rss")
	}
	u := m["unreliableRules"].(map[string]any)
	if _, ok := u["combined"].([]any); !ok {
		t.Error("unreliableRules.combined")
	}
}

func TestSettingsEndpoint(t *testing.T) {
	f := setup(t)
	s := f.json(t, "GET", "/api/settings", "", 200)
	if s["mode"] != "observe" || s["paranoia"] != float64(1) {
		t.Fatalf("defauts: %v", s)
	}
	s = f.json(t, "PUT", "/api/settings", `{"mode":"remediate","disabledRules":[942100,920350],"thresholds":{"challenge":8,"block":20},"exceptions":[{"rule":942100,"vhost":"Blog.example.com","pathPrefix":"/wp-admin/","reason":"x"}]}`, 200)
	if s["mode"] != "remediate" || len(s["disabledRules"].([]any)) != 2 {
		t.Fatalf("PUT: %v", s)
	}
	ex := s["exceptions"].([]any)[0].(map[string]any)
	if ex["id"] == "" || ex["vhost"] != "blog.example.com" || ex["createdAt"] == "" {
		t.Fatalf("exception normalisee: %v", ex)
	}
	if g := f.json(t, "GET", "/api/settings", "", 200); g["mode"] != "remediate" {
		t.Fatal("GET apres PUT")
	}
	bads := []string{
		`{"mode":"x"}`, `{"paranoia":0}`, `{"foo":1}`, `{"thresholds":{"challenge":5,"block":2}}`, `{"disabledRules":["a"]}`, `{"vhosts":{"bad name":{}}}`,
		`{"exceptions":[{"rule":1,"ip":"nope"}]}`, `{"excludeIps":["300.1.1.1"]}`, `[`, ``, `{"ignoreStatus":[7]}`, `{"mode":"observe"} x`,
	}
	for _, b := range bads {
		m := f.json(t, "PUT", "/api/settings", b, 400)
		if m["error"] == "" || m["error"] == nil {
			t.Errorf("%s : message d'erreur attendu", b)
		}
	}
	// aucun PUT invalide n'a modifie l'etat
	if g := f.json(t, "GET", "/api/settings", "", 200); g["mode"] != "remediate" {
		t.Fatal("etat altere")
	}
	// corps trop gros
	code, _, _ := f.do(t, "PUT", "/api/settings", `{"excludeIps":["`+strings.Repeat("1", 2<<20)+`"]}`, nil)
	if code != 413 && code != 400 {
		t.Errorf("corps > 1 Mo : %d", code)
	}
}

func TestParameterBounds(t *testing.T) {
	f := setup(t)
	for _, p := range []string{
		"/api/hits?limit=501", "/api/hits?limit=0", "/api/hits?limit=abc", "/api/hits?offset=-1", "/api/hits?order=sideways", "/api/hits?mode=x",
		"/api/hits?ip=pas-une-ip", "/api/hits?since=hier", "/api/hits?minScore=-3", "/api/hits/stats?hours=0", "/api/hits/stats?hours=99999",
		"/api/rules?limit=501", "/api/rules?state=zzz", "/api/rules?category=zzz", "/api/lists?list=all", "/api/lists/ips?list=", "/api/lists/ips?list=x",
		"/api/alerts?limit=1000", "/api/alerts?sinceId=-1", "/api/alerts?order=up",
	} {
		m := f.json(t, "GET", p, "", 400)
		if m["error"] == nil {
			t.Errorf("%s : error attendu", p)
		}
	}
	f.json(t, "GET", "/api/hits?limit=500&order=asc&since=1700000000&until=2000000000000&ip=203.0.113.9&rule=942100", "", 200)
	f.json(t, "GET", "/api/hits?since=2025-01-01T00:00:00Z", "", 200)
	m := f.json(t, "GET", "/api/hits", "", 200)
	if m["total"] != float64(0) || len(m["hits"].([]any)) != 0 {
		t.Fatalf("hits: %v", m)
	}
}

func TestSimulateAndLists(t *testing.T) {
	f := setup(t)
	m := f.json(t, "POST", "/api/simulate", `{"method":"GET","uri":"/?q=1+union+select+2","vhost":"example.com","ua":"sqlmap","ip":"203.0.113.9","headers":{},"paranoia":2}`, 200)
	if m["score"] != float64(10) || m["wouldList"] != nil || m["mode"] != "observe" {
		t.Fatalf("simulate: %v", m)
	}
	hs := m["hits"].([]any)
	if len(hs) != 2 || hs[0].(map[string]any)["suppressed"] != nil {
		t.Fatalf("hits: %v", hs)
	}
	for _, b := range []string{`{}`, `{"uri":"x"}`, `{"uri":"/","bogus":1}`, `{"uri":"/","ip":"zz"}`, `{"uri":"/","paranoia":7}`, `nope`} {
		f.json(t, "POST", "/api/simulate", b, 400)
	}
	// listes vides
	l := f.json(t, "GET", "/api/lists", "", 200)
	if _, ok := l["lists"].([]any); !ok || l["block"] == nil || l["challenge"] == nil {
		t.Fatalf("lists: %v", l)
	}
	b := f.json(t, "GET", "/api/lists?list=block", "", 200)
	if b["list"] != "block" || b["count"] != float64(0) || len(b["ips"].([]any)) != 0 {
		t.Fatalf("list block: %v", b)
	}
	code, txt, h := f.do(t, "GET", "/api/lists/ips?list=block", "", nil)
	if code != 200 || txt != "" || !strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
		t.Fatalf("ips: %d %q %s", code, txt, h.Get("Content-Type"))
	}
	u := f.json(t, "POST", "/api/lists/unlist", `{"ip":"203.0.113.9","list":"all"}`, 200)
	if u["ok"] != true {
		t.Fatal(u)
	}
	for _, bb := range []string{`{"ip":"x","list":"all"}`, `{"ip":"203.0.113.9","list":"zzz"}`, `{"ip":"203.0.113.9","graceMinutes":-5}`, `{"ip":"203.0.113.9","extra":1}`} {
		f.json(t, "POST", "/api/lists/unlist", bb, 400)
	}
	f.json(t, "POST", "/api/alerts/ack", `{"ids":[1,2]}`, 200)
	f.json(t, "POST", "/api/alerts/ack", `{"ids":[]}`, 400)
	f.json(t, "POST", "/api/alerts/ack", `{"ids":["a"]}`, 400)
	a := f.json(t, "GET", "/api/alerts", "", 200)
	if a["latestId"] != float64(0) || len(a["alerts"].([]any)) != 0 {
		t.Fatalf("alerts: %v", a)
	}
}

func TestRulesCustomAndEngine(t *testing.T) {
	f := setup(t)
	m := f.json(t, "GET", "/api/rules?limit=500", "", 200)
	if m["total"] != float64(5) {
		t.Fatalf("rules: %v", m["total"])
	}
	c := f.json(t, "GET", "/api/rules/categories", "", 200)
	if len(c["categories"].([]any)) != 14 {
		t.Fatal("categories")
	}
	f.json(t, "POST", "/api/engine/reload", "", 200)
	if g := f.json(t, "GET", "/api/custom-rules", "", 200); g["text"] != "" {
		t.Fatal("custom initial")
	}
	for _, b := range []string{`{"text":"Include /etc/passwd"}`, `{"text":"SecRuleEngine On"}`, `{"text":"SecAction \"id:5,phase:1,pass\""}`, `{"text":"SecRule x"}`, `{"text":1}`, `{"txt":"a"}`} {
		f.json(t, "PUT", "/api/custom-rules", b, 400)
	}
	good := `{"text":"SecRule REQUEST_URI \"@contains /secret\" \"id:9100020,phase:1,pass,log,msg:'X',severity:'WARNING'\""}`
	f.json(t, "PUT", "/api/custom-rules", good, 200)
	g := f.json(t, "GET", "/api/custom-rules", "", 200)
	if !strings.Contains(g["text"].(string), "9100020") {
		t.Fatal("relecture")
	}
	s := f.json(t, "POST", "/api/simulate", `{"uri":"/secret"}`, 200)
	if s["score"] != float64(3) {
		t.Fatalf("regle perso: %v", s)
	}
	// mise a jour du CRS : version invalide -> 400 ; valide mais hote injoignable -> 202 puis erreur dans status
	f.json(t, "POST", "/api/rules/update", `{"version":"../../x"}`, 400)
	f.json(t, "POST", "/api/rules/update", `{"bogus":1}`, 400)
}

func TestRulesUpdateAccepted(t *testing.T) {
	f := setup(t)
	m := f.json(t, "POST", "/api/rules/update", `{"version":"v4.8.0"}`, 202)
	if m["started"] != true {
		t.Fatal(m)
	}
	var crsM map[string]any
	for i := 0; i < 500; i++ {
		crsM = f.json(t, "GET", "/api/status", "", 200)["crs"].(map[string]any)
		if crsM["downloading"] == false {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if crsM["downloading"] != false || crsM["lastError"] == nil {
		t.Fatalf("echec attendu et signale dans status.crs.lastError : %v", crsM)
	}
	// le CRS existant est intact et le service reste joignable
	if st := f.json(t, "GET", "/api/status", "", 200); st["engine"].(map[string]any)["ready"] != true {
		t.Fatal("moteur indisponible apres echec de mise a jour")
	}
	f.json(t, "GET", "/api/health", "", 200)
}
