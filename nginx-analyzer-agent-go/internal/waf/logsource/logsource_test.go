package logsource

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"nginx-analyzer-go/internal/tail"
)

func TestFixURI(t *testing.T) {
	cases := map[string]string{
		`/a`:                      `/a`,
		`/%zz\x22x`:               `/%zz%22x`,
		`/\xC3\xA9?q=\x27or\x271`: `/%C3%A9?q=%27or%271`,
		`/trailing\x`:             `/trailing\x`,
		`/bad\xZZ`:                `/bad\xZZ`,
		`/\x5C\x5c`:               `/%5C%5c`,
		`/end\x41`:                `/end%41`,
	}
	for in, want := range cases {
		if got := FixURI(in); got != want {
			t.Errorf("%s -> %s (attendu %s)", in, got, want)
		}
	}
}

func TestParseCombined(t *testing.T) {
	line := `203.0.113.9 - - [10/Oct/2025:13:55:36 +0000] "GET /index.php?id=1\x27%20OR%201=1 HTTP/2.0" 404 153 "https://ref.example/" "sqlmap/1.7"`
	e, ok := ParseAccess(line, "combined", "blog.example.com")
	if !ok || e.Skip {
		t.Fatal("ligne non lue")
	}
	if e.IP != "203.0.113.9" || e.Vhost != "blog.example.com" || e.Method != "GET" || e.Status != 404 {
		t.Fatalf("%+v", e)
	}
	if e.URI != `/index.php?id=1%27%20OR%201=1` || e.Proto != "HTTP/2.0" || e.UA != "sqlmap/1.7" || e.Referer != "https://ref.example/" {
		t.Fatalf("%+v", e)
	}
	if e.Format != "combined" || e.Path() != "/index.php" {
		t.Fatal(e.Format, e.Path())
	}
	// requete "-" : lue mais a ignorer
	e, ok = ParseAccess(`198.51.100.1 - - [10/Oct/2025:13:55:36 +0000] "-" 400 0 "-" "-"`, "combined", "x")
	if !ok || !e.Skip {
		t.Fatal("requete '-' : Skip attendu")
	}
	// ua/referer "-" -> vides
	e, _ = ParseAccess(`198.51.100.1 - - [10/Oct/2025:13:55:36 +0000] "GET / HTTP/1.1" 200 5 "-" "-"`, "combined", "x")
	if e.UA != "" || e.Referer != "" {
		t.Fatal("tirets non vides")
	}
}

func TestParseVhost(t *testing.T) {
	line := `shop.example.com 203.0.113.9 - - [10/Oct/2025:13:55:36 +0000] "POST /cart HTTP/1.1" 200 153 "-" "Mozilla/5.0"`
	e, ok := ParseAccess(line, "vhost", "fallback")
	if !ok || e.Vhost != "shop.example.com" || e.Method != "POST" || e.Format != "vhost" {
		t.Fatalf("%+v", e)
	}
}

func TestParseJSON(t *testing.T) {
	line := `{"t":"2025-10-10T13:55:36+00:00","vhost":"api.example.com","ip":"203.0.113.9","m":"POST","u":"/v1/x?a=<script>","p":"HTTP/1.1","s":403,"ua":"curl/8","ref":"","ct":"application/json","cl":"42","xff":"1.2.3.4","acc":"application/json","al":"","ae":"br","org":"https://o.example","xrw":"XMLHttpRequest"}`
	e, ok := ParseJSON(line, "def")
	if !ok || e.Skip {
		t.Fatal("non lu")
	}
	if e.Vhost != "api.example.com" || e.Status != 403 || e.URI != "/v1/x?a=<script>" || e.CT != "application/json" || !e.HasCL || e.XFF != "1.2.3.4" {
		t.Fatalf("%+v", e)
	}
	if e.TS != time.Date(2025, 10, 10, 13, 55, 36, 0, time.UTC).UnixMilli() {
		t.Fatal("horodatage")
	}
	r := e.Request()
	got := map[string]string{}
	for _, h := range r.Headers {
		got[h[0]] = h[1]
	}
	if got["Content-Type"] != "application/json" || got["Content-Length"] != "42" || got["Accept"] != "application/json" ||
		got["Accept-Language"] != "en" || got["Accept-Encoding"] != "br" || got["Origin"] != "https://o.example" ||
		got["X-Requested-With"] != "XMLHttpRequest" || got["X-Forwarded-For"] != "1.2.3.4" {
		t.Fatalf("en-tetes: %v", got)
	}
	// status en chaine, champs absents, vhost vide -> defaut
	e, ok = ParseJSON(`{"t":"2025-10-10T13:55:36+00:00","ip":"1.1.1.1","m":"GET","u":"/","s":"200"}`, "def")
	if !ok || e.Vhost != "def" || e.Status != 200 {
		t.Fatalf("%+v", e)
	}
	for _, bad := range []string{`{"t":"x"`, `not json`, `{"t":"pas une date","ip":"1.1.1.1","m":"GET","u":"/"}`} {
		if _, ok := ParseJSON(bad, "d"); ok {
			t.Errorf("devait echouer: %s", bad)
		}
	}
}

func TestRequestNeutralHeaders(t *testing.T) {
	e := &Entry{Method: "GET", URI: "/", Proto: "HTTP/1.1", IP: "1.1.1.1", Vhost: "a.com", UA: "Mozilla"}
	r := e.Request()
	m := map[string]string{}
	for _, h := range r.Headers {
		m[h[0]] = h[1]
	}
	if m["Accept"] != "*/*" || m["Accept-Language"] != "en" || m["Accept-Encoding"] != "gzip" || m["User-Agent"] != "Mozilla" {
		t.Fatalf("%v", m)
	}
	if _, ok := m["Content-Type"]; ok {
		t.Fatal("pas de Content-Type pour un GET")
	}
	if _, ok := m["Referer"]; ok {
		t.Fatal("Referer vide ne doit pas etre envoye")
	}
	e.Method = "POST"
	e.UA = ""
	r = e.Request()
	m = map[string]string{}
	for _, h := range r.Headers {
		m[h[0]] = h[1]
	}
	if m["Content-Type"] != "application/x-www-form-urlencoded" || m["Content-Length"] != "0" {
		t.Fatalf("POST: %v", m)
	}
	if _, ok := m["User-Agent"]; ok {
		t.Fatal("UA absent ne doit pas etre injecte")
	}
	if r.Host != "a.com" {
		t.Fatal("host")
	}
}

func TestDetectFormat(t *testing.T) {
	if DetectFormat(nil) != "" || DetectFormat([]string{"", "  "}) != "" {
		t.Fatal("echantillon vide")
	}
	if DetectFormat([]string{`{"a":1}`}) != FormatWafJSON {
		t.Fatal("json")
	}
	if DetectFormat([]string{`203.0.113.9 - - [10/Oct/2025:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "x"`}) != "combined" {
		t.Fatal("combined")
	}
	if DetectFormat([]string{`a.example.com 203.0.113.9 - - [10/Oct/2025:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "x"`}) != "vhost" {
		t.Fatal("vhost")
	}
}

func appendFile(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(s)
}

func TestSourceAllFormatsAndRotation(t *testing.T) {
	dir := t.TempDir()
	comb := filepath.Join(dir, "blog.example.com.access.log")
	vh := filepath.Join(dir, "all.access.log")
	js := filepath.Join(dir, "waf.wafemu.log")
	for _, p := range []string{comb, vh, js} {
		appendFile(t, p, "")
	}
	var mu sync.Mutex
	var got []*Entry
	src := New(Options{
		Dir: dir, Pattern: regexp.MustCompile(`(^|[._])access\.log$`), WafPattern: regexp.MustCompile(`(^|[._-])wafemu\.log$`),
		PollMs: 20, Offsets: tail.NewMemoryOffsetStore(),
		OnEntry: func(e *Entry) { mu.Lock(); got = append(got, e); mu.Unlock() },
	})
	src.Start()
	defer src.Stop()
	appendFile(t, comb, `203.0.113.1 - - [10/Oct/2025:13:55:36 +0000] "GET /a HTTP/1.1" 200 1 "-" "x"`+"\n")
	appendFile(t, vh, `shop.example.com 203.0.113.2 - - [10/Oct/2025:13:55:36 +0000] "GET /b HTTP/1.1" 200 1 "-" "x"`+"\n")
	appendFile(t, js, `{"t":"2025-10-10T13:55:36+00:00","vhost":"api.example.com","ip":"203.0.113.3","m":"GET","u":"/c","p":"HTTP/1.1","s":200,"ua":"x"}`+"\n")
	wait := func(n int) {
		for i := 0; i < 200; i++ {
			mu.Lock()
			l := len(got)
			mu.Unlock()
			if l >= n {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("lignes lues: attendu %d", n)
	}
	wait(3)
	by := map[string]*Entry{}
	mu.Lock()
	for _, e := range got {
		by[e.IP] = e
	}
	mu.Unlock()
	if by["203.0.113.1"].Vhost != "blog.example.com" || by["203.0.113.1"].Format != "combined" {
		t.Errorf("combined: %+v", by["203.0.113.1"])
	}
	if by["203.0.113.2"].Vhost != "shop.example.com" || by["203.0.113.2"].Format != "vhost" {
		t.Errorf("vhost: %+v", by["203.0.113.2"])
	}
	if by["203.0.113.3"].Vhost != "api.example.com" || by["203.0.113.3"].Format != "waf_json" {
		t.Errorf("waf_json: %+v", by["203.0.113.3"])
	}
	st := src.Status()
	if st.Files != 3 || st.Formats["combined"] != 1 || st.Formats["vhost"] != 1 || st.Formats["waf_json"] != 1 {
		t.Errorf("status: %+v", st)
	}
	// rotation : fichier renomme puis recree
	os.Rename(comb, comb+".1")
	appendFile(t, comb, `203.0.113.4 - - [10/Oct/2025:13:55:37 +0000] "GET /d HTTP/1.1" 200 1 "-" "x"`+"\n")
	wait(4)
	// ligne incomprehensible : comptee dans les pertes
	appendFile(t, comb, "n'importe quoi\n")
	time.Sleep(100 * time.Millisecond)
	if src.Status().Dropped < 1 {
		t.Error("ligne invalide non comptee")
	}
	_ = strings.TrimSpace
}
