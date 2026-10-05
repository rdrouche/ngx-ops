package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"nginx-analyzer-go/internal/waf/wtest"
)

func req(uri, ua string) Request {
	h := [][2]string{{"Accept", "*/*"}}
	if ua != "" {
		h = append(h, [2]string{"User-Agent", ua})
	}
	return Request{Method: "GET", URI: uri, Proto: "HTTP/1.1", IP: "203.0.113.5", Host: "example.com", Headers: h}
}

func load(t *testing.T, dir string, par int) *Engine {
	t.Helper()
	e := New(dir)
	if err := e.Reload(context.Background(), par, "v4.8.0"); err != nil {
		t.Fatal(err)
	}
	return e
}

func ids(h []Hit) map[int]Hit {
	m := map[int]Hit{}
	for _, x := range h {
		m[x.ID] = x
	}
	return m
}

func TestNotReady(t *testing.T) {
	e := New(t.TempDir())
	if _, err := e.Eval(req("/", "")); err != ErrNotReady {
		t.Fatalf("attendu ErrNotReady: %v", err)
	}
	if err := e.Reload(context.Background(), 1, "v4.8.0"); err == nil || e.Ready() || e.Err() == nil {
		t.Fatal("CRS absent : erreur attendue")
	}
}

func TestMiniRules(t *testing.T) {
	e := load(t, wtest.MiniRules(t), 2)
	h, err := e.Eval(req("/?q=1+UNION+SELECT+2", "sqlmap/1.7"))
	if err != nil {
		t.Fatal(err)
	}
	m := ids(h)
	if m[942100].Score != 5 || m[942100].Severity != "CRITICAL" || m[942100].Paranoia != 1 {
		t.Fatalf("942100: %+v", m[942100])
	}
	if len(m[942100].Tags) != 1 || m[942100].Tags[0] != "attack-sqli" {
		t.Fatalf("tags: %v", m[942100].Tags)
	}
	if _, ok := m[913100]; !ok {
		t.Fatal("scanner non detecte")
	}
	if m[942100].Data == "" && m[942100].Msg != "SQL Injection mini" {
		t.Fatalf("msg: %q", m[942100].Msg)
	}
	// PL2 charge : la regle PL2 se declenche et porte son niveau
	h, _ = e.Eval(req("/?q=sleep(5)", ""))
	if x, ok := ids(h)[942160]; !ok || x.Paranoia != 2 {
		t.Fatalf("regle PL2: %+v", h)
	}
	// requete saine : aucun hit
	h, _ = e.Eval(req("/index.html?a=b", "Mozilla/5.0"))
	if len(h) != 0 {
		t.Fatalf("faux positif: %+v", h)
	}
	if info := e.Info(); info.Paranoia != 2 || info.RulesLoaded < 5 || len(info.FilesIgnored) != 0 {
		t.Fatalf("info: %+v", info)
	}
	// les regles de 901 (sans msg) ne sont jamais des hits
	for _, x := range ids(h) {
		if x.ID < 911000 {
			t.Fatal("regle d'init exposee")
		}
	}
}

func TestParanoiaLevelOneDoesNotLoadSetupDifferently(t *testing.T) {
	// avec PL1 la regle PL2 est quand meme evaluee par Coraza (mini regle sans garde) : c'est
	// le post-filtrage qui la retire grace au tag. On verifie que le niveau est expose.
	e := load(t, wtest.MiniRules(t), 1)
	h, _ := e.Eval(req("/?q=sleep(5)", ""))
	if x, ok := ids(h)[942160]; !ok || x.Paranoia != 2 {
		t.Fatalf("niveau attendu 2: %+v", h)
	}
}

func TestTolerantLoading(t *testing.T) {
	dir := wtest.MiniRules(t)
	rules := filepath.Join(dir, "crs", "rules")
	os.WriteFile(filepath.Join(rules, "REQUEST-943-BROKEN.conf"), []byte("SecRule ARGS \"@bogusoperator x\" \"id:943100,phase:2,pass,msg:'x'\"\n"), 0o644)
	os.WriteFile(filepath.Join(rules, "REQUEST-944-DUP.conf"), []byte("SecAction \"id:942100,phase:1,pass,nolog\"\n"), 0o644) // id deja pris
	os.MkdirAll(filepath.Join(dir, "custom"), 0o755)
	os.WriteFile(filepath.Join(dir, "custom", "bad.conf"), []byte("SecRule\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "custom", "good.conf"), []byte("SecRule REQUEST_URI \"@contains /secret\" \"id:9100001,phase:1,pass,log,msg:'Acces secret',severity:'WARNING',tag:'mon-tag'\"\n"), 0o644)
	e := load(t, dir, 1)
	info := e.Info()
	got := map[string]bool{}
	for _, f := range info.FilesIgnored {
		got[f.File] = true
		if f.Reason == "" {
			t.Errorf("raison vide pour %s", f.File)
		}
	}
	for _, want := range []string{"REQUEST-943-BROKEN.conf", "REQUEST-944-DUP.conf", "custom/bad.conf"} {
		if !got[want] {
			t.Errorf("%s doit etre ignore (ignores: %v)", want, info.FilesIgnored)
		}
	}
	if len(info.FilesIgnored) != 3 {
		t.Errorf("ignores: %+v", info.FilesIgnored)
	}
	// les autres fichiers fonctionnent
	h, err := e.Eval(req("/secret?q=union select 1", ""))
	if err != nil {
		t.Fatal(err)
	}
	m := ids(h)
	if _, ok := m[942100]; !ok {
		t.Error("regle saine perdue")
	}
	if x, ok := m[9100001]; !ok || x.Score != 3 || len(x.Tags) != 1 {
		t.Errorf("regle personnalisee: %+v", x)
	}
	// metadonnees : les regles du fichier ignore sont marquees
	found := false
	for _, r := range info.Rules {
		if r.ID == 943100 {
			found = true
			if !info.IgnoredFiles[r.File] {
				t.Error("fichier ignore non reference")
			}
		}
	}
	if !found {
		t.Error("regle 943100 absente des metadonnees")
	}
}

func TestReloadSwapKeepsServing(t *testing.T) {
	dir := wtest.MiniRules(t)
	e := load(t, dir, 1)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, 8)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				h, err := e.Eval(req("/?q=union select 1", ""))
				if err != nil {
					errs <- err
					return
				}
				if _, ok := ids(h)[942100]; !ok {
					errs <- os.ErrInvalid
					return
				}
			}
		}()
	}
	for i := 0; i < 5; i++ {
		if err := e.Reload(context.Background(), 1+i%2, "v4.8.0"); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatalf("evaluation concurrente pendant rechargement: %v", err)
	default:
	}
	// un rechargement qui echoue conserve l'instance
	os.RemoveAll(filepath.Join(dir, "crs"))
	if err := e.Reload(context.Background(), 1, "v4.8.0"); err == nil {
		t.Fatal("echec attendu")
	}
	if !e.Ready() {
		t.Fatal("l'ancienne instance doit rester active")
	}
	if _, err := e.Eval(req("/?q=union select 1", "")); err != nil {
		t.Fatal(err)
	}
}

func TestTestCompile(t *testing.T) {
	e := load(t, wtest.MiniRules(t), 1)
	if err := e.TestCompile(`SecRule ARGS "@contains x" "id:9100010,phase:2,pass,log,msg:'ok',severity:'NOTICE'"`); err != nil {
		t.Fatal(err)
	}
	if err := e.TestCompile(`SecRule ARGS "@nope x" "id:9100010,phase:2,pass"`); err == nil {
		t.Error("operateur inconnu accepte")
	}
	if err := e.TestCompile(`SecRule ARGS "@contains x" "id:942100,phase:2,pass"`); err == nil {
		t.Error("id duplique avec le CRS accepte")
	}
	if err := e.TestCompile(``); err != nil {
		t.Errorf("texte vide: %v", err)
	}
}

func TestIsUnreliable(t *testing.T) {
	for _, id := range []int{920280, 920290, 920300, 920310, 920311, 920330, 920340, 920341, 920350, 920420, 920480, 920500, 920510, 922100, 922999} {
		if !IsUnreliable("combined", id, false) || !IsUnreliable("vhost", id, false) {
			t.Errorf("%d doit etre non fiable en combined", id)
		}
	}
	for _, id := range []int{920100, 942100, 920320, 921110} {
		if IsUnreliable("combined", id, false) {
			t.Errorf("%d ne doit pas etre non fiable", id)
		}
	}
	if !IsUnreliable("waf_json", 922100, true) || IsUnreliable("waf_json", 920280, false) || IsUnreliable("waf_json", 920350, false) {
		t.Error("waf_json : seulement 922 (+ 920340/341 si cl absent)")
	}
	if !IsUnreliable("waf_json", 920340, false) || IsUnreliable("waf_json", 920340, true) {
		t.Error("920340 waf_json depend de cl")
	}
	l := unreliableLists(map[int]bool{920280: true, 922100: true, 942100: true, 920300: true})
	if len(l["combined"]) != 3 || len(l["waf_json"]) != 1 {
		t.Errorf("listes: %v", l)
	}
}

func TestVersion(t *testing.T) {
	if !strings.Contains(Version(), ".") {
		t.Fatal(Version())
	}
}

// Avec le vrai CRS : chargement, categories de detection, aucun hit sur du trafic normal.
func TestRealCRS(t *testing.T) {
	src := os.Getenv("WAF_TEST_CRS")
	if src == "" {
		t.Skip("WAF_TEST_CRS absent")
	}
	dir := wtest.CopyCRS(t, src)
	e := load(t, dir, 2)
	info := e.Info()
	if len(info.FilesIgnored) != 0 || info.RulesLoaded < 300 {
		t.Fatalf("chargement: %d regles, ignores %+v", info.RulesLoaded, info.FilesIgnored)
	}
	for _, f := range info.Unreliable["combined"] {
		_ = f
	}
	has := func(uri, ua string, id int) {
		t.Helper()
		h, err := e.Eval(req(uri, ua))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ids(h)[id]; !ok {
			t.Errorf("%s (%s): regle %d attendue, obtenu %v", uri, ua, id, keys(ids(h)))
		}
	}
	has("/index.php?id=1%27%20OR%20%271%27=%271", "Mozilla/5.0", 942100)
	has("/?q=%3Cscript%3Ealert(1)%3C/script%3E", "Mozilla/5.0", 941110)
	has("/?file=../../etc/passwd", "Mozilla/5.0", 930100)
	has("/", "sqlmap/1.7.2#stable (https://sqlmap.org)", 913100)
	has("/.env", "Mozilla/5.0", 930130)
	has("/wp-config.php.bak", "Mozilla/5.0", 930130)
	for _, uri := range []string{"/", "/index.html", "/blog/2024/10/mon-article-sur-nginx?utm_source=rss&page=2", "/static/app.3f9a1c.js", "/api/v1/users?limit=20&offset=40"} {
		h, _ := e.Eval(req(uri, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"))
		for _, x := range h {
			if !IsUnreliable("combined", x.ID, false) && x.Paranoia <= 1 {
				t.Errorf("faux positif PL1 sur %s : %d %s", uri, x.ID, x.Msg)
			}
		}
	}
}

func keys(m map[int]Hit) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	return out
}
