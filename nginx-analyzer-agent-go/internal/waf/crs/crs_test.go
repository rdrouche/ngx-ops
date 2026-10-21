package crs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sample = `# commentaire
SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners-user-agents.data" \
    "id:913100,\
    phase:1,\
    block,\
    capture,\
    t:none,\
    msg:'Found User-Agent associated with security scanner',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'attack-reputation-scanner',\
    tag:'paranoia-level/2',\
    severity:'CRITICAL',\
    chain"
    SecRule TX:0 "@rx x" "t:none,setvar:'tx.a=1'"

SecAction "id:900990,phase:1,nolog,pass,t:none,setvar:tx.crs_setup_version=480"
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:942012,phase:1,pass,nolog,skipAfter:END"
SecRule ARGS "@rx a, b" "id:942100,phase:2,pass,msg:'It''s a \"test\", ok',severity:'ERROR',tag:'attack-sqli'"
SecMarker END
`

func TestParseFile(t *testing.T) {
	rs := ParseFile("REQUEST-913-SCANNER-DETECTION.conf", strings.NewReader(sample))
	if len(rs) != 4 { // 913100, 900990, 942012, 942100 (la chaine n'a pas d'id)
		t.Fatalf("regles: %d %+v", len(rs), rs)
	}
	r := rs[0]
	if r.ID != 913100 || r.Severity != "CRITICAL" || r.Score != 5 || r.Paranoia != 2 || r.Category != "scanner" {
		t.Fatalf("913100: %+v", r)
	}
	if !strings.HasPrefix(r.Msg, "Found User-Agent") || len(r.Tags) != 3 {
		t.Fatalf("msg/tags: %+v", r)
	}
	if rs[1].Msg != "" || rs[2].Msg != "" {
		t.Error("regles d'init sans msg")
	}
	if rs[3].Severity != "ERROR" || rs[3].Score != 4 || rs[3].Paranoia != 1 {
		t.Fatalf("942100: %+v", rs[3])
	}
	if got := PublicTags(r.Tags, false); len(got) != 1 || got[0] != "attack-reputation-scanner" {
		t.Fatalf("tags publics: %v", got)
	}
}

func TestCategories(t *testing.T) {
	cases := map[string]string{
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf": "sqli", "REQUEST-941-APPLICATION-ATTACK-XSS.conf": "xss",
		"REQUEST-930-APPLICATION-ATTACK-LFI.conf": "lfi", "REQUEST-931-X.conf": "rfi", "REQUEST-932-X.conf": "rce",
		"REQUEST-933-X.conf": "php", "REQUEST-934-X.conf": "generic", "REQUEST-944-X.conf": "java",
		"REQUEST-913-X.conf": "scanner", "REQUEST-920-X.conf": "protocol", "REQUEST-921-X.conf": "protocol",
		"REQUEST-943-X.conf": "session-fixation", "REQUEST-911-X.conf": "method", "REQUEST-922-X.conf": "multipart",
		"REQUEST-901-X.conf": "other", "custom/user.conf": "other",
	}
	for f, want := range cases {
		if got := CategoryOfFile(f); got != want {
			t.Errorf("%s: %s (attendu %s)", f, got, want)
		}
	}
	if CategoryOfID(942100) != "sqli" || CategoryOfID(9100001) != "other" || CategoryOfID(920350) != "protocol" {
		t.Error("CategoryOfID")
	}
	if CategoryLabel("sqli") != "Injection SQL" {
		t.Error("libelle")
	}
}

func TestSeverityScore(t *testing.T) {
	for sev, want := range map[string]int{"CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2, "EMERGENCY": 5, "INFO": 2, "": 3} {
		if SeverityScore(sev) != want {
			t.Errorf("%s", sev)
		}
	}
}

type tf struct {
	name string
	body string
	typ  byte
	link string
}

func mkTar(t testing.TB, files []tf) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		typ := f.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: f.name, Typeflag: typ, Mode: 0o644, Size: int64(len(f.body)), Linkname: f.link}
		if typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(f.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

var goodFiles = []tf{
	{name: "coreruleset-4.8.0/", typ: tar.TypeDir},
	{name: "coreruleset-4.8.0/rules/REQUEST-942-X.conf", body: "SecAction \"id:1,phase:1,pass,nolog\"\n"},
	{name: "coreruleset-4.8.0/rules/scanners.data", body: "sqlmap\n"},
	{name: "coreruleset-4.8.0/rules/REQUEST-900-X.conf.example", body: "x"},
	{name: "coreruleset-4.8.0/rules/RESPONSE-950.conf", body: "x"},
	{name: "coreruleset-4.8.0/crs-setup.conf.example", body: "# setup\n"},
	{name: "coreruleset-4.8.0/tests/regression/a.yaml", body: "x"},
	{name: "coreruleset-4.8.0/util/evil", typ: tar.TypeSymlink, link: "/etc/passwd"},
	{name: "coreruleset-4.8.0/README.md", body: "x"},
}

func TestInstallTarballOK(t *testing.T) {
	dir := t.TempDir()
	// ancien CRS : doit etre remplace
	os.MkdirAll(filepath.Join(dir, "crs", "rules"), 0o755)
	os.WriteFile(filepath.Join(dir, "crs", "rules", "OLD.conf"), []byte("x"), 0o644)
	if err := InstallTarball(bytes.NewReader(mkTar(t, goodFiles)), dir, "v4.8.0", 1<<20); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"rules/REQUEST-942-X.conf", "rules/scanners.data", "crs-setup.conf.example", "VERSION"} {
		if _, err := os.Stat(filepath.Join(dir, "crs", f)); err != nil {
			t.Errorf("manquant: %s", f)
		}
	}
	for _, f := range []string{"rules/OLD.conf", "rules/REQUEST-900-X.conf.example", "tests", "README.md"} {
		if _, err := os.Stat(filepath.Join(dir, "crs", f)); err == nil {
			t.Errorf("ne devait pas etre extrait: %s", f)
		}
	}
	m := NewManager(dir, "v4.8.0", nil)
	if m.InstalledVersion() != "v4.8.0" || m.Empty() {
		t.Error("version / Empty")
	}
	// pas de residu temporaire
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".crs") {
			t.Errorf("residu: %s", e.Name())
		}
	}
}

func TestInstallTarballRefuses(t *testing.T) {
	base := []tf{{name: "c-1/rules/REQUEST-942-X.conf", body: "x"}}
	bad := map[string][]tf{
		"traversal":       append([]tf{{name: "c-1/../../evil.conf", body: "x"}}, base...),
		"traversal rules": append([]tf{{name: "c-1/rules/../../x.conf", body: "x"}}, base...),
		"absolu":          append([]tf{{name: "/etc/passwd", body: "x"}}, base...),
		"antislash":       append([]tf{{name: "c-1\\rules\\a.conf", body: "x"}}, base...),
		"lien extrait":    append([]tf{{name: "c-1/rules/REQUEST-943-L.conf", typ: tar.TypeSymlink, link: "/etc/shadow"}}, base...),
		"lien dur":        append([]tf{{name: "c-1/rules/REQUEST-943-H.conf", typ: tar.TypeLink, link: "x"}}, base...),
		"sans regles":     {{name: "c-1/README.md", body: "x"}},
		"nom douteux":     {{name: "c-1/rules/.hidden.conf", body: "x"}},
	}
	for name, files := range bad {
		dir := t.TempDir()
		os.MkdirAll(filepath.Join(dir, "crs"), 0o755)
		os.WriteFile(filepath.Join(dir, "crs", "KEEP"), []byte("x"), 0o644)
		if err := InstallTarball(bytes.NewReader(mkTar(t, files)), dir, "v4.8.0", 1<<20); err == nil {
			t.Errorf("%s: doit etre refuse", name)
		}
		if _, err := os.Stat(filepath.Join(dir, "crs", "KEEP")); err != nil {
			t.Errorf("%s: l'ancien CRS doit etre conserve", name)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil.conf")); err == nil {
			t.Errorf("%s: ecriture hors du dossier", name)
		}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".crs-tmp") {
				t.Errorf("%s: dossier temporaire non nettoye", name)
			}
		}
	}
	// archive trop grosse
	big := mkTar(t, []tf{{name: "c-1/rules/REQUEST-942-X.conf", body: strings.Repeat("A", 4096)}})
	if err := InstallTarball(bytes.NewReader(big), t.TempDir(), "v4.8.0", 100); err == nil {
		t.Error("taille max non appliquee")
	}
	// pas du gzip
	if err := InstallTarball(strings.NewReader("pas une archive"), t.TempDir(), "v4.8.0", 1<<20); err == nil {
		t.Error("gzip invalide accepte")
	}
}

func TestValidVersionAndURL(t *testing.T) {
	for _, v := range []string{"v4.8.0", "4.8.0", "v4.10.1", "v4.0.0-rc1", "v4.8"} {
		if !ValidVersion(v) {
			t.Errorf("%s doit etre valide", v)
		}
	}
	for _, v := range []string{"", "latest", "../x", "v4.8.0/../../x", "v4.8.0?x=1", "v4.8.0\n", "v4.8.0 ", "main"} {
		if ValidVersion(v) {
			t.Errorf("%q doit etre invalide", v)
		}
	}
	d := NewDownloader("")
	if u, err := d.URLFor("v4.8.0"); err != nil || u.Host != "github.com" {
		t.Fatalf("URL: %v %v", u, err)
	}
	for _, tpl := range []string{"https://evil.example.com/%s.tar.gz", "http://github.com/%s.tar.gz", "https://github.com.evil.com/%s", "https://user@github.com/%s", "https://github.com/no-placeholder", "https://github.com/%s/%s", "https://github.com:8443/%s"} {
		d2 := NewDownloader(tpl)
		if _, err := d2.URLFor("v4.8.0"); err == nil {
			t.Errorf("modele refuse attendu: %s", tpl)
		}
	}
}

func tlsServer(t *testing.T, h http.Handler) (*httptest.Server, string) {
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return srv, u.Host
}

func TestDownloadAndRedirects(t *testing.T) {
	tarball := mkTar(t, goodFiles)
	srv, host := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok.tar.gz":
			w.Write(tarball)
		case "/redir-ok":
			http.Redirect(w, r, "/ok.tar.gz", http.StatusFound)
		case "/redir-evil":
			http.Redirect(w, r, "https://evil.example.com/x.tar.gz", http.StatusFound)
		case "/redir-http":
			http.Redirect(w, r, "http://"+r.Host+"/ok.tar.gz", http.StatusFound)
		case "/huge":
			w.Write(bytes.Repeat([]byte{1}, 5000))
		default:
			http.NotFound(w, r)
		}
	}))
	mk := func(path string) *Downloader {
		d := NewDownloader("https://" + host + path + "%s")
		d.AllowedHosts = []string{host}
		d.Client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint (test local)
		d.MaxBytes = 1 << 20
		return d
	}
	_ = srv
	dir := t.TempDir()
	// "%s" suffixe : /ok.tar.gz?  -> on utilise un modele dont le %s est dans la query
	d := mk("/ok.tar.gz?v=")
	if err := d.Install(context.Background(), dir, "v4.8.0"); err != nil {
		t.Fatal(err)
	}
	if NewManager(dir, "", nil).Empty() {
		t.Fatal("CRS non installe")
	}
	d = mk("/redir-ok?v=")
	if err := d.Install(context.Background(), t.TempDir(), "v4.8.0"); err != nil {
		t.Fatalf("redirection vers l'hote autorise: %v", err)
	}
	for _, p := range []string{"/redir-evil?v=", "/redir-http?v=", "/nope?v="} {
		if err := mk(p).Install(context.Background(), t.TempDir(), "v4.8.0"); err == nil {
			t.Errorf("%s doit echouer", p)
		}
	}
	d = mk("/huge?v=")
	d.MaxBytes = 1000
	if err := d.Install(context.Background(), t.TempDir(), "v4.8.0"); err == nil {
		t.Error("taille max non appliquee")
	}
}

func TestManagerStartFailureNeverFatal(t *testing.T) {
	dir := t.TempDir()
	d := NewDownloader("https://github.com.invalid.example/%s")
	m := NewManager(dir, "v4.8.0", d)
	done := make(chan struct{})
	if err := m.Start(context.Background(), "", func() { t.Error("onDone ne doit pas etre appele") }); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background(), "", nil); err != ErrBusy && err != nil {
		// l'echec est quasi immediat : une erreur de concurrence est acceptable
		t.Log(err)
	}
	go func() {
		for i := 0; i < 200; i++ {
			if !m.Status().Downloading {
				close(done)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		close(done)
	}()
	<-done
	st := m.Status()
	if st.Downloading || st.LastError == nil || st.Installed {
		t.Fatalf("statut: %+v", st)
	}
	if err := m.Start(context.Background(), "../etc", nil); err == nil {
		t.Error("version invalide acceptee")
	}
}
