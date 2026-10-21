// Package wtest fournit des aides pour les tests du WAF emule (repertoires de regles).
package wtest

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// MiniRules cree un RULES_DIR contenant quelques regles SecLang minimales (sans le vrai CRS).
func MiniRules(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "crs", "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(rules, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("REQUEST-901-INITIALIZATION.conf", `# init
SecRule &TX:detection_paranoia_level "@eq 0" "id:901120,phase:1,pass,nolog,setvar:tx.detection_paranoia_level=1"
`)
	write("REQUEST-942-APPLICATION-ATTACK-SQLI.conf", `# mini sqli
SecRule ARGS "@contains union select" \
    "id:942100,phase:2,pass,log,msg:'SQL Injection mini',severity:'CRITICAL',\
    tag:'attack-sqli',tag:'paranoia-level/1',t:none,t:lowercase"
SecRule ARGS "@contains sleep(" \
    "id:942160,phase:2,pass,log,msg:'Blind SQLi mini',severity:'CRITICAL',\
    tag:'attack-sqli',tag:'paranoia-level/2',t:none,t:lowercase"
`)
	write("REQUEST-913-SCANNER-DETECTION.conf", `SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \
    "id:913100,phase:1,pass,log,msg:'Scanner detecte',severity:'CRITICAL',tag:'attack-reputation-scanner',tag:'paranoia-level/1'"
`)
	write("REQUEST-920-PROTOCOL-ENFORCEMENT.conf", `SecRule REQUEST_HEADERS:Accept "@streq nothing" \
    "id:920300,phase:1,pass,log,msg:'Missing Accept (non fiable)',severity:'NOTICE',tag:'attack-protocol',tag:'paranoia-level/2'"
SecRule REQUEST_URI "@contains /warn" \
    "id:920999,phase:1,pass,log,msg:'Warning mini',severity:'WARNING',tag:'attack-protocol',tag:'paranoia-level/1'"
`)
	return dir
}

// CopyCRS copie les fichiers utiles d'un clone CRS (rules/*.conf|*.data, crs-setup.conf.example)
// dans un nouveau RULES_DIR/crs.
func CopyCRS(t testing.TB, src string) string {
	t.Helper()
	dir := t.TempDir()
	dst := filepath.Join(dir, "crs", "rules")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(filepath.Join(src, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !(strings.HasSuffix(n, ".conf") || strings.HasSuffix(n, ".data")) {
			continue
		}
		cp(t, filepath.Join(src, "rules", n), filepath.Join(dst, n))
	}
	return dir
}

func cp(t testing.TB, from, to string) {
	t.Helper()
	in, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
}
