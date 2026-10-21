package settings

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsValid(t *testing.T) {
	d := Default()
	if err := d.Normalize(); err != nil {
		t.Fatal(err)
	}
	if d.Mode != "observe" || d.Paranoia != 1 || d.Thresholds.Block != 25 || d.AlertMinScore != 10 {
		t.Fatalf("defauts inattendus: %+v", d)
	}
}

func TestPatchRejects(t *testing.T) {
	d := Default()
	cases := map[string]string{
		"champ inconnu":       `{"foo":1}`,
		"mode":                `{"mode":"block"}`,
		"paranoia 5":          `{"paranoia":5}`,
		"paranoia chaine":     `{"paranoia":"2"}`,
		"paranoia flottant":   `{"paranoia":2.5}`,
		"block<challenge":     `{"thresholds":{"challenge":30,"block":20}}`,
		"threshold inconnu":   `{"thresholds":{"x":1}}`,
		"fenetre 0":           `{"windowMinutes":0}`,
		"listHours":           `{"listHours":{"challenge":0,"block":1}}`,
		"vhostMode":           `{"vhostMode":"some"}`,
		"vhost invalide":      `{"vhosts":{"bad host!":{}}}`,
		"vhost mode":          `{"vhosts":{"a.com":{"mode":"x"}}}`,
		"vhost paranoia":      `{"vhosts":{"a.com":{"paranoia":9}}}`,
		"vhost champ":         `{"vhosts":{"a.com":{"zzz":1}}}`,
		"regle negative":      `{"disabledRules":[-5]}`,
		"regle chaine":        `{"disabledRules":["942100"]}`,
		"exception sans rule": `{"exceptions":[{"vhost":"a.com"}]}`,
		"exception ip":        `{"exceptions":[{"rule":942100,"ip":"pas-une-ip"}]}`,
		"exception prefix":    `{"exceptions":[{"rule":942100,"pathPrefix":"admin"}]}`,
		"exception id dup":    `{"exceptions":[{"id":"a","rule":1},{"id":"a","rule":2}]}`,
		"exception id":        `{"exceptions":[{"id":"a b","rule":1}]}`,
		"exception date":      `{"exceptions":[{"rule":1,"createdAt":"hier"}]}`,
		"exception ctl":       `{"exceptions":[{"rule":1,"uaContains":"a\u0000b"}]}`,
		"ignoreStatus":        `{"ignoreStatus":[42]}`,
		"excludeIps":          `{"excludeIps":["1.2.3.4/40"]}`,
		"json invalide":       `{`,
		"pas un objet":        `[]`,
		"superflu":            `{} {}`,
	}
	for name, body := range cases {
		if _, err := d.Patch([]byte(body)); err == nil {
			t.Errorf("%s : doit etre rejete (%s)", name, body)
		}
	}
}

func TestPatchMergeAndNormalize(t *testing.T) {
	d := Default()
	s, err := d.Patch([]byte(`{"mode":"remediate","thresholds":{"block":40},"disabledRules":[942100,920350,942100],
	  "vhosts":{"Blog.Example.com":{"analyze":false,"paranoia":3,"disabledRules":[941130,941130]}},
	  "excludeIps":["10.1.0.0/16","203.0.113.7"],"ignoreStatus":[444,444],
	  "exceptions":[{"rule":942100,"vhost":"BLOG.example.com","pathPrefix":"/wp-admin/","reason":"editeur"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode != "remediate" || s.Thresholds.Challenge != 10 || s.Thresholds.Block != 40 {
		t.Fatalf("fusion: %+v", s)
	}
	if len(s.DisabledRules) != 2 || s.DisabledRules[0] != 920350 {
		t.Fatalf("regles: %v", s.DisabledRules)
	}
	v, ok := s.Vhosts["blog.example.com"]
	if !ok || v.Analyze == nil || *v.Analyze || len(v.DisabledRules) != 1 {
		t.Fatalf("vhost: %+v", s.Vhosts)
	}
	if len(s.Exceptions) != 1 || s.Exceptions[0].ID == "" || s.Exceptions[0].CreatedAt == "" || s.Exceptions[0].Vhost != "blog.example.com" {
		t.Fatalf("exceptions: %+v", s.Exceptions)
	}
	if len(s.IgnoreStatus) != 1 {
		t.Fatal("ignoreStatus non dedoublonne")
	}
	// l'original n'est pas modifie
	if d.Mode != "observe" {
		t.Fatal("Patch ne doit pas modifier la source")
	}
}

func TestPersistence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "settings.json")
	h, err := NewHolder(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.Update([]byte(`{"mode":"remediate"}`)); err != nil {
		t.Fatal(err)
	}
	h2, err := NewHolder(p)
	if err != nil || h2.Get().S.Mode != "remediate" {
		t.Fatalf("relecture: %v %v", err, h2.Get().S.Mode)
	}
	// rejet : l'etat n'est pas modifie
	if _, _, err := h.Update([]byte(`{"mode":"x"}`)); err == nil {
		t.Fatal("attendu une erreur")
	} else if _, ok := err.(*ValidationError); !ok {
		t.Fatalf("type d'erreur: %T", err)
	}
	if h.Get().S.Mode != "remediate" {
		t.Fatal("etat modifie par un PUT invalide")
	}
}

func TestSuppressionOrderAndExceptions(t *testing.T) {
	s, err := Default().Patch([]byte(`{"disabledRules":[920350],
	  "vhosts":{"a.com":{"disabledRules":[941130]}},
	  "exceptions":[
	    {"id":"e1","rule":942100,"vhost":"a.com","pathPrefix":"/wp-admin/"},
	    {"id":"e2","rule":942200,"uaContains":"MyMonitor"},
	    {"id":"e3","rule":942300,"ip":"203.0.113.0/24"},
	    {"id":"e4","rule":941130,"vhost":"a.com"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := Compile(s)
	chk := func(rule int, vhost, ip, path, ua, want string) {
		t.Helper()
		if got := c.Suppression(rule, vhost, ip, path, ua); got != want {
			t.Errorf("rule %d %s %s %s : %q (attendu %q)", rule, vhost, path, ua, got, want)
		}
	}
	chk(942100, "a.com", "1.1.1.1", "/wp-admin/post.php", "", "exception")
	chk(942100, "a.com", "1.1.1.1", "/blog/", "", "")
	chk(942100, "b.com", "1.1.1.1", "/wp-admin/x", "", "")
	chk(942200, "x", "1.1.1.1", "/", "xx mymonitor/1.0", "exception") // insensible a la casse
	chk(942200, "x", "1.1.1.1", "/", "curl", "")
	chk(942300, "x", "203.0.113.55", "/", "", "exception")
	chk(942300, "x", "198.51.100.1", "/", "", "")
	chk(941130, "a.com", "1.1.1.1", "/", "", "exception") // exception > vhost
	chk(920350, "a.com", "1.1.1.1", "/", "", "global")
	chk(941130, "b.com", "1.1.1.1", "/", "", "")
	if !c.DisabledForVhost(941130, "a.com") || c.DisabledForVhost(941130, "b.com") {
		t.Error("DisabledForVhost")
	}
	if !c.ExceptionMatchesEvidence(942100, "a.com", "1.1.1.1", []string{"/wp-admin/a", "/wp-admin/b"}, nil) {
		t.Error("evidence: tous les chemins correspondent")
	}
	if c.ExceptionMatchesEvidence(942100, "a.com", "1.1.1.1", []string{"/wp-admin/a", "/autre"}, nil) {
		t.Error("evidence: un chemin ne correspond pas")
	}
	// pathPrefix est litteral : pas de regex
	s2, _ := Default().Patch([]byte(`{"exceptions":[{"rule":1,"pathPrefix":"/a.*"}]}`))
	if Compile(s2).Suppression(1, "", "", "/abc", "") != "" {
		t.Error("pathPrefix interprete comme regex")
	}
	if Compile(s2).Suppression(1, "", "", "/a.*x", "") != "exception" {
		t.Error("pathPrefix litteral attendu")
	}
}

func TestModeParanoiaVhostMode(t *testing.T) {
	s, err := Default().Patch([]byte(`{"paranoia":2,"mode":"remediate","vhosts":{
	  "a.com":{"mode":"observe","paranoia":4},"off.com":{"analyze":false,"paranoia":4},"sel.com":{"analyze":true}}}`))
	if err != nil {
		t.Fatal(err)
	}
	c := Compile(s)
	if c.Mode("a.com") != "observe" || c.Mode("z.com") != "remediate" {
		t.Error("mode effectif")
	}
	if c.Paranoia("a.com") != 4 || c.Paranoia("z.com") != 2 {
		t.Error("paranoia effectif")
	}
	if !c.VhostAnalyzed("z.com") || c.VhostAnalyzed("off.com") || !c.VhostAnalyzed("sel.com") {
		t.Error("vhostMode all")
	}
	if c.EffectiveParanoia() != 4 {
		t.Errorf("paranoia max: %d", c.EffectiveParanoia())
	}
	s2, _ := s.Patch([]byte(`{"vhostMode":"selected"}`))
	c2 := Compile(s2)
	if c2.VhostAnalyzed("z.com") || c2.VhostAnalyzed("a.com") || !c2.VhostAnalyzed("sel.com") {
		t.Error("vhostMode selected")
	}
	if c2.EffectiveParanoia() != 2 { // seul sel.com est analyse : paranoia global
		t.Errorf("paranoia selected: %d", c2.EffectiveParanoia())
	}
}

func TestIPExcluded(t *testing.T) {
	s, _ := Default().Patch([]byte(`{"excludeIps":["203.0.113.0/24","2001:db8::/32"]}`))
	c := Compile(s)
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1", "::1", "169.254.1.1", "fd00::1", "203.0.113.9", "2001:db8::5"} {
		if !c.IPExcluded(ip) {
			t.Errorf("%s doit etre exclue", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "198.51.100.1", "2606:4700::1"} {
		if c.IPExcluded(ip) {
			t.Errorf("%s ne doit pas etre exclue", ip)
		}
	}
	if !strings.Contains(string(mustJSON(t, c.S)), `"excludeIps"`) {
		t.Error("serialisation")
	}
}

func mustJSON(t *testing.T, s Settings) []byte {
	t.Helper()
	b, err := jsonMarshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
