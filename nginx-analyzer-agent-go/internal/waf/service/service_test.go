package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nginx-analyzer-go/internal/waf/wtest"
)

const (
	normalUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
	atk      = "/?q=1+union+select+2"
)

func TestPipelineMiniRules(t *testing.T) {
	e := newEnv(t, wtest.MiniRules(t), nil)
	// trois formats, avec fichiers vides d'abord (detection a l'arrivee des donnees)
	for _, n := range []string{"a.example.com.access.log", "all.access.log", "waf.wafemu.log"} {
		e.write(t, n)
	}
	e.start(t)

	// --- observe (defaut) : hits + alertes, aucune liste ---
	e.write(t, "a.example.com.access.log",
		combined("198.51.100.7", "GET", atk, 404, "sqlmap/1.7"),
		combined("198.51.100.7", "GET", atk, 200, "sqlmap/1.7"),
		combined("198.51.100.7", "GET", atk, 404, "sqlmap/1.7"),
		combined("198.51.100.8", "GET", "/index.html?a=b", 200, normalUA),
		combined("10.0.0.5", "GET", atk, 404, "sqlmap/1.7"),     // IP privee : ignoree
		combined("203.0.113.50", "GET", atk, 404, "sqlmap/1.7"), // sera exclue plus tard
	)
	e.write(t, "all.access.log", vhostLine("shop.example.com", "198.51.100.20", "GET", "/warn", 200, normalUA))
	e.write(t, "waf.wafemu.log", jsonLine("api.example.com", "198.51.100.21", "POST", "/v1?q=union select 1", 200, normalUA, `,"ct":"application/json","cl":"12"`))
	e.settle(t, 8)

	tot, hs := e.hits(t, nil)
	if tot != 6 { // 3 + 203.0.113.50 + warn + json (10.0.0.5 ignoree, .8 normale)
		t.Fatalf("hits: %d %+v", tot, hs)
	}
	for _, h := range hs {
		if h.IP == "10.0.0.5" || h.IP == "198.51.100.8" {
			t.Fatalf("hit inattendu: %+v", h)
		}
		if h.Mode != "observe" {
			t.Fatalf("mode: %+v", h)
		}
	}
	_, a7 := e.hits(t, func(q *HitQ) { q.IP = "198.51.100.7" })
	if len(a7) != 3 || a7[0].Score != 10 || !a7[0].has(942100) || !a7[0].has(913100) {
		t.Fatalf("scores: %+v", a7)
	}
	lists, _ := e.svc.Lists("")
	for _, l := range lists {
		if l.Count != 0 {
			t.Fatalf("liste en observe: %+v", l)
		}
	}
	alerts, latest, err := e.svc.Alerts(context.Background(), 0, true, 100, false)
	if err != nil {
		t.Fatal(err)
	}
	var for7 []AlertDoc
	for _, a := range alerts {
		if a.IP == "198.51.100.7" {
			for7 = append(for7, a)
		}
	}
	if len(for7) != 2 || for7[0].Severity != "medium" || for7[1].Severity != "high" || latest < 2 {
		t.Fatalf("alertes: %+v", for7)
	}
	ev := for7[1].Evidence
	if ev.Score != 30 || ev.Requests != 3 || ev.Mode != "observe" || ev.Listed != nil || ev.Statuses["404"] != 2 || len(ev.UserAgents) != 1 || ev.Categories[0] != "scanner" && ev.Categories[0] != "sqli" {
		t.Fatalf("evidence: %+v", ev)
	}
	// vhosts vus (meme sans hit), formats
	vhs := e.svc.Vhosts(context.Background())
	seen := map[string]VhostDoc{}
	for _, v := range vhs {
		seen[v.Name] = v
	}
	if seen["a.example.com"].Format != "combined" || seen["shop.example.com"].Format != "vhost" || seen["api.example.com"].Format != "waf_json" {
		t.Fatalf("vhosts: %+v", vhs)
	}
	if seen["a.example.com"].Lines != 6 || seen["a.example.com"].Hits24h != 4 || !seen["a.example.com"].Analyzed {
		t.Fatalf("a.example.com: %+v", seen["a.example.com"])
	}

	// --- le statut ---
	st := e.svc.Status(context.Background())
	if !st.Engine.Ready || st.Engine.Name != "coraza" || st.Logs.Files != 3 || st.Logs.Formats["waf_json"] != 1 || st.Logs.LinesAnalyzed != 7 ||
		st.VhostsSeen != 3 || st.Stats24h.Requests != 7 || st.Stats24h.Hits != 6 || st.EffectiveParanoia != 1 || !st.CRS.Installed {
		t.Fatalf("status: %+v", st)
	}
	if len(st.UnreliableRules["combined"]) != 1 || st.UnreliableRules["combined"][0] != 920300 {
		t.Fatalf("unreliableRules: %v", st.UnreliableRules)
	}

	// --- exclusion d'IP, ignoreStatus ---
	put(t, e.svc, `{"excludeIps":["203.0.113.0/24"],"ignoreStatus":[444]}`)
	e.write(t, "a.example.com.access.log",
		combined("203.0.113.51", "GET", atk, 404, normalUA),
		combined("198.51.100.30", "GET", atk, 444, normalUA),
	)
	e.settle(t, 10)
	if tot, _ := e.hits(t, func(q *HitQ) { q.IP = "203.0.113.51" }); tot != 0 {
		t.Fatal("IP exclue analysee")
	}
	if tot, _ := e.hits(t, func(q *HitQ) { q.IP = "198.51.100.30" }); tot != 0 {
		t.Fatal("statut ignore analyse")
	}

	// --- remediate : challenge puis block ---
	put(t, e.svc, `{"mode":"remediate"}`)
	e.write(t, "a.example.com.access.log",
		combined("198.51.100.40", "GET", atk, 404, "sqlmap/1.7"),
		combined("198.51.100.40", "GET", atk, 404, "sqlmap/1.7"),
	)
	e.settle(t, 12)
	ls, _ := e.svc.Lists("challenge")
	if ls[0].Count != 1 || ls[0].IPs[0].IP != "198.51.100.40" || ls[0].IPs[0].Score != 20 {
		t.Fatalf("challenge: %+v", ls[0])
	}
	e.write(t, "a.example.com.access.log", combined("198.51.100.40", "GET", atk, 404, "sqlmap/1.7"))
	e.settle(t, 13)
	ls, _ = e.svc.Lists("block")
	if ls[0].Count != 1 || ls[0].IPs[0].Score != 30 || ls[0].IPs[0].Hits != 3 || ls[0].IPs[0].Until <= ls[0].IPs[0].Since+71*3600000 {
		t.Fatalf("block: %+v", ls[0])
	}
	if c, _ := e.svc.Lists("challenge"); c[0].Count != 0 {
		t.Fatal("block prime : challenge doit etre retire")
	}
	if txt, _ := e.svc.ListIPs("block"); txt != "198.51.100.40\n" {
		t.Fatalf("ips: %q", txt)
	}
	// l'IP observee plus haut (.7) n'est toujours pas listee
	if txt, _ := e.svc.ListIPs("challenge"); strings.Contains(txt, "198.51.100.7") {
		t.Fatal("IP observe listee")
	}
	// persistance des listes + redemarrage
	removed, err := e.svc.Unlist("198.51.100.40", "block", 30)
	if err != nil || len(removed) != 1 {
		t.Fatalf("unlist: %v %v", removed, err)
	}
	e.write(t, "a.example.com.access.log", combined("198.51.100.40", "GET", atk, 404, "sqlmap/1.7"))
	e.settle(t, 14)
	if txt, _ := e.svc.ListIPs("block"); txt != "" {
		t.Fatal("relistee pendant la grace")
	}
	if err := (func() error { _, err := e.svc.Unlist("pas-une-ip", "all", 0); return err })(); err == nil {
		t.Fatal("IP invalide acceptee")
	}
}

func TestExceptionsDisableAndAlertFilter(t *testing.T) {
	e := newEnv(t, wtest.MiniRules(t), nil)
	e.write(t, "a.example.com.access.log")
	e.write(t, "b.example.com.access.log")
	e.start(t)
	put(t, e.svc, `{"exceptions":[{"id":"ex1","rule":942100,"vhost":"a.example.com","pathPrefix":"/wp-admin/","reason":"editeur"}]}`)
	e.write(t, "a.example.com.access.log",
		combined("198.51.100.60", "GET", "/wp-admin/post.php?q=union+select+1", 200, normalUA), // supprime
		combined("198.51.100.60", "GET", "/blog/?q=union+select+1", 200, normalUA),             // hit
	)
	e.write(t, "b.example.com.access.log", combined("198.51.100.60", "GET", "/wp-admin/post.php?q=union+select+1", 200, normalUA)) // autre vhost : hit
	e.settle(t, 3)
	if tot, _ := e.hits(t, func(q *HitQ) { q.IP = "198.51.100.60" }); tot != 2 {
		t.Fatalf("hits avec exception: %d", tot)
	}
	// simulate : raison de suppression
	r, err := e.svc.Simulate(SimInput{Method: "GET", URI: "/wp-admin/x?q=union+select+1", Vhost: "a.example.com", IP: "198.51.100.61", UA: normalUA})
	if err != nil {
		t.Fatal(err)
	}
	if r.Score != 0 || len(r.Hits) != 1 || r.Hits[0].Suppressed == nil || *r.Hits[0].Suppressed != "exception" {
		t.Fatalf("simulate exception: %+v", r)
	}
	r, _ = e.svc.Simulate(SimInput{URI: "/blog/?q=union+select+1", Vhost: "a.example.com", UA: normalUA})
	if r.Score != 5 || r.Hits[0].Suppressed != nil || r.WouldList != nil || r.Mode != "observe" {
		t.Fatalf("simulate: %+v", r)
	}
	// raisons : global, vhost, systeme, paranoia
	put(t, e.svc, `{"disabledRules":[913100],"vhosts":{"b.example.com":{"disabledRules":[942100]}}}`)
	r, _ = e.svc.Simulate(SimInput{URI: "/warn?q=union+select+1+sleep(3)", Vhost: "b.example.com", UA: "sqlmap"})
	sup := map[int]string{}
	for _, h := range r.Hits {
		if h.Suppressed != nil {
			sup[h.ID] = *h.Suppressed
		} else {
			sup[h.ID] = ""
		}
	}
	if sup[942100] != "vhost" || sup[913100] != "global" || sup[920999] != "" || sup[942160] != "paranoia" {
		t.Fatalf("raisons: %v", sup)
	}
	if r.Score != 3 {
		t.Fatalf("score: %d", r.Score)
	}
	r, _ = e.svc.Simulate(SimInput{URI: "/warn?q=1", Headers: map[string]string{"Accept": "nothing"}, Paranoia: 2})
	for _, h := range r.Hits {
		if h.ID == 920300 && (h.Suppressed == nil || *h.Suppressed != "system") {
			t.Fatalf("920300 doit etre supprimee par le systeme: %+v", h)
		}
	}

	// --- desactivation d'une regle => alerte filtree a la lecture ---
	put(t, e.svc, `{"disabledRules":[],"vhosts":{},"exceptions":[]}`)
	e.write(t, "b.example.com.access.log",
		combined("198.51.100.62", "GET", "/", 200, "sqlmap/1"),
		combined("198.51.100.62", "GET", "/", 200, "sqlmap/1"),
	)
	e.settle(t, 5)
	ctx := context.Background()
	al, latest, _ := e.svc.Alerts(ctx, 0, true, 100, false)
	count := func(list []AlertDoc, ip string) int {
		n := 0
		for _, a := range list {
			if a.IP == ip {
				n++
			}
		}
		return n
	}
	if count(al, "198.51.100.62") != 1 {
		t.Fatalf("alerte attendue: %+v", al)
	}
	put(t, e.svc, `{"disabledRules":[913100]}`)
	al2, latest2, _ := e.svc.Alerts(ctx, 0, true, 100, false)
	if count(al2, "198.51.100.62") != 0 {
		t.Fatal("alerte non filtree apres desactivation de la regle")
	}
	if latest2 != latest {
		t.Fatalf("latestId doit rester inchange: %d != %d", latest2, latest)
	}
	raw, _, _ := e.svc.Alerts(ctx, 0, true, 100, true)
	if count(raw, "198.51.100.62") != 1 {
		t.Fatal("raw doit tout montrer")
	}
	// alerte partiellement filtree : score restant recalcule
	put(t, e.svc, `{"disabledRules":[]}`)
	e.write(t, "b.example.com.access.log", combined("198.51.100.63", "GET", atk, 200, "sqlmap/1"), combined("198.51.100.63", "GET", atk, 200, "sqlmap/1"), combined("198.51.100.63", "GET", atk, 200, "sqlmap/1"))
	e.settle(t, 8)
	put(t, e.svc, `{"disabledRules":[913100]}`)
	al3, _, _ := e.svc.Alerts(ctx, 0, true, 100, false)
	var got *AlertDoc
	for i := range al3 {
		if al3[i].IP == "198.51.100.63" {
			got = &al3[i]
		}
	}
	if got == nil || got.Evidence.Score != 15 || got.Severity != "medium" || len(got.Evidence.Rules) != 1 || got.Evidence.Rules[0].ID != 942100 {
		t.Fatalf("filtre partiel: %+v", got)
	}
	// sinceId / desc / ack
	if only, _, _ := e.svc.Alerts(ctx, latest, true, 100, true); len(only) == 0 || only[0].ID <= latest {
		t.Fatalf("sinceId: %+v", only)
	}
	desc, _, _ := e.svc.Alerts(ctx, 0, false, 100, true)
	if len(desc) < 2 || desc[0].ID < desc[1].ID {
		t.Fatal("ordre desc")
	}
	if err := e.svc.AckAlerts([]int64{desc[0].ID}); err != nil {
		t.Fatal(err)
	}
	desc, _, _ = e.svc.Alerts(ctx, 0, false, 100, true)
	if !desc[0].Ack || desc[1].Ack {
		t.Fatal("ack")
	}
	if e.svc.AckAlerts(nil) == nil || e.svc.AckAlerts([]int64{0}) == nil {
		t.Fatal("ack invalide accepte")
	}
}

func TestVhostModeAndParanoiaReload(t *testing.T) {
	e := newEnv(t, wtest.MiniRules(t), nil)
	for _, n := range []string{"a.example.com.access.log", "b.example.com.access.log"} {
		e.write(t, n)
	}
	e.start(t)
	if e.svc.eng.Paranoia() != 1 {
		t.Fatal("paranoia initial")
	}
	put(t, e.svc, `{"vhostMode":"selected","vhosts":{"a.example.com":{"analyze":true,"paranoia":2}}}`)
	waitFor(t, 10*time.Second, "rechargement paranoia 2", func() bool { return e.svc.eng.Paranoia() == 2 })
	e.write(t, "a.example.com.access.log", combined("198.51.100.70", "GET", "/?q=sleep(2)", 200, normalUA), combined("198.51.100.70", "GET", "/?q=union+select", 200, normalUA))
	e.write(t, "b.example.com.access.log", combined("198.51.100.71", "GET", "/?q=union+select", 200, normalUA))
	e.settle(t, 3)
	if tot, _ := e.hits(t, func(q *HitQ) { q.Vhost = "a.example.com" }); tot != 2 {
		t.Fatalf("a (PL2) : %d", tot)
	}
	if tot, _ := e.hits(t, func(q *HitQ) { q.Vhost = "b.example.com" }); tot != 0 {
		t.Fatal("b non selectionne : pas d'analyse")
	}
	vh := map[string]VhostDoc{}
	for _, v := range e.svc.Vhosts(context.Background()) {
		vh[v.Name] = v
	}
	if vh["b.example.com"].Analyzed || vh["b.example.com"].Lines != 1 || vh["b.example.com"].Hits24h != 0 || !vh["a.example.com"].Analyzed || vh["a.example.com"].Paranoia != 2 {
		t.Fatalf("vhosts: %+v", vh)
	}
	// retour a PL1 sur a : la regle PL2 n'est plus retenue (post-filtrage)
	put(t, e.svc, `{"vhostMode":"all","vhosts":{"a.example.com":{"paranoia":1}}}`)
	waitFor(t, 10*time.Second, "rechargement paranoia 1", func() bool { return e.svc.eng.Paranoia() == 1 })
	e.write(t, "a.example.com.access.log", combined("198.51.100.72", "GET", "/?q=sleep(2)", 200, normalUA))
	e.settle(t, 4)
	if tot, _ := e.hits(t, func(q *HitQ) { q.IP = "198.51.100.72" }); tot != 0 {
		t.Fatal("regle PL2 retenue en PL1")
	}
	// enable=false : lignes comptees mais plus analysees
	put(t, e.svc, `{"enable":false}`)
	e.write(t, "a.example.com.access.log", combined("198.51.100.73", "GET", atk, 200, normalUA))
	e.settle(t, 5)
	if tot, _ := e.hits(t, func(q *HitQ) { q.IP = "198.51.100.73" }); tot != 0 {
		t.Fatal("analyse malgre enable=false")
	}
}

func TestRulesEndpointsAndCategories(t *testing.T) {
	e := newEnv(t, wtest.MiniRules(t), nil)
	e.write(t, "a.example.com.access.log")
	e.start(t)
	put(t, e.svc, `{"disabledRules":[920999],"vhosts":{"a.example.com":{"disabledRules":[942100]}},"exceptions":[{"rule":942100,"pathPrefix":"/x/"}]}`)
	e.write(t, "a.example.com.access.log", combined("198.51.100.80", "GET", "/", 200, "sqlmap/1"))
	e.settle(t, 1)
	ctx := context.Background()
	total, rules, err := e.svc.Rules(ctx, RulesQuery{Limit: 100})
	if err != nil || total != 5 {
		t.Fatalf("regles: %d %v", total, err)
	}
	by := map[int]RuleDoc{}
	for _, r := range rules {
		by[r.ID] = r
	}
	if by[942100].Category != "sqli" || by[942100].Severity != "CRITICAL" || by[942100].Score != 5 || by[942100].Paranoia != 1 ||
		len(by[942100].DisabledVhosts) != 1 || by[942100].Exceptions != 1 || by[942100].State != "active" || by[942100].File != "REQUEST-942-APPLICATION-ATTACK-SQLI.conf" {
		t.Fatalf("942100: %+v", by[942100])
	}
	if by[920999].State != "disabled_global" || by[920300].State != "disabled_system" || !by[920300].SystemDisabled || by[942160].Paranoia != 2 || by[913100].Hits7d != 1 {
		t.Fatalf("etats: %+v %+v %+v", by[920999], by[920300], by[942160])
	}
	for _, q := range []struct {
		q    RulesQuery
		want int
	}{
		{RulesQuery{State: "disabled_global", Limit: 10}, 1},
		{RulesQuery{State: "disabled_system", Limit: 10}, 1},
		{RulesQuery{State: "active", Limit: 10}, 3},
		{RulesQuery{Category: "sqli", Limit: 10}, 2},
		{RulesQuery{Q: "blind", Limit: 10}, 1},
		{RulesQuery{Q: "942", Limit: 10}, 2},
		{RulesQuery{Q: "attack-protocol", Limit: 10}, 2},
		{RulesQuery{Limit: 2, Offset: 4}, 1},
	} {
		tot, rs, err := e.svc.Rules(ctx, q.q)
		if err != nil || len(rs) != q.want {
			t.Errorf("%+v : %d regles %v (attendu %d), total %d", q.q, len(rs), err, q.want, tot)
		}
	}
	if _, _, err := e.svc.Rules(ctx, RulesQuery{State: "x", Limit: 1}); err == nil {
		t.Error("state invalide accepte")
	}
	if _, _, err := e.svc.Rules(ctx, RulesQuery{Category: "x", Limit: 1}); err == nil {
		t.Error("category invalide acceptee")
	}
	cats := e.svc.Categories(ctx)
	cm := map[string]CategoryDoc{}
	for _, c := range cats {
		cm[c.Key] = c
	}
	if len(cats) != 14 || cm["sqli"].Rules != 2 || cm["sqli"].Label != "Injection SQL" || cm["scanner"].Hits7d != 1 || len(cm["sqli"].Files) != 1 || cm["protocol"].Rules != 2 {
		t.Fatalf("categories: %+v", cats)
	}
}

func TestCustomRules(t *testing.T) {
	rules := wtest.MiniRules(t)
	e := newEnv(t, rules, nil)
	e.write(t, "a.example.com.access.log")
	e.start(t)
	for name, txt := range map[string]string{
		"include":      `Include /etc/passwd`,
		"engine":       `SecRuleEngine Off`,
		"audit":        `SecAuditLog /tmp/x`,
		"secaction":    `SecAction "id:1000,phase:1,pass,nolog"`,
		"ctl":          `SecRule REQUEST_URI "@contains x" "id:9100002,phase:1,pass,ctl:ruleEngine=Off"`,
		"syntaxe":      `SecRule ARGS "@nope x" "id:9100003,phase:2,pass"`,
		"id duplique":  `SecRule ARGS "@contains x" "id:942100,phase:2,pass,msg:'x'"`,
		"continuation": "SecRule ARGS \"@contains x\" \\",
		"gros":         strings.Repeat("# x\n", 100000),
	} {
		err := e.svc.PutCustomRules(txt)
		if _, ok := err.(*BadRequest); !ok {
			t.Errorf("%s : BadRequest attendu, obtenu %v", name, err)
		}
	}
	if txt, _ := e.svc.CustomRules(); txt != "" {
		t.Fatal("un refus ne doit pas ecrire le fichier")
	}
	good := `# regle perso
SecRule REQUEST_URI "@contains /secret" "id:9100010,phase:1,pass,log,msg:'Acces secret',severity:'CRITICAL',tag:'mon-tag'"
SecAction "id:9100011,phase:1,pass,nolog,setvar:tx.x=1"
`
	if err := e.svc.PutCustomRules(good); err != nil {
		t.Fatal(err)
	}
	if txt, _ := e.svc.CustomRules(); txt != good {
		t.Fatal("relecture")
	}
	// une regle invalide ulterieure ne remplace pas la bonne
	if err := e.svc.PutCustomRules(`SecRule x`); err == nil {
		t.Fatal("refus attendu")
	}
	if txt, _ := e.svc.CustomRules(); txt != good {
		t.Fatal("ancien fichier non conserve")
	}
	r, err := e.svc.Simulate(SimInput{URI: "/secret", UA: normalUA})
	if err != nil || r.Score != 5 || len(r.Hits) != 1 || r.Hits[0].ID != 9100010 || r.Hits[0].Tags[0] != "mon-tag" {
		t.Fatalf("regle perso: %+v %v", r, err)
	}
	// visible dans /api/rules et desactivable
	_, rs, _ := e.svc.Rules(context.Background(), RulesQuery{Q: "9100010", Limit: 5})
	if len(rs) != 1 || rs[0].Category != "other" || rs[0].File != "custom/user.conf" {
		t.Fatalf("api rules: %+v", rs)
	}
	if st := filepath.Join(rules, "custom", "user.conf"); func() bool { _, err := os.Stat(st); return err != nil }() {
		t.Fatal("custom/user.conf absent")
	}
	if err := e.svc.PutCustomRules(""); err != nil {
		t.Fatal(err)
	}
	r, _ = e.svc.Simulate(SimInput{URI: "/secret", UA: normalUA})
	if len(r.Hits) != 0 {
		t.Fatal("regle toujours active apres suppression")
	}
}

func TestSimulateValidation(t *testing.T) {
	e := newEnv(t, wtest.MiniRules(t), nil)
	e.write(t, "a.example.com.access.log")
	e.start(t)
	bads := []SimInput{
		{URI: ""}, {URI: "pas-de-slash"}, {URI: "/a b"}, {URI: "/a\r\nX: y"}, {URI: "/", Method: "GE T"}, {URI: "/", IP: "x"},
		{URI: "/", Paranoia: 9}, {URI: "/", Format: "xml"}, {URI: "/", Headers: map[string]string{"X\r\nA": "b"}},
		{URI: "/", Headers: map[string]string{"X-A": "b\r\nC: d"}}, {URI: "/" + strings.Repeat("a", 9000)},
	}
	for i, b := range bads {
		if _, err := e.svc.Simulate(b); err == nil {
			t.Errorf("entree %d acceptee: %+v", i, b)
		} else if _, ok := err.(*BadRequest); !ok {
			t.Errorf("entree %d : %T", i, err)
		}
	}
	// wouldList en remediate (fenetre + score courant)
	put(t, e.svc, `{"mode":"remediate"}`)
	r, err := e.svc.Simulate(SimInput{URI: atk, UA: "sqlmap", IP: "198.51.100.90"})
	if err != nil || r.Score != 10 || r.WouldList == nil || *r.WouldList != "challenge" || r.Mode != "remediate" {
		t.Fatalf("wouldList: %+v %v", r, err)
	}
	put(t, e.svc, `{"thresholds":{"challenge":5,"block":10}}`)
	r, _ = e.svc.Simulate(SimInput{URI: atk, UA: "sqlmap", IP: "198.51.100.90"})
	if r.WouldList == nil || *r.WouldList != "block" {
		t.Fatalf("block: %+v", r)
	}
	r, _ = e.svc.Simulate(SimInput{URI: atk, UA: "sqlmap", IP: "10.1.2.3"})
	if r.WouldList != nil {
		t.Fatal("IP privee jamais listee")
	}
	// simulate n'ecrit rien
	if tot, _ := e.hits(t, nil); tot != 0 {
		t.Fatal("simulate a ecrit en base")
	}
}

func TestRestartKeepsListsAndOffsets(t *testing.T) {
	rules := wtest.MiniRules(t)
	e := newEnv(t, rules, nil)
	e.write(t, "a.example.com.access.log")
	e.start(t)
	put(t, e.svc, `{"mode":"remediate"}`)
	e.write(t, "a.example.com.access.log",
		combined("198.51.100.91", "GET", atk, 404, "sqlmap"), combined("198.51.100.91", "GET", atk, 404, "sqlmap"), combined("198.51.100.91", "GET", atk, 404, "sqlmap"))
	e.settle(t, 3)
	if txt, _ := e.svc.ListIPs("block"); txt != "198.51.100.91\n" {
		t.Fatalf("block: %q", txt)
	}
	before, _, _ := e.svc.Alerts(context.Background(), 0, true, 100, true)
	e.svc.Close()
	// nouveau service sur les memes donnees : listes et alertes restaurees, lignes non relues
	cfg := e.svc.cfg
	cfg.ReadFromStart = false
	s2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.Start()
	waitFor(t, 20*time.Second, "moteur", func() bool { return s2.eng.Ready() })
	if txt, _ := s2.ListIPs("block"); txt != "198.51.100.91\n" {
		t.Fatalf("liste non restauree: %q", txt)
	}
	time.Sleep(200 * time.Millisecond)
	after, _, _ := s2.Alerts(context.Background(), 0, true, 100, true)
	if len(after) != len(before) || len(after) == 0 {
		t.Fatalf("alertes: %d -> %d", len(before), len(after))
	}
	if s2.linesAnalyzed.Load() != 0 {
		t.Fatalf("lignes relues apres redemarrage: %d", s2.linesAnalyzed.Load())
	}
}

func TestQueueSaturationDropsInsteadOfBlocking(t *testing.T) {
	e := newEnv(t, wtest.MiniRules(t), func(c *Config) { c.QueueSize = 4; c.Workers = 1 })
	e.write(t, "a.example.com.access.log")
	// pas de start du pipeline complet : on appelle onEntry directement avec un moteur pret
	e.start(t)
	// bloquer le seul worker : on sature la file puis on verifie que onEntry ne bloque pas
	done := make(chan struct{})
	go func() {
		for i := 0; i < 20000; i++ {
			e.svc.onEntry(entryFor("198.51.100.99", i))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("onEntry bloque")
	}
	e.svc.Sync(30 * time.Second)
	if e.svc.queueDropped.Load() == 0 {
		t.Skip("machine assez rapide pour ne jamais saturer la file (4)")
	}
	if st := e.svc.Status(context.Background()); st.Logs.Dropped < st.Logs.QueueDropped || st.Logs.QueueDropped == 0 {
		t.Fatalf("dropped non expose: %+v", st.Logs)
	}
}

func TestSettingsJSONShape(t *testing.T) {
	e := newEnv(t, wtest.MiniRules(t), nil)
	b, _ := json.Marshal(e.svc.Settings())
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"enable", "mode", "paranoia", "thresholds", "windowMinutes", "listHours", "alertMinScore", "vhostMode", "vhosts", "disabledRules", "exceptions", "ignoreStatus", "excludeIps"} {
		if _, ok := m[k]; !ok {
			t.Errorf("cle manquante: %s", k)
		}
	}
	for _, k := range []string{"disabledRules", "exceptions", "ignoreStatus", "excludeIps"} {
		if _, ok := m[k].([]any); !ok {
			t.Errorf("%s doit etre un tableau JSON (pas null): %v", k, m[k])
		}
	}
	if _, ok := m["vhosts"].(map[string]any); !ok {
		t.Error("vhosts doit etre un objet")
	}
}
