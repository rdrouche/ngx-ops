package scoring

import "testing"

var P = Params{Challenge: 10, Block: 25, WindowMinutes: 60, HoursChallenge: 24, HoursBlock: 72, AlertMinScore: 10}

const min = int64(60000)

func ev(ip string, ts, now int64, score int, remed bool) Event {
	return Event{TS: ts, Now: now, IP: ip, Vhost: "a.com", Path: "/p", UA: "ua", Status: 404, Score: score, Remed: remed,
		Rules: []RuleRef{{ID: 942100, Msg: "sqli", Severity: "CRITICAL", Score: score}}, Tags: []string{"attack-sqli"}, Category: []string{"sqli"}}
}

func TestObserveNeverLists(t *testing.T) {
	tr := New()
	now := int64(1_000_000_000_000)
	var alerts int
	for i := 0; i < 20; i++ {
		o := tr.Process(ev("1.1.1.1", now+int64(i), now+int64(i), 5, false), P)
		if o.Upsert != nil {
			t.Fatal("liste en mode observe")
		}
		if o.Alert != nil {
			alerts++
		}
	}
	if len(tr.Lists("", now)) != 0 {
		t.Fatal("listes non vides")
	}
	if alerts == 0 {
		t.Fatal("les alertes existent en observe (tous modes)")
	}
}

func TestChallengeThenBlock(t *testing.T) {
	tr := New()
	now := int64(1_000_000_000_000)
	var last Outcome
	steps := []struct {
		score int
		list  string
	}{{5, ""}, {5, "challenge"}, {5, "challenge"}, {5, "challenge"}, {5, "block"}}
	for i, s := range steps {
		last = tr.Process(ev("2.2.2.2", now, now, s.score, true), P)
		got := ""
		if last.Upsert != nil {
			got = last.Upsert.List
		}
		if got != s.list {
			t.Fatalf("etape %d : liste %q (attendu %q)", i, got, s.list)
		}
	}
	// block prime : challenge retire
	if last.DropOther != "challenge" {
		t.Fatalf("DropOther: %q", last.DropOther)
	}
	ls := tr.Lists("", now)
	if len(ls) != 1 || ls[0].List != "block" || ls[0].Score != 25 || ls[0].Hits != 5 {
		t.Fatalf("listes: %+v", ls)
	}
	if ls[0].Until != now+72*3600000 {
		t.Fatalf("duree block: %d", ls[0].Until-now)
	}
	// un hit de plus : challenge n'est pas re-cree, block prolonge
	o := tr.Process(ev("2.2.2.2", now, now+1000, 5, true), P)
	if o.Upsert == nil || o.Upsert.List != "block" || o.Upsert.Until != now+1000+72*3600000 || o.Upsert.Since != now {
		t.Fatalf("prolongation: %+v", o.Upsert)
	}
	if got := tr.ListsOf("2.2.2.2", now); len(got) != 1 || got[0] != "block" {
		t.Fatal(got)
	}
	if tr.IPsText("block", now) != "2.2.2.2\n" || tr.IPsText("challenge", now) != "" {
		t.Fatal("IPsText")
	}
	// expiration
	if len(tr.Lists("block", now+73*3600000)) != 0 {
		t.Fatal("liste expiree encore visible")
	}
	tr.Sweep(now+73*3600000, 60)
	if len(tr.Lists("", 0)) != 0 {
		t.Fatal("Sweep n'a pas purge")
	}
}

func TestMixedModesOnlyRemediateCounts(t *testing.T) {
	tr := New()
	now := int64(1_000_000_000_000)
	for i := 0; i < 10; i++ {
		tr.Process(ev("3.3.3.3", now, now, 5, false), P) // observe : 50 points
	}
	if tr.Lists("", now) != nil {
		t.Fatal("liste sur trafic observe")
	}
	o := tr.Process(ev("3.3.3.3", now, now, 5, true), P)
	if o.Upsert != nil {
		t.Fatal("5 points remediate < seuil")
	}
	o = tr.Process(ev("3.3.3.3", now, now, 5, true), P)
	if o.Upsert == nil || o.Upsert.List != "challenge" || o.Upsert.Score != 10 {
		t.Fatalf("%+v", o.Upsert)
	}
}

func TestWindowSliding(t *testing.T) {
	tr := New()
	t0 := int64(1_000_000_000_000)
	tr.Process(ev("4.4.4.4", t0, t0, 5, true), P)
	// 61 minutes plus tard : le premier evenement sort de la fenetre
	o := tr.Process(ev("4.4.4.4", t0+61*min, t0+61*min, 5, true), P)
	if o.Upsert != nil {
		t.Fatal("evenement hors fenetre compte")
	}
	if got := tr.WindowRemSum("4.4.4.4", 60, t0+61*min); got != 5 {
		t.Fatalf("somme fenetre: %d", got)
	}
	o = tr.Process(ev("4.4.4.4", t0+62*min, t0+62*min, 5, true), P)
	if o.Upsert == nil || o.Upsert.List != "challenge" {
		t.Fatal("dans la fenetre : challenge attendu")
	}
}

func TestAlertOncePerWindowAndEscalation(t *testing.T) {
	tr := New()
	now := int64(1_000_000_000_000)
	alerts := []Alert{}
	step := func(ts int64, score int) {
		if o := tr.Process(ev("5.5.5.5", ts, ts, score, false), P); o.Alert != nil {
			alerts = append(alerts, *o.Alert)
		}
	}
	step(now, 5)
	if len(alerts) != 0 {
		t.Fatal("5 < alertMinScore")
	}
	step(now+1000, 5) // 10 -> alerte medium
	if len(alerts) != 1 || alerts[0].Severity != "medium" {
		t.Fatalf("%+v", alerts)
	}
	step(now+2000, 5) // 15 : pas de nouvelle alerte
	step(now+3000, 5) // 20
	if len(alerts) != 1 {
		t.Fatalf("une seule alerte par fenetre: %d", len(alerts))
	}
	step(now+4000, 5) // 25 -> high : montee de severite
	if len(alerts) != 2 || alerts[1].Severity != "high" {
		t.Fatalf("montee: %+v", alerts)
	}
	step(now+5000, 5) // 30, deja high
	if len(alerts) != 2 {
		t.Fatal("pas de doublon high")
	}
	// apres une fenetre complete (heure de traitement) : nouvelle alerte
	later := now + 61*min
	if o := tr.Process(ev("5.5.5.5", later, later, 30, false), P); o.Alert == nil {
		t.Fatal("nouvelle alerte apres la fenetre")
	}
	e := alerts[1].Evidence
	if e.Score != 25 || e.Requests != 5 || e.WindowMinutes != 60 || e.Mode != "observe" || len(e.Rules) != 1 || e.Rules[0].Count != 5 ||
		e.Tags[0] != "attack-sqli" || e.Categories[0] != "sqli" || e.Paths[0] != "/p" || e.UserAgents[0] != "ua" || e.Statuses["404"] != 5 || e.Listed != nil {
		t.Fatalf("evidence: %+v", e)
	}
	if e.FirstSeen != now || e.LastSeen != now+4000 {
		t.Fatalf("firstSeen/lastSeen: %d %d", e.FirstSeen, e.LastSeen)
	}
}

func TestAlertEvidenceListed(t *testing.T) {
	tr := New()
	now := int64(1_000_000_000_000)
	var a *Alert
	for i := 0; i < 5 && a == nil; i++ {
		a = tr.Process(ev("6.6.6.6", now, now, 5, true), P).Alert
	}
	if a == nil || a.Evidence.Listed == nil || *a.Evidence.Listed != "challenge" || a.Evidence.Mode != "remediate" {
		t.Fatalf("%+v", a)
	}
}

func TestUnlistGrace(t *testing.T) {
	tr := New()
	now := int64(1_000_000_000_000)
	for i := 0; i < 5; i++ {
		tr.Process(ev("7.7.7.7", now, now, 5, true), P)
	}
	if len(tr.Lists("block", now)) != 1 {
		t.Fatal("pas liste")
	}
	removed := tr.Unlist("7.7.7.7", "all", now, now+60*min)
	if len(removed) != 1 || removed[0] != "block" || len(tr.Lists("", now)) != 0 {
		t.Fatalf("removed=%v", removed)
	}
	if !tr.InGrace("7.7.7.7", now) {
		t.Fatal("grace")
	}
	// pendant la grace : plus de liste, meme avec beaucoup de hits
	for i := 0; i < 10; i++ {
		if tr.Process(ev("7.7.7.7", now+int64(i), now+int64(i), 5, true), P).Upsert != nil {
			t.Fatal("relistee pendant la grace")
		}
	}
	// apres la grace : relistee des qu'un hit qualifie
	after := now + 61*min
	var o Outcome
	for i := 0; i < 5; i++ {
		o = tr.Process(ev("7.7.7.7", after, after, 5, true), P)
	}
	if o.Upsert == nil {
		t.Fatal("pas relistee apres la grace")
	}
}

func TestRestore(t *testing.T) {
	tr := New()
	now := int64(1_000_000_000_000)
	tr.Restore([]Listed{{IP: "8.8.8.8", List: "block", Until: now + 1000, Score: 30}}, map[string]int64{"9.9.9.9": now + 1000}, map[string]Mark{"5.5.5.5": {TS: now, Severity: "medium"}})
	if len(tr.Lists("block", now)) != 1 || !tr.InGrace("9.9.9.9", now) {
		t.Fatal("restore")
	}
	// marque restauree : pas de nouvelle alerte medium dans la fenetre
	for i := 0; i < 2; i++ {
		if tr.Process(ev("5.5.5.5", now, now+1, 5, false), P).Alert != nil {
			t.Fatal("alerte dupliquee apres redemarrage")
		}
	}
}

func TestCaps(t *testing.T) {
	tr := New()
	now := int64(1_000_000_000_000)
	for i := 0; i < maxEventsPerIP+500; i++ {
		tr.Process(ev("1.2.3.4", now+int64(i), now, 1, false), P)
	}
	tr.mu.Lock()
	n := len(tr.ips["1.2.3.4"].events)
	sum := tr.ips["1.2.3.4"].allSum
	tr.mu.Unlock()
	if n > maxEventsPerIP || sum != n {
		t.Fatalf("plafond: %d evenements, somme %d", n, sum)
	}
}
