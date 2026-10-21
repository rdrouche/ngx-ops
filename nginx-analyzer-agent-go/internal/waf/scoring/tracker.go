// Package scoring : fenetre glissante par IP, listes (challenge/block) et alertes, selon le
// contrat. Logique pure (aucune E/S) : le Tracker renvoie des decisions que l'appelant persiste.
package scoring

import (
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Params : reglages utiles au scoring (copies des Settings courants).
type Params struct {
	Challenge, Block int
	WindowMinutes    int
	HoursChallenge   int
	HoursBlock       int
	AlertMinScore    int
}

// RuleRef : regle declenchee par une requete.
type RuleRef struct {
	ID       int
	Msg      string
	Severity string
	Score    int
}

// Event : une requete avec au moins un hit retenu.
type Event struct {
	TS       int64 // heure de la requete (log), ms
	Now      int64 // heure de traitement, ms
	IP       string
	Vhost    string
	Path     string
	UA       string
	Status   int
	Score    int
	Remed    bool // mode effectif = remediate
	Rules    []RuleRef
	Tags     []string // tags publics
	Category []string
}

// Listed : IP presente dans une liste.
type Listed struct {
	IP       string
	List     string
	Score    int
	Hits     int
	Since    int64
	Until    int64
	Vhosts   []string
	TopRules []int
}

// Alert : alerte creee (evidence prete a serialiser).
type Alert struct {
	TS       int64
	Severity string
	IP       string
	Vhost    string
	Evidence Evidence
}

// RuleCount : regle comptee dans une alerte.
type RuleCount struct {
	ID       int    `json:"id"`
	Msg      string `json:"msg"`
	Count    int    `json:"count"`
	Severity string `json:"severity"`
}

// Evidence : champ `evidence` d'une alerte (contrat).
type Evidence struct {
	Score         int            `json:"score"`
	Requests      int            `json:"requests"`
	WindowMinutes int            `json:"windowMinutes"`
	Mode          string         `json:"mode"`
	Rules         []RuleCount    `json:"rules"`
	Tags          []string       `json:"tags"`
	Categories    []string       `json:"categories"`
	Paths         []string       `json:"paths"`
	UserAgents    []string       `json:"userAgents"`
	Statuses      map[string]int `json:"statuses"`
	FirstSeen     int64          `json:"firstSeen"`
	LastSeen      int64          `json:"lastSeen"`
	Listed        *string        `json:"listed"`
}

// Outcome : decisions a persister apres un evenement.
type Outcome struct {
	Upsert    *Listed // entree de liste a ecrire
	DropOther string  // liste a retirer pour cette IP (ex. challenge quand block)
	Alert     *Alert
}

const (
	maxEventsPerIP = 5000
	maxIPs         = 100000
)

type ipState struct {
	events  []Event
	maxTS   int64
	allSum  int
	remSum  int
	lastNow int64
}

type alertMark struct {
	ts  int64
	sev int
}

// Tracker garde l'etat. Methodes sures pour un usage concurrent.
type Tracker struct {
	mu    sync.Mutex
	ips   map[string]*ipState
	lists map[string]map[string]*Listed // ip -> liste -> entree
	grace map[string]int64
	marks map[string]alertMark
}

// New cree un Tracker vide.
func New() *Tracker {
	return &Tracker{
		ips:   map[string]*ipState{},
		lists: map[string]map[string]*Listed{},
		grace: map[string]int64{},
		marks: map[string]alertMark{},
	}
}

func sevRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	}
	return 1
}

func sevOf(score int, p Params) string {
	switch {
	case score >= p.Block:
		return "high"
	case score >= p.Challenge:
		return "medium"
	}
	return "low"
}

// Mark : derniere alerte connue d'une IP (restauration au demarrage).
type Mark struct {
	TS       int64
	Severity string
}

// Restore recharge listes, delais de grace et marques d'alerte (demarrage).
func (t *Tracker) Restore(ls []Listed, grace map[string]int64, marks map[string]Mark) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range ls {
		l := ls[i]
		m := t.lists[l.IP]
		if m == nil {
			m = map[string]*Listed{}
			t.lists[l.IP] = m
		}
		m[l.List] = &l
	}
	for ip, u := range grace {
		t.grace[ip] = u
	}
	for ip, mk := range marks {
		t.marks[ip] = alertMark{ts: mk.TS, sev: sevRank(mk.Severity)}
	}
}

func (st *ipState) prune(window int64) {
	cut := st.maxTS - window
	if len(st.events) == 0 || st.events[0].TS >= cut {
		// rien a retirer en tete ; les evenements arrivent a peu pres tries
		if len(st.events) <= maxEventsPerIP {
			return
		}
	}
	kept := st.events[:0]
	for _, e := range st.events {
		if e.TS < cut {
			st.allSum -= e.Score
			if e.Remed {
				st.remSum -= e.Score
			}
			continue
		}
		kept = append(kept, e)
	}
	// plafond memoire : on retire les plus anciens
	for len(kept) > maxEventsPerIP {
		e := kept[0]
		st.allSum -= e.Score
		if e.Remed {
			st.remSum -= e.Score
		}
		kept = kept[1:]
	}
	st.events = kept
}

func (t *Tracker) activeList(ip, list string, now int64) *Listed {
	if l := t.lists[ip][list]; l != nil && l.Until > now {
		return l
	}
	return nil
}

// Process integre un evenement et renvoie les decisions.
func (t *Tracker) Process(ev Event, p Params) Outcome {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out Outcome
	window := int64(p.WindowMinutes) * 60000
	st := t.ips[ev.IP]
	if st == nil {
		if len(t.ips) >= maxIPs {
			t.evictLocked(ev.Now, window)
		}
		st = &ipState{}
		t.ips[ev.IP] = st
	}
	st.lastNow = ev.Now
	if ev.TS > st.maxTS {
		st.maxTS = ev.TS
	}
	st.events = append(st.events, ev)
	st.allSum += ev.Score
	if ev.Remed {
		st.remSum += ev.Score
	}
	st.prune(window)

	// --- Listes (evaluation sur les evenements en mode remediate uniquement) ---
	if ev.Remed {
		want := ""
		hours := 0
		switch {
		case st.remSum >= p.Block:
			want, hours = "block", p.HoursBlock
		case st.remSum >= p.Challenge:
			want, hours = "challenge", p.HoursChallenge
		}
		if want != "" && t.grace[ev.IP] <= ev.Now {
			switch {
			case want == "challenge" && t.activeList(ev.IP, "block", ev.Now) != nil:
				// block deja actif : block prime, rien a faire
			default:
				l := t.upsertLocked(ev.IP, want, ev.Now, hours, st)
				cp := *l
				out.Upsert = &cp
				if want == "block" {
					if t.lists[ev.IP]["challenge"] != nil {
						delete(t.lists[ev.IP], "challenge")
						out.DropOther = "challenge"
					}
				}
			}
		}
	}

	// --- Alerte (tous modes) ---
	if st.allSum >= p.AlertMinScore {
		sev := sevOf(st.allSum, p)
		mk, had := t.marks[ev.IP]
		if !had || ev.Now-mk.ts >= window || sevRank(sev) > mk.sev {
			t.marks[ev.IP] = alertMark{ts: ev.Now, sev: sevRank(sev)}
			a := t.buildAlert(ev, st, sev, p)
			out.Alert = &a
		}
	}
	return out
}

func (t *Tracker) upsertLocked(ip, list string, now int64, hours int, st *ipState) *Listed {
	m := t.lists[ip]
	if m == nil {
		m = map[string]*Listed{}
		t.lists[ip] = m
	}
	l := m[list]
	if l == nil || l.Until <= now {
		l = &Listed{IP: ip, List: list, Since: now}
		m[list] = l
	}
	l.Score = st.remSum
	hits, vh, top := summarize(st.events)
	l.Hits = hits
	l.Vhosts = vh
	l.TopRules = top
	l.Until = now + int64(hours)*3600000
	return l
}

func summarize(events []Event) (hits int, vhosts []string, top []int) {
	vs := map[string]bool{}
	rc := map[int]int{}
	for _, e := range events {
		if !e.Remed {
			continue
		}
		hits++
		vs[e.Vhost] = true
		for _, r := range e.Rules {
			rc[r.ID]++
		}
	}
	for v := range vs {
		vhosts = append(vhosts, v)
	}
	sort.Strings(vhosts)
	if len(vhosts) > 20 {
		vhosts = vhosts[:20]
	}
	type kv struct{ id, n int }
	var kvs []kv
	for id, n := range rc {
		kvs = append(kvs, kv{id, n})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].n != kvs[j].n {
			return kvs[i].n > kvs[j].n
		}
		return kvs[i].id < kvs[j].id
	})
	for i, x := range kvs {
		if i >= 5 {
			break
		}
		top = append(top, x.id)
	}
	if top == nil {
		top = []int{}
	}
	if vhosts == nil {
		vhosts = []string{}
	}
	return
}

func addUniq(list []string, v string, max int) []string {
	if v == "" || len(list) >= max {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func (t *Tracker) buildAlert(ev Event, st *ipState, sev string, p Params) Alert {
	ev2 := Evidence{
		Score: st.allSum, WindowMinutes: p.WindowMinutes, Mode: "observe",
		Rules: []RuleCount{}, Tags: []string{}, Categories: []string{}, Paths: []string{}, UserAgents: []string{},
		Statuses: map[string]int{}, FirstSeen: 0,
	}
	if ev.Remed {
		ev2.Mode = "remediate"
	}
	rc := map[int]*RuleCount{}
	for _, e := range st.events {
		ev2.Requests++
		if ev2.FirstSeen == 0 || e.TS < ev2.FirstSeen {
			ev2.FirstSeen = e.TS
		}
		if e.TS > ev2.LastSeen {
			ev2.LastSeen = e.TS
		}
		for _, r := range e.Rules {
			c := rc[r.ID]
			if c == nil {
				c = &RuleCount{ID: r.ID, Msg: r.Msg, Severity: r.Severity}
				rc[r.ID] = c
			}
			c.Count++
		}
		for _, tg := range e.Tags {
			ev2.Tags = addUniq(ev2.Tags, tg, 20)
		}
		for _, c := range e.Category {
			ev2.Categories = addUniq(ev2.Categories, c, 20)
		}
		ev2.Paths = addUniq(ev2.Paths, truncate(e.Path, 200), 10)
		ev2.UserAgents = addUniq(ev2.UserAgents, truncate(e.UA, 120), 5)
		ev2.Statuses[strconv.Itoa(e.Status)]++
	}
	for _, c := range rc {
		ev2.Rules = append(ev2.Rules, *c)
	}
	sort.Slice(ev2.Rules, func(i, j int) bool {
		if ev2.Rules[i].Count != ev2.Rules[j].Count {
			return ev2.Rules[i].Count > ev2.Rules[j].Count
		}
		return ev2.Rules[i].ID < ev2.Rules[j].ID
	})
	if len(ev2.Rules) > 30 {
		ev2.Rules = ev2.Rules[:30]
	}
	sort.Strings(ev2.Tags)
	sort.Strings(ev2.Categories)
	listed := t.currentListLocked(ev.IP, ev.Now)
	ev2.Listed = listed
	return Alert{TS: ev.Now, Severity: sev, IP: ev.IP, Vhost: ev.Vhost, Evidence: ev2}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (t *Tracker) currentListLocked(ip string, now int64) *string {
	var s string
	switch {
	case t.activeList(ip, "block", now) != nil:
		s = "block"
	case t.activeList(ip, "challenge", now) != nil:
		s = "challenge"
	default:
		return nil
	}
	return &s
}

// Lists renvoie les entrees actives ("" = les deux), triees par score decroissant.
func (t *Tracker) Lists(list string, now int64) []Listed {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Listed
	for _, m := range t.lists {
		for name, l := range m {
			if (list == "" || list == name) && l.Until > now {
				out = append(out, *l)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// ListsOf renvoie les noms de listes actives d'une IP.
func (t *Tracker) ListsOf(ip string, now int64) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := []string{}
	for _, name := range []string{"block", "challenge"} {
		if t.activeList(ip, name, now) != nil {
			out = append(out, name)
		}
	}
	return out
}

// IPsText : IP actives d'une liste, une par ligne.
func (t *Tracker) IPsText(list string, now int64) string {
	var b strings.Builder
	ls := t.Lists(list, now)
	sort.Slice(ls, func(i, j int) bool { return ls[i].IP < ls[j].IP })
	for _, l := range ls {
		b.WriteString(l.IP)
		b.WriteByte('\n')
	}
	return b.String()
}

// Unlist retire l'IP des listes ("all" ou "") et memorise le delai de grace. Reinitialise la
// fenetre de l'IP pour qu'elle ne soit pas relistee immediatement. Renvoie les listes retirees.
func (t *Tracker) Unlist(ip, list string, now, graceUntil int64) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var removed []string
	for name := range t.lists[ip] {
		if list == "" || list == "all" || list == name {
			if t.lists[ip][name].Until > now {
				removed = append(removed, name)
			}
			delete(t.lists[ip], name)
		}
	}
	t.grace[ip] = graceUntil
	if st := t.ips[ip]; st != nil {
		st.events, st.allSum, st.remSum = nil, 0, 0
	}
	sort.Strings(removed)
	return removed
}

// WindowRemSum : somme courante (mode remediate) de l'IP dans la fenetre (pour /api/simulate).
func (t *Tracker) WindowRemSum(ip string, windowMin int, now int64) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.ips[ip]
	if st == nil {
		return 0
	}
	cut := now - int64(windowMin)*60000
	sum := 0
	for _, e := range st.events {
		if e.Remed && e.TS >= cut {
			sum += e.Score
		}
	}
	return sum
}

// InGrace : l'IP est dans un delai « ne plus lister avant ».
func (t *Tracker) InGrace(ip string, now int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.grace[ip] > now
}

func (t *Tracker) evictLocked(now, window int64) {
	for ip, st := range t.ips {
		if now-st.lastNow > window {
			delete(t.ips, ip)
		}
	}
	if len(t.ips) >= maxIPs { // toujours plein : on vide tout (cas pathologique)
		t.ips = map[string]*ipState{}
	}
}

// Sweep purge les etats inactifs, listes expirees, graces et marques d'alerte perimees.
func (t *Tracker) Sweep(now int64, windowMin int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	window := int64(windowMin) * 60000
	for ip, st := range t.ips {
		if now-st.lastNow > window {
			delete(t.ips, ip)
		}
	}
	for ip, m := range t.lists {
		for name, l := range m {
			if l.Until <= now {
				delete(m, name)
			}
		}
		if len(m) == 0 {
			delete(t.lists, ip)
		}
	}
	for ip, u := range t.grace {
		if u <= now {
			delete(t.grace, ip)
		}
	}
	for ip, mk := range t.marks {
		if now-mk.ts >= window {
			delete(t.marks, ip)
		}
	}
}
