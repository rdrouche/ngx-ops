package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/waf/crs"
	"nginx-analyzer-go/internal/waf/engine"
	"nginx-analyzer-go/internal/waf/logsource"
	"nginx-analyzer-go/internal/waf/scoring"
	"nginx-analyzer-go/internal/waf/settings"
	"nginx-analyzer-go/internal/waf/store"
)

// BadRequest : entree invalide (HTTP 400).
type BadRequest struct{ Msg string }

func (e *BadRequest) Error() string { return e.Msg }

func bad(format string, a ...any) error { return &BadRequest{Msg: fmt.Sprintf(format, a...)} }

// Version renvoie la version de l'application.
func (s *Service) Version() string { return s.cfg.Version }

// ---------- /api/status ----------

type EngineStatus struct {
	Name     string  `json:"name"`
	Version  string  `json:"version"`
	Ready    bool    `json:"ready"`
	Error    *string `json:"error"`
	Loading  bool    `json:"loading"`
	Paranoia int     `json:"paranoia"`
}

type CRSStatus struct {
	Version      string               `json:"version"`
	Installed    bool                 `json:"installed"`
	RulesLoaded  int                  `json:"rulesLoaded"`
	FilesIgnored []engine.FileIgnored `json:"filesIgnored"`
	UpdatedAt    string               `json:"updatedAt"`
	Downloading  bool                 `json:"downloading"`
	LastError    *string              `json:"lastError"`
}

type LogsStatus struct {
	Files             int            `json:"files"`
	Formats           map[string]int `json:"formats"`
	LinesRead         int            `json:"linesRead"`
	LinesAnalyzed     int64          `json:"linesAnalyzed"`
	Dropped           int64          `json:"dropped"`
	QueueDropped      int64          `json:"queueDropped"`
	UnparsedSamples   []string       `json:"unparsedSamples"`
	Unparsed          int64          `json:"unparsed"`          // lignes lues mais non comprises (format inattendu)
	NotReady          int64          `json:"notReady"`          // lignes perdues car le moteur n'etait pas pret
	DuplicatesSkipped int64          `json:"duplicatesSkipped"` // doublons combined/waf_json ecartes
	LinesPerSecond    float64        `json:"linesPerSecond"`
}

type Stats24h struct {
	Requests  int     `json:"requests"`
	Hits      int     `json:"hits"`
	IPs       int     `json:"ips"`
	AvgEvalMs float64 `json:"avgEvalMs"`
}

type StatusDoc struct {
	Version           string            `json:"version"`
	Engine            EngineStatus      `json:"engine"`
	Enabled           bool              `json:"enabled"`
	CRS               CRSStatus         `json:"crs"`
	EffectiveParanoia int               `json:"effectiveParanoia"`
	Logs              LogsStatus        `json:"logs"`
	VhostsSeen        int               `json:"vhostsSeen"`
	UnreliableRules   map[string][]int  `json:"unreliableRules"`
	Stats24h          Stats24h          `json:"stats24h"`
	Memory            map[string]uint64 `json:"memory"`
	Persistence       bool              `json:"persistence"`
}

func rssBytes() uint64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 2 {
			if pages, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				return pages * uint64(os.Getpagesize())
			}
		}
	}
	return 0
}

// Status construit /api/status.
func (s *Service) Status(ctx context.Context) StatusDoc {
	c := s.set.Get()
	d := StatusDoc{Version: s.cfg.Version, Enabled: c.S.Enable, EffectiveParanoia: c.EffectiveParanoia(), Persistence: s.st.OK()}
	d.Engine = EngineStatus{Name: "coraza", Version: engine.Version(), Ready: s.eng.Ready(), Loading: s.eng.Loading(), Paranoia: s.eng.Paranoia()}
	if err := s.eng.Err(); err != nil {
		m := err.Error()
		d.Engine.Error = &m
	}
	cs := s.crs.Status()
	d.CRS = CRSStatus{Version: cs.Version, Installed: cs.Installed, UpdatedAt: cs.UpdatedAt, Downloading: cs.Downloading, LastError: cs.LastError, FilesIgnored: []engine.FileIgnored{}}
	d.UnreliableRules = map[string][]int{"combined": {}, "waf_json": {}}
	if info := s.eng.Info(); info != nil {
		d.CRS.RulesLoaded = info.RulesLoaded
		if info.FilesIgnored != nil {
			d.CRS.FilesIgnored = info.FilesIgnored
		}
		d.UnreliableRules = info.Unreliable
	}
	ls := logsource.Status{Formats: map[string]int{"combined": 0, "vhost": 0, "waf_json": 0}}
	if src := s.src.Load(); src != nil {
		ls = src.Status()
	}
	qd := s.queueDropped.Load()
	d.Logs = LogsStatus{
		Files: ls.Files, Formats: ls.Formats, LinesRead: ls.Lines,
		LinesAnalyzed: s.linesAnalyzed.Load(), Dropped: int64(ls.Dropped) + qd + s.notReady.Load(),
		QueueDropped: qd, Unparsed: int64(ls.Dropped), UnparsedSamples: unparsedSamples(s), NotReady: s.notReady.Load(), DuplicatesSkipped: s.dd.skipped.Load(), LinesPerSecond: round1(s.rate.perSecond(s.linesAnalyzed.Load())),
	}
	s.vhMu.Lock()
	d.VhostsSeen = len(s.vh)
	s.vhMu.Unlock()
	req, hits, ips := s.st.Summary(ctx, time.Now().Add(-24*time.Hour).UnixMilli())
	d.Stats24h = Stats24h{Requests: req, Hits: hits, IPs: ips, AvgEvalMs: round1(s.avgEvalMs()*100) / 100}
	d.Memory = map[string]uint64{"rss": rssBytes()}
	return d
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

// ---------- /api/vhosts ----------

type VhostDoc struct {
	Name     string `json:"name"`
	Lines    int64  `json:"lines"`
	Hits24h  int    `json:"hits24h"`
	LastSeen string `json:"lastSeen"`
	Format   string `json:"format"`
	Analyzed bool   `json:"analyzed"`
	Mode     string `json:"mode"`
	Paranoia int    `json:"paranoia"`
}

// Vhosts renvoie les vhosts vus dans les logs.
func (s *Service) Vhosts(ctx context.Context) []VhostDoc {
	c := s.set.Get()
	hits := s.st.HitsByVhost(ctx, time.Now().Add(-24*time.Hour).UnixMilli())
	s.vhMu.Lock()
	out := make([]VhostDoc, 0, len(s.vh))
	for n, v := range s.vh {
		out = append(out, VhostDoc{
			Name: n, Lines: v.lines, Hits24h: hits[n], Format: v.format,
			LastSeen: time.UnixMilli(v.last).UTC().Format(time.RFC3339),
			Analyzed: c.VhostAnalyzed(n), Mode: c.Mode(n), Paranoia: c.Paranoia(n),
		})
		if !c.VhostAnalyzed(n) {
			out[len(out)-1].Hits24h = 0
		}
	}
	s.vhMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---------- /api/rules ----------

type RuleDoc struct {
	ID             int      `json:"id"`
	Msg            string   `json:"msg"`
	Category       string   `json:"category"`
	File           string   `json:"file"`
	Severity       string   `json:"severity"`
	Score          int      `json:"score"`
	Paranoia       int      `json:"paranoia"`
	Tags           []string `json:"tags"`
	Hits7d         int      `json:"hits7d"`
	State          string   `json:"state"`
	SystemDisabled bool     `json:"systemDisabled"`
	DisabledVhosts []string `json:"disabledVhosts"`
	Exceptions     int      `json:"exceptions"`
}

// RulesQuery : parametres de GET /api/rules.
type RulesQuery struct {
	Q, Category, State string
	Limit, Offset      int
}

var validStates = map[string]bool{"active": true, "disabled_global": true, "disabled_system": true, "ignored": true}

func (s *Service) ruleDocs(ctx context.Context) []RuleDoc {
	info := s.eng.Info()
	if info == nil {
		return nil
	}
	c := s.set.Get()
	hits7 := s.st.RuleHits(ctx, time.Now().Add(-7*24*time.Hour).UnixMilli())
	out := make([]RuleDoc, 0, len(info.Rules))
	for _, m := range info.Rules {
		// Les regles d'initialisation/evaluation (900-910, 949+) ne detectent rien : inutiles dans l'UI.
		if m.Category == "other" && (m.ID < 910000 || m.ID >= 945000) && !strings.HasPrefix(m.File, "custom") {
			continue
		}
		d := RuleDoc{
			ID: m.ID, Msg: m.Msg, Category: m.Category, File: m.File, Severity: m.Severity, Score: m.Score,
			Paranoia: m.Paranoia, Tags: m.Tags, Hits7d: hits7[m.ID],
			SystemDisabled: engine.IsUnreliable("combined", m.ID, false),
			DisabledVhosts: c.DisabledVhosts(m.ID), Exceptions: c.ExceptionCount(m.ID),
		}
		switch {
		case info.IgnoredFiles[m.File]:
			d.State = "ignored"
		case c.GloballyDisabled(m.ID):
			d.State = "disabled_global"
		case d.SystemDisabled:
			d.State = "disabled_system"
		default:
			d.State = "active"
		}
		out = append(out, d)
	}
	return out
}

// Rules renvoie la liste filtree/paginee des regles.
func (s *Service) Rules(ctx context.Context, q RulesQuery) (int, []RuleDoc, error) {
	if q.State != "" && !validStates[q.State] {
		return 0, nil, bad("state invalide (active, disabled_global, disabled_system, ignored)")
	}
	if q.Category != "" {
		ok := false
		for _, c := range crs.Categories {
			if c.Key == q.Category {
				ok = true
			}
		}
		if !ok {
			return 0, nil, bad("category inconnue")
		}
	}
	needle := strings.ToLower(q.Q)
	var filtered []RuleDoc
	for _, d := range s.ruleDocs(ctx) {
		if q.Category != "" && d.Category != q.Category {
			continue
		}
		if q.State != "" && d.State != q.State {
			continue
		}
		if needle != "" {
			hay := strings.ToLower(strconv.Itoa(d.ID) + " " + d.Msg + " " + strings.Join(d.Tags, " "))
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		filtered = append(filtered, d)
	}
	total := len(filtered)
	if q.Offset >= total {
		return total, []RuleDoc{}, nil
	}
	end := q.Offset + q.Limit
	if end > total {
		end = total
	}
	return total, filtered[q.Offset:end], nil
}

type CategoryDoc struct {
	Key    string   `json:"key"`
	Label  string   `json:"label"`
	Files  []string `json:"files"`
	Rules  int      `json:"rules"`
	Hits7d int      `json:"hits7d"`
}

// Categories regroupe les regles par categorie.
func (s *Service) Categories(ctx context.Context) []CategoryDoc {
	docs := map[string]*CategoryDoc{}
	var order []string
	for _, c := range crs.Categories {
		docs[c.Key] = &CategoryDoc{Key: c.Key, Label: c.Label, Files: []string{}}
		order = append(order, c.Key)
	}
	if info := s.eng.Info(); info != nil {
		for _, m := range info.Rules {
			d := docs[m.Category]
			if d == nil {
				continue
			}
			d.Rules++
			found := false
			for _, f := range d.Files {
				if f == m.File {
					found = true
				}
			}
			if !found {
				d.Files = append(d.Files, m.File)
			}
		}
	}
	hits := s.st.CategoryHits(ctx, time.Now().Add(-7*24*time.Hour).UnixMilli())
	out := make([]CategoryDoc, 0, len(order))
	for _, k := range order {
		d := docs[k]
		sort.Strings(d.Files)
		d.Hits7d = hits[k]
		out = append(out, *d)
	}
	return out
}

// ---------- /api/hits ----------

// QueryHits : voir store.HitFilter.
func (s *Service) QueryHits(ctx context.Context, f store.HitFilter) (int, []store.Hit, error) {
	if !s.st.OK() {
		return 0, []store.Hit{}, nil
	}
	return s.st.QueryHits(ctx, f)
}

type StatsDoc struct {
	Hours       int                `json:"hours"`
	Requests    int                `json:"requests"`
	HitRequests int                `json:"hitRequests"`
	IPs         int                `json:"ips"`
	TopRules    []store.RuleCount  `json:"topRules"`
	TopIps      []store.IPCount    `json:"topIps"`
	TopVhosts   []store.VhostCount `json:"topVhosts"`
	ByCategory  []store.CatCount   `json:"byCategory"`
	Timeline    []store.TimePoint  `json:"timeline"`
}

func stepFor(hours int) int {
	target := hours * 60 / 96
	for _, n := range []int{1, 5, 10, 15, 30, 60, 120, 360, 720, 1440} {
		if n >= target {
			return n
		}
	}
	return 1440
}

// HitStats : agregats sur les `hours` dernieres heures.
func (s *Service) HitStats(ctx context.Context, hours int) (StatsDoc, error) {
	now := time.Now().UnixMilli()
	st, err := s.st.QueryStats(ctx, now-int64(hours)*3600000, now, stepFor(hours))
	if err != nil {
		return StatsDoc{}, err
	}
	d := StatsDoc{Hours: hours, Requests: st.Requests, HitRequests: st.HitRequests, IPs: st.IPs,
		TopRules: st.TopRules, TopIps: st.TopIPs, TopVhosts: st.TopVhosts, ByCategory: st.ByCategory, Timeline: st.Timeline}
	if d.TopRules == nil {
		d.TopRules = []store.RuleCount{}
	}
	if d.TopIps == nil {
		d.TopIps = []store.IPCount{}
	}
	if d.TopVhosts == nil {
		d.TopVhosts = []store.VhostCount{}
	}
	if d.ByCategory == nil {
		d.ByCategory = []store.CatCount{}
	}
	if d.Timeline == nil {
		d.Timeline = []store.TimePoint{}
	}
	for i := range d.TopIps {
		d.TopIps[i].Lists = s.trk.ListsOf(d.TopIps[i].IP, now)
	}
	return d, nil
}

// ---------- /api/simulate ----------

type SimInput struct {
	Method   string            `json:"method"`
	URI      string            `json:"uri"`
	Vhost    string            `json:"vhost"`
	UA       string            `json:"ua"`
	IP       string            `json:"ip"`
	Headers  map[string]string `json:"headers"`
	Paranoia int               `json:"paranoia"`
	Format   string            `json:"format"`
}

type SimHit struct {
	ID         int      `json:"id"`
	Msg        string   `json:"msg"`
	Severity   string   `json:"severity"`
	Score      int      `json:"score"`
	Data       string   `json:"data"`
	Tags       []string `json:"tags"`
	Paranoia   int      `json:"paranoia"`
	Suppressed *string  `json:"suppressed"`
}

type SimResult struct {
	Score          int      `json:"score"`
	Hits           []SimHit `json:"hits"`
	WouldList      *string  `json:"wouldList"`
	Mode           string   `json:"mode"`
	Paranoia       int      `json:"paranoia"`
	EngineParanoia int      `json:"engineParanoia"`
	Analyzed       bool     `json:"analyzed"`
	WindowScore    int      `json:"windowScore"`
	Note           string   `json:"note,omitempty"`
}

func validToken(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func validHeaderValue(v string) bool {
	if len(v) > 4096 {
		return false
	}
	for _, r := range v {
		if r == '\r' || r == '\n' || r == 0 {
			return false
		}
	}
	return true
}

// Simulate evalue une requete sans rien ecrire en base ni modifier l'etat des listes.
func (s *Service) Simulate(in SimInput) (SimResult, error) {
	if in.Method == "" {
		in.Method = "GET"
	}
	in.Method = strings.ToUpper(in.Method)
	if !validToken(in.Method) {
		return SimResult{}, bad("method invalide")
	}
	if in.URI == "" || len(in.URI) > 8192 || !strings.HasPrefix(in.URI, "/") {
		return SimResult{}, bad("uri invalide (doit commencer par /, 8192 caracteres max)")
	}
	for _, r := range in.URI {
		if r == '\r' || r == '\n' || r == 0 || r == ' ' {
			return SimResult{}, bad("uri invalide (espace ou caractere de controle : utiliser %%20)")
		}
	}
	if in.IP == "" {
		in.IP = "203.0.113.9"
	}
	if !parse.LooksLikeIP(in.IP) {
		return SimResult{}, bad("ip invalide")
	}
	if len(in.UA) > 1024 || !validHeaderValue(in.UA) {
		return SimResult{}, bad("ua invalide")
	}
	if in.Paranoia != 0 && (in.Paranoia < 1 || in.Paranoia > 4) {
		return SimResult{}, bad("paranoia doit etre compris entre 1 et 4")
	}
	format := in.Format
	if format == "" {
		format = logsource.FormatCombined
	}
	if format != logsource.FormatCombined && format != logsource.FormatWafJSON && format != logsource.FormatVhost {
		return SimResult{}, bad("format invalide (combined, vhost, waf_json)")
	}
	if len(in.Headers) > 50 {
		return SimResult{}, bad("trop d'en-tetes (50 max)")
	}
	vhost := ""
	if in.Vhost != "" {
		vhost = s.normVhost(in.Vhost)
	}
	e := &logsource.Entry{Format: format, Vhost: vhost, IP: in.IP, Method: in.Method, URI: logsource.FixURI(in.URI), Proto: "HTTP/1.1", UA: in.UA, WafJSON: format == logsource.FormatWafJSON}
	req := e.Request()
	hasCL := false
	for name, val := range in.Headers {
		if !validToken(strings.ReplaceAll(name, "-", "x")) || len(name) > 64 || !validHeaderValue(val) {
			return SimResult{}, bad("en-tete invalide : %q", truncate(name, 40))
		}
		if strings.EqualFold(name, "host") {
			req.Host = val
			continue
		}
		if strings.EqualFold(name, "content-length") {
			hasCL = true
		}
		replaced := false
		for i, h := range req.Headers {
			if strings.EqualFold(h[0], name) {
				req.Headers[i][1] = val
				replaced = true
			}
		}
		if !replaced {
			req.Headers = append(req.Headers, [2]string{name, val})
		}
	}
	c := s.set.Get()
	par := c.Paranoia(vhost)
	if in.Paranoia != 0 {
		par = in.Paranoia
	}
	res := SimResult{Hits: []SimHit{}, Mode: c.Mode(vhost), Paranoia: par, EngineParanoia: s.eng.Paranoia(), Analyzed: c.VhostAnalyzed(vhost)}
	raw, err := s.eng.Eval(req)
	if err != nil {
		return res, errors.New("moteur indisponible : " + err.Error())
	}
	if par > res.EngineParanoia {
		res.Note = fmt.Sprintf("le moteur est charge au paranoia %d : les regles de niveau superieur ne peuvent pas etre evaluees", res.EngineParanoia)
	}
	for _, cl := range classify(c, format, hasCL, vhost, in.IP, e.Path(), in.UA, par, raw) {
		h := SimHit{ID: cl.ID, Msg: cl.Msg, Severity: cl.Severity, Score: cl.Score, Data: cl.Data, Tags: cl.Tags, Paranoia: cl.Paranoia}
		if h.Tags == nil {
			h.Tags = []string{}
		}
		if cl.Suppressed != "" {
			r := cl.Suppressed
			h.Suppressed = &r
		} else {
			res.Score += cl.Score
		}
		res.Hits = append(res.Hits, h)
	}
	if res.Mode == "remediate" && !c.IPExcluded(in.IP) && !s.trk.InGrace(in.IP, time.Now().UnixMilli()) {
		res.WindowScore = s.trk.WindowRemSum(in.IP, c.S.WindowMinutes, time.Now().UnixMilli())
		total := res.WindowScore + res.Score
		var l string
		switch {
		case res.Score == 0:
		case total >= c.S.Thresholds.Block:
			l = "block"
		case total >= c.S.Thresholds.Challenge:
			l = "challenge"
		}
		if l != "" {
			res.WouldList = &l
		}
	}
	return res, nil
}

// ---------- listes ----------

type ListedDoc struct {
	IP       string   `json:"ip"`
	Score    int      `json:"score"`
	Hits     int      `json:"hits"`
	Since    int64    `json:"since"`
	Until    int64    `json:"until"`
	Vhosts   []string `json:"vhosts"`
	TopRules []int    `json:"topRules"`
}

type ListDoc struct {
	List  string      `json:"list"`
	IPs   []ListedDoc `json:"ips"`
	Count int         `json:"count"`
}

func validList(l string) bool { return l == "block" || l == "challenge" }

// Lists renvoie les IP listees ; list "" = les deux listes.
func (s *Service) Lists(list string) ([]ListDoc, error) {
	if list != "" && !validList(list) {
		return nil, bad("list doit valoir block ou challenge")
	}
	now := time.Now().UnixMilli()
	names := []string{"block", "challenge"}
	if list != "" {
		names = []string{list}
	}
	var out []ListDoc
	for _, n := range names {
		d := ListDoc{List: n, IPs: []ListedDoc{}}
		for _, l := range s.trk.Lists(n, now) {
			d.IPs = append(d.IPs, ListedDoc{IP: l.IP, Score: l.Score, Hits: l.Hits, Since: l.Since, Until: l.Until, Vhosts: l.Vhosts, TopRules: l.TopRules})
		}
		d.Count = len(d.IPs)
		out = append(out, d)
	}
	return out, nil
}

// ListIPs : texte brut, une IP par ligne.
func (s *Service) ListIPs(list string) (string, error) {
	if !validList(list) {
		return "", bad("list doit valoir block ou challenge")
	}
	return s.trk.IPsText(list, time.Now().UnixMilli()), nil
}

// Unlist retire l'IP et memorise un delai « ne plus lister avant ».
func (s *Service) Unlist(ip, list string, graceMinutes int) ([]string, error) {
	if !parse.LooksLikeIP(ip) {
		return nil, bad("ip invalide")
	}
	if list == "" {
		list = "all"
	}
	if list != "all" && !validList(list) {
		return nil, bad("list doit valoir block, challenge ou all")
	}
	if graceMinutes == 0 {
		graceMinutes = 60
	}
	if graceMinutes < 1 || graceMinutes > 10080 {
		return nil, bad("graceMinutes doit etre compris entre 1 et 10080")
	}
	now := time.Now().UnixMilli()
	until := now + int64(graceMinutes)*60000
	removed := s.trk.Unlist(ip, list, now, until)
	delList := ""
	if list != "all" {
		delList = list
	}
	err := s.st.DoSync(func(tx *sql.Tx) error {
		if err := store.DeleteListed(tx, ip, delList); err != nil {
			return err
		}
		return store.SetGrace(tx, ip, until)
	})
	if removed == nil {
		removed = []string{}
	}
	return removed, err
}

// ---------- alertes ----------

type AlertDoc struct {
	ID       int64             `json:"id"`
	TS       int64             `json:"ts"`
	Type     string            `json:"type"`
	Severity string            `json:"severity"`
	IP       string            `json:"ip"`
	Vhost    string            `json:"vhost"`
	Ack      bool              `json:"ack"`
	Evidence *scoring.Evidence `json:"evidence"`
}

func (s *Service) persistAlert(a *scoring.Alert) {
	id := s.nextAlertID.Add(1)
	ev, _ := json.Marshal(a.Evidence)
	row := store.AlertRow{ID: id, TS: a.TS, Severity: a.Severity, IP: a.IP, Vhost: a.Vhost, Evidence: ev}
	s.st.Do(func(tx *sql.Tx) error { return store.InsertAlert(tx, row) })
}

// filterAlert retire les regles desormais desactivees ; ok=false si le score restant < alertMinScore.
func (s *Service) filterAlert(c *settings.Compiled, a *AlertDoc) bool {
	ev := a.Evidence
	kept := ev.Rules[:0:0]
	removed := 0
	for _, r := range ev.Rules {
		off := c.DisabledForVhost(r.ID, a.Vhost) ||
			c.ExceptionMatchesEvidence(r.ID, a.Vhost, a.IP, ev.Paths, ev.UserAgents) ||
			engine.IsUnreliable("waf_json", r.ID, true)
		if off {
			removed += r.Count * crs.SeverityScore(r.Severity)
			continue
		}
		kept = append(kept, r)
	}
	if removed == 0 {
		return true
	}
	ev.Rules = kept
	ev.Score -= removed
	if ev.Score < c.S.AlertMinScore {
		return false
	}
	switch {
	case ev.Score >= c.S.Thresholds.Block:
		a.Severity = "high"
	case ev.Score >= c.S.Thresholds.Challenge:
		a.Severity = "medium"
	default:
		a.Severity = "low"
	}
	return true
}

// Alerts lit les alertes (filtre anti-faux positifs sauf raw). latestId = plus grand id en base.
func (s *Service) Alerts(ctx context.Context, sinceID int64, asc bool, limit int, raw bool) ([]AlertDoc, int64, error) {
	latest := s.st.MaxAlertID(ctx)
	out := []AlertDoc{}
	if !s.st.OK() {
		return out, latest, nil
	}
	c := s.set.Get()
	var cursorSince, cursorBefore int64 = sinceID, 0
	for page := 0; page < 20 && len(out) < limit; page++ {
		rows, err := s.st.QueryAlerts(ctx, cursorSince, cursorBefore, asc, limit)
		if err != nil {
			return nil, latest, err
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			if asc {
				cursorSince = r.ID
			} else {
				cursorBefore = r.ID
			}
			var ev scoring.Evidence
			if err := json.Unmarshal(r.Evidence, &ev); err != nil {
				continue
			}
			d := AlertDoc{ID: r.ID, TS: r.TS, Type: "waf", Severity: r.Severity, IP: r.IP, Vhost: r.Vhost, Ack: r.Ack, Evidence: &ev}
			if !raw && !s.filterAlert(c, &d) {
				continue
			}
			out = append(out, d)
			if len(out) >= limit {
				break
			}
		}
		if len(rows) < limit {
			break
		}
	}
	return out, latest, nil
}

// AckAlerts acquitte des alertes.
func (s *Service) AckAlerts(ids []int64) error {
	if len(ids) == 0 || len(ids) > 500 {
		return bad("ids : 1 a 500 identifiants attendus")
	}
	for _, id := range ids {
		if id < 1 {
			return bad("ids : identifiant invalide")
		}
	}
	return s.st.AckAlerts(ids)
}

// ---------- reglages, CRS, moteur ----------

// Settings renvoie les reglages courants.
func (s *Service) Settings() settings.Settings { return s.set.Get().S }

// UpdateSettings valide/applique un PUT ; recharge le moteur si le paranoia maximal change.
func (s *Service) UpdateSettings(body []byte) (settings.Settings, error) {
	old, cur, err := s.set.Update(body)
	if err != nil {
		var ve *settings.ValidationError
		if errors.As(err, &ve) {
			return old.S, &BadRequest{Msg: ve.Error()}
		}
		return old.S, err
	}
	if s.eng.Ready() && cur.EffectiveParanoia() != s.eng.Paranoia() {
		go func() {
			if err := s.ReloadEngine(); err != nil {
				fmt.Fprintf(os.Stderr, "[waf] rechargement du moteur (paranoia) : %v\n", err)
			}
		}()
	}
	return cur.S, nil
}

// StartRulesUpdate lance le telechargement du CRS (asynchrone).
func (s *Service) StartRulesUpdate(version string) error {
	if version != "" && !crs.ValidVersion(version) {
		return bad("version CRS invalide")
	}
	err := s.crs.Start(s.ctx, version, func() { _ = s.ReloadEngine() })
	if errors.Is(err, crs.ErrBusy) {
		return &ConflictError{Msg: err.Error()}
	}
	return err
}

// ConflictError : operation deja en cours (HTTP 409).
type ConflictError struct{ Msg string }

func (e *ConflictError) Error() string { return e.Msg }

func unparsedSamples(s *Service) []string {
	if src := s.src.Load(); src != nil {
		if v := src.UnparsedSamples(); v != nil {
			return v
		}
	}
	return []string{}
}
