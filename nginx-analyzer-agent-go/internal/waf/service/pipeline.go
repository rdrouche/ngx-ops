package service

import (
	"database/sql"
	"math"
	"runtime"
	"time"

	"nginx-analyzer-go/internal/waf/crs"
	"nginx-analyzer-go/internal/waf/engine"
	"nginx-analyzer-go/internal/waf/logsource"
	"nginx-analyzer-go/internal/waf/scoring"
	"nginx-analyzer-go/internal/waf/settings"
	"nginx-analyzer-go/internal/waf/store"
)

func goMaxProcs() int { return runtime.GOMAXPROCS(0) }

// Raisons de suppression d'un hit (contrat /api/simulate).
const (
	SupException = "exception"
	SupVhost     = "vhost"
	SupGlobal    = "global"
	SupSystem    = "system"
	SupParanoia  = "paranoia"
)

// Classified : un hit brut + sa raison de suppression ("" = retenu).
type Classified struct {
	engine.Hit
	Suppressed string
}

// classify applique, dans l'ordre du contrat : exception > vhost > global > systeme > paranoia.
func classify(c *settings.Compiled, format string, hasCL bool, vhost, ip, path, ua string, paranoia int, hits []engine.Hit) []Classified {
	out := make([]Classified, 0, len(hits))
	for _, h := range hits {
		cl := Classified{Hit: h}
		if r := c.Suppression(h.ID, vhost, ip, path, ua); r != "" {
			cl.Suppressed = r
		} else if engine.IsUnreliable(format, h.ID, hasCL) {
			cl.Suppressed = SupSystem
		} else if h.Paranoia > paranoia {
			cl.Suppressed = SupParanoia
		}
		out = append(out, cl)
	}
	return out
}

func (s *Service) worker() {
	defer s.workersWG.Done()
	for e := range s.jobs {
		s.process(e)
	}
}

func (s *Service) process(e *logsource.Entry) {
	c := s.set.Get()
	req := e.Request()
	t0 := time.Now()
	hits, err := s.eng.Eval(req)
	// Moteur en (re)chargement (demarrage, changement de paranoia, mise a jour du CRS) : on attend
	// jusqu'a 30 s au lieu de perdre la ligne (la file bornee absorbe l'attente).
	for i := 0; err == engine.ErrNotReady && i < 150; i++ {
		select {
		case <-s.stop:
			i = 150
		case <-time.After(200 * time.Millisecond):
		}
		hits, err = s.eng.Eval(req)
	}
	if err != nil {
		if err == engine.ErrNotReady {
			s.notReady.Add(1)
		} else {
			s.evalErrors.Add(1)
		}
		s.inflight.Add(-1)
		return
	}
	s.recordEval(time.Since(t0))
	s.linesAnalyzed.Add(1)
	var kept []engine.Hit
	if len(hits) > 0 {
		for _, cl := range classify(c, e.Format, e.HasCL, e.Vhost, e.IP, e.Path(), e.UA, c.Paranoia(e.Vhost), hits) {
			if cl.Suppressed == "" {
				kept = append(kept, cl.Hit)
			}
		}
	}
	s.results <- result{e: e, kept: kept, mode: c.Mode(e.Vhost), ok: true}
}

func (s *Service) recordEval(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	for {
		old := s.avgEvalBits.Load()
		avg := math.Float64frombits(old)
		if avg == 0 {
			avg = ms
		} else {
			avg = avg*0.99 + ms*0.01
		}
		if s.avgEvalBits.CompareAndSwap(old, math.Float64bits(avg)) {
			return
		}
	}
}

func (s *Service) avgEvalMs() float64 { return math.Float64frombits(s.avgEvalBits.Load()) }

func paramsOf(c *settings.Compiled) scoring.Params {
	return scoring.Params{
		Challenge: c.S.Thresholds.Challenge, Block: c.S.Thresholds.Block,
		WindowMinutes:  c.S.WindowMinutes,
		HoursChallenge: c.S.ListHours.Challenge, HoursBlock: c.S.ListHours.Block,
		AlertMinScore: c.S.AlertMinScore,
	}
}

type statKey struct {
	bucket int64
	vhost  string
}

// aggregator : goroutine unique (scoring deterministe) ; ecritures groupees.
func (s *Service) aggregator() {
	defer s.aggWG.Done()
	stats := map[statKey]*store.ReqStat{}
	var hits []store.Hit
	flush := func() {
		if len(stats) > 0 {
			batch := make([]store.ReqStat, 0, len(stats))
			for _, v := range stats {
				batch = append(batch, *v)
			}
			stats = map[statKey]*store.ReqStat{}
			s.st.Do(func(tx *sql.Tx) error { return store.AddReqStats(tx, batch) })
		}
		if len(hits) > 0 {
			b := hits
			hits = nil
			s.st.Do(func(tx *sql.Tx) error { return store.InsertHits(tx, b) })
		}
		s.flushOffsetsAndVhosts()
	}
	handle := func(r result) {
		defer s.inflight.Add(-1)
		e := r.e
		k := statKey{e.TS / 60000, e.Vhost}
		st := stats[k]
		if st == nil {
			st = &store.ReqStat{Bucket: k.bucket, Vhost: k.vhost}
			stats[k] = st
		}
		st.Requests++
		if len(r.kept) == 0 {
			return
		}
		st.Hits++
		hit, ev := s.buildHit(r)
		hits = append(hits, hit)
		s.applyOutcome(s.trk.Process(ev, paramsOf(s.set.Get())))
		if len(hits) >= 200 {
			flush()
		}
	}
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case r, ok := <-s.results:
			if !ok {
				flush()
				return
			}
			handle(r)
		case ch := <-s.flushCh:
			// tout ce qui est deja dans results est traite avant le vidage
			for drained := false; !drained; {
				select {
				case r, ok := <-s.results:
					if !ok {
						drained = true
						break
					}
					handle(r)
				default:
					drained = true
				}
			}
			flush()
			s.st.Flush()
			close(ch)
		case <-tk.C:
			flush()
		}
	}
}

func (s *Service) buildHit(r result) (store.Hit, scoring.Event) {
	e := r.e
	h := store.Hit{
		TS: e.TS, Vhost: e.Vhost, IP: e.IP, Method: e.Method, URI: truncate(e.URI, 2048),
		Status: e.Status, UA: truncate(e.UA, 512), Mode: r.mode, Format: e.Format,
	}
	ev := scoring.Event{
		TS: e.TS, Now: time.Now().UnixMilli(), IP: e.IP, Vhost: e.Vhost, Path: e.Path(),
		UA: e.UA, Status: e.Status, Remed: r.mode == "remediate",
	}
	seenTag := map[string]bool{}
	seenCat := map[string]bool{}
	for _, k := range r.kept {
		cat := crs.CategoryOfID(k.ID)
		tags := k.Tags
		if tags == nil {
			tags = []string{}
		}
		h.Rules = append(h.Rules, store.HitRule{ID: k.ID, Msg: k.Msg, Severity: k.Severity, Score: k.Score, Data: k.Data, Tags: tags, Category: cat})
		h.Score += k.Score
		ev.Rules = append(ev.Rules, scoring.RuleRef{ID: k.ID, Msg: k.Msg, Severity: k.Severity, Score: k.Score})
		for _, t := range tags {
			if !seenTag[t] {
				seenTag[t] = true
				ev.Tags = append(ev.Tags, t)
			}
		}
		if !seenCat[cat] {
			seenCat[cat] = true
			ev.Category = append(ev.Category, cat)
		}
	}
	ev.Score = h.Score
	h.PossiblySucceeded = e.Status >= 200 && e.Status < 400 && h.Score >= 5
	return h, ev
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Service) applyOutcome(o scoring.Outcome) {
	if o.Upsert != nil {
		l := o.Upsert
		row := store.ListedRow{IP: l.IP, List: l.List, Score: l.Score, Hits: l.Hits, Since: l.Since, Until: l.Until, Vhosts: l.Vhosts, TopRules: l.TopRules}
		drop := o.DropOther
		s.st.Do(func(tx *sql.Tx) error {
			if drop != "" {
				if err := store.DeleteListed(tx, row.IP, drop); err != nil {
					return err
				}
			}
			return store.UpsertListed(tx, row)
		})
	}
	if o.Alert != nil {
		s.persistAlert(o.Alert)
	}
}

func (s *Service) flushOffsetsAndVhosts() {
	if !s.st.OK() {
		return
	}
	if d := s.offs.TakeDirty(); d != nil {
		s.st.Do(func(tx *sql.Tx) error { return store.SaveOffsets(tx, d) })
	}
	var rows []store.VhostRow
	s.vhMu.Lock()
	for n, v := range s.vh {
		if v.dirty {
			v.dirty = false
			rows = append(rows, store.VhostRow{Name: n, Lines: v.lines, LastSeen: v.last, Format: v.format})
		}
	}
	s.vhMu.Unlock()
	if len(rows) > 0 {
		s.st.Do(func(tx *sql.Tx) error { return store.SaveVhosts(tx, rows) })
	}
}

// background : purge de retention, nettoyage des etats en memoire.
func (s *Service) background() {
	defer s.bgWG.Done()
	purge := func() {
		now := time.Now().UnixMilli()
		s.st.Purge(now, s.cfg.HitRetentionDays, s.cfg.AlertRetentionDays)
		s.trk.Sweep(now, s.set.Get().S.WindowMinutes)
	}
	t0 := time.NewTimer(30 * time.Second)
	defer t0.Stop()
	tk := time.NewTicker(10 * time.Minute)
	defer tk.Stop()
	sweep := time.NewTicker(time.Minute)
	defer sweep.Stop()
	ddTick := time.NewTicker(500 * time.Millisecond)
	defer ddTick.Stop()
	ddCheck := 0
	for {
		select {
		case <-s.stop:
			return
		case <-t0.C:
			purge()
		case <-tk.C:
			s.st.Purge(time.Now().UnixMilli(), s.cfg.HitRetentionDays, s.cfg.AlertRetentionDays)
		case <-ddTick.C:
			if ddCheck%2 == 0 { // ~1 s : un fichier waf_json est-il suivi ?
				if src := s.src.Load(); src != nil {
					s.dd.jsonActive.Store(src.WafFilesFollowed())
				}
			}
			ddCheck++
			for _, e := range s.dd.flush(time.Now()) {
				s.enqueue(e)
			}
		case <-sweep.C:
			s.trk.Sweep(time.Now().UnixMilli(), s.set.Get().S.WindowMinutes)
		}
	}
}
