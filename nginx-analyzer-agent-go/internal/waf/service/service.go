// Package service assemble le WAF emule : reglages, moteur Coraza, source de logs, pool de
// workers, agregateur (scoring/listes/alertes), stockage et methodes metier appelees par l'API.
package service

import (
	"context"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/waf/crs"
	"nginx-analyzer-go/internal/waf/engine"
	"nginx-analyzer-go/internal/waf/logsource"
	"nginx-analyzer-go/internal/waf/scoring"
	"nginx-analyzer-go/internal/waf/settings"
	"nginx-analyzer-go/internal/waf/store"
)

// Config : configuration du service (variables d'environnement du contrat).
type Config struct {
	Version            string
	LogsDir            string
	LogPattern         *regexp.Regexp
	WafLogPattern      *regexp.Regexp
	DataDir            string
	RulesDir           string
	CRSVersion         string
	CRSURLTemplate     string
	HitRetentionDays   int
	AlertRetentionDays int

	// Reglages internes (tests / ajustements) ; zero = valeur par defaut.
	PollMs        int
	ReadFromStart bool
	Workers       int
	QueueSize     int
	Downloader    *crs.Downloader
}

const (
	maxVhostsSeen = 5000
	defaultQueue  = 65536
)

type vhostInfo struct {
	lines  int64
	last   int64
	format string
	dirty  bool
}

type result struct {
	e    *logsource.Entry
	kept []engine.Hit
	mode string
	ok   bool // evaluation reussie
}

// Service : etat global.
type Service struct {
	cfg  Config
	set  *settings.Holder
	eng  *engine.Engine
	crs  *crs.Manager
	st   *store.Store
	trk  *scoring.Tracker
	src  atomic.Pointer[logsource.Source]
	offs *store.Offsets

	jobs    chan *logsource.Entry
	results chan result

	workersWG sync.WaitGroup
	aggWG     sync.WaitGroup
	bgWG      sync.WaitGroup
	stop      chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc

	inflight    atomic.Int64
	flushCh     chan chan struct{}
	jobsMu      sync.RWMutex
	jobsClosed  bool
	startSource sync.Once
	closeOnce   sync.Once

	// compteurs
	linesAnalyzed atomic.Int64
	queueDropped  atomic.Int64
	notReady      atomic.Int64
	evalErrors    atomic.Int64
	avgEvalBits   atomic.Uint64
	rate          rateMeter

	vhMu sync.Mutex
	vh   map[string]*vhostInfo

	dd *dedup

	nextAlertID atomic.Int64
	customMu    sync.Mutex
	reloadMu    sync.Mutex

	startedAt time.Time
}

// New construit le service (sans le demarrer). Une base SQLite indisponible n'est pas
// fatale : le service tourne alors sans persistance (erreur journalisee).
func New(cfg Config) (*Service, error) {
	if cfg.HitRetentionDays <= 0 {
		cfg.HitRetentionDays = 30
	}
	if cfg.AlertRetentionDays <= 0 {
		cfg.AlertRetentionDays = 90
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueue
	}
	if cfg.Workers <= 0 {
		cfg.Workers = maxInt(2, goMaxProcs()-1)
	}
	set, err := settings.NewHolder(filepath.Join(cfg.DataDir, "settings.json"))
	if err != nil {
		log.Printf("[waf] %v", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "waf.db"))
	if err != nil {
		log.Printf("[waf] SQLite indisponible, fonctionnement sans persistance : %v", err)
		st = store.Disabled()
	}
	dl := cfg.Downloader
	if dl == nil {
		dl = crs.NewDownloader(cfg.CRSURLTemplate)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{
		cfg: cfg, set: set, st: st,
		eng:       engine.New(cfg.RulesDir),
		crs:       crs.NewManager(cfg.RulesDir, cfg.CRSVersion, dl),
		trk:       scoring.New(),
		dd:        newDedup(),
		jobs:      make(chan *logsource.Entry, cfg.QueueSize),
		results:   make(chan result, 4096),
		flushCh:   make(chan chan struct{}),
		stop:      make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
		vh:        map[string]*vhostInfo{},
		startedAt: time.Now(),
	}
	s.restore()
	return s, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// restore recharge l'etat persiste (listes, graces, marques d'alerte, vhosts, offsets).
func (s *Service) restore() {
	if !s.st.OK() {
		s.offs = store.NewOffsets(nil, s.cfg.ReadFromStart)
		return
	}
	ctx := context.Background()
	now := time.Now().UnixMilli()
	var ls []scoring.Listed
	for _, r := range s.st.LoadListed(ctx, now) {
		ls = append(ls, scoring.Listed{IP: r.IP, List: r.List, Score: r.Score, Hits: r.Hits, Since: r.Since, Until: r.Until, Vhosts: r.Vhosts, TopRules: r.TopRules})
	}
	marks := map[string]scoring.Mark{}
	win := int64(s.set.Get().S.WindowMinutes) * 60000
	for _, a := range s.st.RecentAlerts(ctx, now-win) {
		marks[a.IP] = scoring.Mark{TS: a.TS, Severity: a.Severity}
	}
	s.trk.Restore(ls, s.st.LoadGrace(ctx, now), marks)
	s.nextAlertID.Store(s.st.MaxAlertID(ctx))
	for _, v := range s.st.LoadVhosts(ctx) {
		s.vh[v.Name] = &vhostInfo{lines: v.Lines, last: v.LastSeen, format: v.Format}
	}
	s.offs = store.NewOffsets(s.st.LoadOffsets(ctx), s.cfg.ReadFromStart)
}

// Start demarre workers, agregateur, boucles de fond et le chargement du moteur (asynchrone :
// l'API peut etre ouverte avant). La lecture des logs demarre des que le moteur est pret.
func (s *Service) Start() {
	for i := 0; i < s.cfg.Workers; i++ {
		s.workersWG.Add(1)
		go s.worker()
	}
	s.aggWG.Add(1)
	go s.aggregator()
	s.bgWG.Add(2)
	go s.background()
	go s.rate.run(&s.linesAnalyzed, s.stop, &s.bgWG)
	go s.initEngine()
}

func (s *Service) initEngine() {
	if s.crs.Empty() {
		log.Printf("[waf] CRS absent : telechargement de %s", s.cfg.CRSVersion)
		if err := s.crs.Start(s.ctx, s.cfg.CRSVersion, func() { _ = s.ReloadEngine() }); err != nil {
			log.Printf("[waf] telechargement impossible : %v", err)
		}
		return
	}
	if err := s.ReloadEngine(); err != nil {
		log.Printf("[waf] chargement du moteur : %v", err)
	}
}

// ReloadEngine (re)charge le moteur avec le paranoia effectif courant. A la premiere
// reussite, la lecture des logs demarre.
func (s *Service) ReloadEngine() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	ver := s.crs.InstalledVersion()
	if ver == "" {
		ver = s.cfg.CRSVersion
	}
	par := s.set.Get().EffectiveParanoia()
	if err := s.eng.Reload(s.ctx, par, ver); err != nil {
		return err
	}
	info := s.eng.Info()
	log.Printf("[waf] moteur charge : %d regles, paranoia %d, %d fichier(s) ignore(s)", info.RulesLoaded, par, len(info.FilesIgnored))
	s.startSource.Do(s.beginSource)
	return nil
}

func (s *Service) beginSource() {
	src := logsource.New(logsource.Options{
		Dir: s.cfg.LogsDir, Pattern: s.cfg.LogPattern, WafPattern: s.cfg.WafLogPattern,
		PollMs: s.cfg.PollMs, Offsets: s.offs, OnEntry: s.onEntry,
	})
	s.src.Store(src)
	src.Start()
	// Le premier Poll est synchrone : les fichiers waf_json deja presents sont connus, le dedoublonnage
	// est donc actif des la premiere ligne ; la boucle de fond l'affine ensuite (fichier cree plus tard).
	s.dd.jsonActive.Store(src.WafFilesFollowed())
}

// PollNow force une passe de lecture (tests).
func (s *Service) PollNow() {
	if src := s.src.Load(); src != nil {
		src.Poll()
	}
}

// Sync attend que toutes les lignes deja soumises au pipeline soient evaluees, comptabilisees
// (scoring, listes, alertes) et ecrites en base. Utile aux tests et a un arret propre.
func (s *Service) Sync(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	// Lignes combined retenues par le dedoublonnage : liberees tout de suite (utilise par les tests).
	for _, e := range s.dd.drain() {
		s.enqueue(e)
	}
	for s.inflight.Load() > 0 {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
	ch := make(chan struct{})
	select {
	case s.flushCh <- ch:
		<-ch
		return true
	case <-time.After(time.Until(deadline)):
		return false
	}
}

// Close arrete proprement : source, workers, agregateur, ecritures puis base.
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		if src := s.src.Load(); src != nil {
			src.Stop()
		}
		for _, e := range s.dd.drain() { // lignes combined encore retenues : analysees avant l'arret
			s.enqueue(e)
		}
		s.jobsMu.Lock()
		s.jobsClosed = true
		close(s.jobs)
		s.jobsMu.Unlock()
		s.workersWG.Wait()
		close(s.results)
		s.aggWG.Wait()
		close(s.stop)
		s.bgWG.Wait()
		s.flushOffsetsAndVhosts()
		_ = s.st.Close()
	})
}

// ---------- entree des lignes ----------

var reVhostPort = regexp.MustCompile(`^([^:\[\]]+):\d{1,5}$`)

func (s *Service) normVhost(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if m := reVhostPort.FindStringSubmatch(v); m != nil {
		v = m[1]
	}
	if n, ok := settings.NormalizeVhost(v); ok {
		return n
	}
	return "(invalide)"
}

func (s *Service) noteVhost(e *logsource.Entry) {
	now := time.Now().UnixMilli()
	s.vhMu.Lock()
	defer s.vhMu.Unlock()
	vi := s.vh[e.Vhost]
	if vi == nil {
		if len(s.vh) >= maxVhostsSeen {
			e.Vhost = "(autres)"
			vi = s.vh[e.Vhost]
		}
		if vi == nil {
			vi = &vhostInfo{}
			s.vh[e.Vhost] = vi
		}
	}
	vi.lines++
	vi.last = now
	vi.format = e.Format
	vi.dirty = true
}

// onEntry est appele par le tailer : ne bloque jamais (file bornee, compteur de pertes).
func (s *Service) onEntry(e *logsource.Entry) {
	if e.Skip {
		return
	}
	if s.dd != nil && !s.dd.admit(e, time.Now()) {
		return
	}
	s.enqueue(e)
}

// enqueue : filtres de reglages puis mise en file (appele aussi par la purge du dedoublonnage).
func (s *Service) enqueue(e *logsource.Entry) {
	e.Vhost = s.normVhost(e.Vhost)
	s.noteVhost(e)
	c := s.set.Get()
	if !c.S.Enable || !c.VhostAnalyzed(e.Vhost) || !parse.LooksLikeIP(e.IP) ||
		c.IPExcluded(e.IP) || c.IgnoredStatus(e.Status) {
		return
	}
	s.jobsMu.RLock()
	defer s.jobsMu.RUnlock()
	if s.jobsClosed {
		return
	}
	s.inflight.Add(1)
	select {
	case s.jobs <- e:
	default:
		s.inflight.Add(-1)
		s.queueDropped.Add(1)
	}
}

// rateMeter : debit (lignes analysees / s) sur ~10 s.
type rateMeter struct {
	mu      sync.Mutex
	samples [10]struct {
		t time.Time
		n int64
	}
	idx, cnt int
}

func (r *rateMeter) run(c *atomic.Int64, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case t := <-tk.C:
			r.mu.Lock()
			r.samples[r.idx].t, r.samples[r.idx].n = t, c.Load()
			r.idx = (r.idx + 1) % len(r.samples)
			if r.cnt < len(r.samples) {
				r.cnt++
			}
			r.mu.Unlock()
		}
	}
}

func (r *rateMeter) perSecond(cur int64) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cnt < 2 {
		return 0
	}
	newest := r.samples[(r.idx-1+len(r.samples))%len(r.samples)]
	oldest := r.samples[(r.idx-r.cnt+len(r.samples))%len(r.samples)]
	dt := newest.t.Sub(oldest.t).Seconds()
	if dt <= 0 {
		return 0
	}
	return float64(newest.n-oldest.n) / dt
}
