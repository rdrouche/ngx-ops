package challenge

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"nginx-challenge/internal/redislite"
)

// Persistance optionnelle dans Redis (NC_REDIS_URL) : les statistiques, le suivi
// des IP en échec / blocages et les jetons anti-rejeu survivent à un redémarrage
// du conteneur. Sans Redis, rien ne change. Toute erreur Redis est journalisée
// puis ignorée : le challenge ne dépend jamais de Redis pour répondre.

const (
	redisKeyTTL      = 7 * 24 * time.Hour
	persistEvery     = 15 * time.Second
	persistVersion   = 1
	maxRestoreBytes  = 64 << 20
	persistErrLogGap = 5 * time.Minute
)

// Persister relie Stats / Offenders / usedSet à Redis.
type Persister struct {
	cl     *redislite.Client
	prefix string
	srv    *Server

	lastVer  map[string]uint64
	lastErr  time.Time
	LastOK   time.Time
	Restored map[string]int // nombre d'éléments restaurés (journal de démarrage)
}

// NewPersister renvoie nil si Redis n'est pas configuré (url vide).
func NewPersister(url, password, prefix string, srv *Server) (*Persister, error) {
	if strings.TrimSpace(url) == "" {
		return nil, nil
	}
	cl, err := redislite.Parse(url, password)
	if err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix = "ngx"
	}
	return &Persister{cl: cl, prefix: prefix + ":challenge:", srv: srv, lastVer: map[string]uint64{}, Restored: map[string]int{}}, nil
}

// Addr : adresse sans identifiants (journaux).
func (p *Persister) Addr() string { return p.cl.Redacted() }

func (p *Persister) warn(what string, err error) {
	if time.Since(p.lastErr) > persistErrLogGap {
		log.Printf("redis (%s) : %v — poursuite sans persistance", what, err)
		p.lastErr = time.Now()
	}
}

type usedFile struct {
	V    int              `json:"v"`
	Used map[string]int64 `json:"used"` // id → expiration (epoch s)
}

type offFile struct {
	V    int                `json:"v"`
	Seq  int64              `json:"seq"`
	Recs map[string]*recOut `json:"recs"`
	Bans map[string]*Ban    `json:"bans"`
	Log  []Ban              `json:"log"`
}

type recOut struct {
	First     int64             `json:"first"`
	Last      int64             `json:"last"`
	Hours     map[int64]*Counts `json:"hours"`
	Fails     []int64           `json:"fails,omitempty"`
	LastSolve int64             `json:"lastSolve,omitempty"`
	UA        string            `json:"ua,omitempty"`
	Host      string            `json:"host,omitempty"`
}

// ---- export / import (sous le verrou de chaque composant) ----

func (s *Stats) exportJSON() ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(statsFile{Since: s.since, Hours: s.hours})
	return b, s.ver, err
}

// mergeJSON : fusionne un instantané Redis ; pour chaque heure, le compteur le plus élevé l'emporte.
func (s *Stats) mergeJSON(b []byte) int {
	var f statsFile
	if json.Unmarshal(b, &f) != nil || f.Hours == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.nowFunc().Add(-statsRetention).Unix()
	n := 0
	for h, c := range f.Hours {
		if c == nil || h < cut {
			continue
		}
		cur := s.hours[h]
		if cur == nil || sumCounts(*c) > sumCounts(*cur) {
			cc := *c
			s.hours[h] = &cc
			n++
		}
	}
	if f.Since > 0 && f.Since < s.since {
		s.since = f.Since
	}
	return n
}

func sumCounts(c Counts) int {
	return c.Redirected + c.Pages + c.Started + c.Solved + c.Failed + c.RateLimited + c.PassCookie + c.PassBot + c.Blocked
}

func (o *Offenders) exportJSON() ([]byte, uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	f := offFile{V: persistVersion, Seq: o.seq, Recs: make(map[string]*recOut, len(o.recs)), Bans: o.bans, Log: o.log}
	for ip, r := range o.recs {
		f.Recs[ip] = &recOut{First: r.First, Last: r.Last, Hours: r.Hours, Fails: r.Fails, LastSolve: r.LastSolve, UA: r.UA, Host: r.Host}
	}
	b, err := json.Marshal(f)
	return b, o.ver, err
}

// importJSON : à n'appeler qu'au démarrage (tables vides). Les blocages expirés sont ignorés.
func (o *Offenders) importJSON(b []byte) int {
	var f offFile
	if json.Unmarshal(b, &f) != nil || f.V != persistVersion {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	cut := now.Add(-o.cfg.Retention).Unix()
	n := 0
	for ip, r := range f.Recs {
		if r == nil || NormIP(ip) != ip || r.Last < cut || len(o.recs) >= maxTrackedIPs {
			continue
		}
		if r.Hours == nil {
			r.Hours = map[int64]*Counts{}
		}
		if len(r.Fails) > maxFailStamps {
			r.Fails = r.Fails[len(r.Fails)-maxFailStamps:]
		}
		o.recs[ip] = &ipRec{First: r.First, Last: r.Last, Hours: r.Hours, Fails: r.Fails, LastSolve: r.LastSolve, UA: trunc(r.UA, maxUALen), Host: trunc(r.Host, 253)}
		n++
	}
	for ip, bn := range f.Bans {
		if bn != nil && NormIP(ip) == ip && now.Unix() < bn.Until {
			o.bans[ip] = bn
		}
	}
	if len(f.Log) > maxBanEvents {
		f.Log = f.Log[len(f.Log)-maxBanEvents:]
	}
	o.log = f.Log
	if f.Seq > o.seq {
		o.seq = f.Seq
	}
	return n
}

func (u *usedSet) exportJSON() ([]byte, uint64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	m := make(map[string]int64, len(u.m))
	for k, v := range u.m {
		if now.Before(v) {
			m[k] = v.Unix()
		}
	}
	b, err := json.Marshal(usedFile{V: persistVersion, Used: m})
	return b, u.ver, err
}

func (u *usedSet) importJSON(b []byte) int {
	var f usedFile
	if json.Unmarshal(b, &f) != nil || f.V != persistVersion {
		return 0
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	n := 0
	for k, exp := range f.Used {
		t := time.Unix(exp, 0)
		if now.Before(t) && len(u.m) < u.cap {
			u.m[k] = t
			n++
		}
	}
	return n
}

// ---- cycle de vie ----

type part struct {
	name   string
	export func() ([]byte, uint64, error)
	load   func([]byte) int
}

func (p *Persister) parts() []part {
	return []part{
		{"stats", p.srv.stats.exportJSON, p.srv.stats.mergeJSON},
		{"offenders", p.srv.off.exportJSON, p.srv.off.importJSON},
		{"used", p.srv.used.exportJSON, p.srv.used.importJSON},
	}
}

// Restore recharge l'état depuis Redis (au démarrage). Renvoie une erreur si Redis est injoignable.
func (p *Persister) Restore() error {
	if err := p.cl.Ping(); err != nil {
		return err
	}
	for _, pt := range p.parts() {
		b, ok, err := p.cl.Get(p.prefix + pt.name)
		if err != nil {
			p.warn("lecture "+pt.name, err)
			continue
		}
		if !ok || len(b) > maxRestoreBytes {
			continue
		}
		p.Restored[pt.name] = pt.load(b)
	}
	return nil
}

// Save écrit les composants modifiés depuis la dernière sauvegarde (force = tout).
func (p *Persister) Save(force bool) {
	for _, pt := range p.parts() {
		b, ver, err := pt.export()
		if err != nil {
			p.warn("export "+pt.name, err)
			continue
		}
		if !force && p.lastVer[pt.name] == ver && ver != 0 {
			continue
		}
		cl := p.cl
		if len(b) > 8<<20 {
			cl.CmdTimout = 5 * time.Second
		} else {
			cl.CmdTimout = 1500 * time.Millisecond
		}
		if err := cl.SetEX(p.prefix+pt.name, b, redisKeyTTL); err != nil {
			p.warn("écriture "+pt.name, err)
			continue
		}
		p.lastVer[pt.name] = ver
		p.LastOK = time.Now()
	}
}

// Run sauvegarde périodiquement ; une dernière sauvegarde complète a lieu à l'arrêt.
func (p *Persister) Run(stop <-chan struct{}) {
	t := time.NewTicker(persistEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			p.Save(false)
		case <-stop:
			p.Save(true)
			p.cl.Close()
			return
		}
	}
}
