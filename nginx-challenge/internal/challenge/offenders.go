package challenge

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Suivi par IP des visiteurs qui n'arrivent jamais à passer le challenge, et blocage
// automatique temporaire (v12.73.0).
//
// Une « tentative en échec » = requête renvoyée vers la page de vérification (401 du
// contrôle), solution fausse/expirée, ou trop de tentatives. Un visiteur légitime en
// fait quelques-unes puis résout (cookie) ; un robot sans JavaScript en fait des
// centaines sans jamais résoudre. Une IP qui a résolu le challenge au moins une fois
// pendant la période suivie n'est JAMAIS bloquée (réseaux partagés / NAT).
//
// Données conservées uniquement en mémoire (jamais écrites sur disque), bornées en nombre
// d'IP et en durée (NC_OFFENDERS_HOURS) ; un redémarrage du conteneur les efface.

const (
	maxTrackedIPs = 20000
	maxFailStamps = 600 // horodatages d'échecs conservés par IP (fenêtre glissante)
	maxBanEvents  = 200
	maxUALen      = 160
)

// OffendersConfig : réglages du suivi et du blocage automatique.
type OffendersConfig struct {
	Autoblock bool          // NC_AUTOBLOCK (défaut false)
	Threshold int           // NC_AUTOBLOCK_THRESHOLD : échecs dans la fenêtre pour déclencher (défaut 30)
	Window    time.Duration // NC_AUTOBLOCK_WINDOW_MIN (défaut 60 min)
	BanFor    time.Duration // NC_AUTOBLOCK_HOURS (défaut 24 h)
	Retention time.Duration // NC_OFFENDERS_HOURS : durée d'analyse conservée (défaut 24 h)
}

// DefaultOffendersConfig : valeurs par défaut (blocage désactivé, suivi actif).
func DefaultOffendersConfig() OffendersConfig {
	return OffendersConfig{Threshold: 30, Window: time.Hour, BanFor: 24 * time.Hour, Retention: 24 * time.Hour}
}

type ipRec struct {
	First, Last int64
	Hours       map[int64]*Counts
	Fails       []int64 // horodatages (s) des échecs récents
	LastSolve   int64
	UA, Host    string
}

// Ban : une IP bloquée temporairement.
type Ban struct {
	Seq         int64  `json:"seq"`
	IP          string `json:"ip"`
	Since       int64  `json:"since"`
	Until       int64  `json:"until"`
	Attempts    int    `json:"attempts"` // échecs dans la fenêtre au déclenchement
	Window      int    `json:"windowMinutes"`
	Redirected  int    `json:"redirected"`
	Failed      int    `json:"failed"`
	RateLimited int    `json:"rateLimited"`
	UA          string `json:"userAgent,omitempty"`
	Host        string `json:"host,omitempty"`
}

// Offenders : suivi thread-safe.
type Offenders struct {
	mu        sync.Mutex
	cfg       OffendersConfig
	recs      map[string]*ipRec
	bans      map[string]*Ban
	log       []Ban // historique des blocages déclenchés (anneau)
	seq       int64
	lastRedir map[string]int64 // dernière redirection comptée par IP (ms) : anti double-comptage
	ver       uint64           // incrémenté à chaque modification (sauvegarde Redis)
	now       func() time.Time
	onBan     func(Ban) // facultatif : notifié à chaque blocage automatique déclenché
}

// SetOnBan enregistre le rappel notifié à chaque blocage automatique (non bloquant exigé : appelé sous verrou).
func (o *Offenders) SetOnBan(f func(Ban)) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.onBan = f
	o.mu.Unlock()
}

// NewOffenders crée le suivi (cfg normalisée).
func NewOffenders(cfg OffendersConfig) *Offenders {
	d := DefaultOffendersConfig()
	if cfg.Threshold < 1 {
		cfg.Threshold = d.Threshold
	}
	if cfg.Window <= 0 {
		cfg.Window = d.Window
	}
	if cfg.BanFor <= 0 {
		cfg.BanFor = d.BanFor
	}
	if cfg.Retention <= 0 {
		cfg.Retention = d.Retention
	}
	if cfg.Retention < cfg.Window {
		cfg.Retention = cfg.Window
	}
	return &Offenders{cfg: cfg, recs: map[string]*ipRec{}, bans: map[string]*Ban{}, lastRedir: map[string]int64{}, now: time.Now}
}

// NormIP valide une adresse et renvoie sa forme canonique ("" si invalide).
func NormIP(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func isFail(c Counts) bool { return c.Redirected > 0 || c.Failed > 0 || c.RateLimited > 0 }

// Record applique f à l'IP (compteur de l'heure courante) et évalue le blocage automatique.
func (o *Offenders) Record(ip, ua, host string, f func(*Counts)) {
	if o == nil {
		return
	}
	ip = NormIP(ip)
	if ip == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ver++
	now := o.now()
	r := o.recs[ip]
	if r == nil {
		if len(o.recs) >= maxTrackedIPs {
			o.purgeLocked(now)
			if len(o.recs) >= maxTrackedIPs {
				return // table saturée : on ne suit plus de nouvelles IP (borne mémoire)
			}
		}
		r = &ipRec{First: now.Unix(), Hours: map[int64]*Counts{}}
		o.recs[ip] = r
	}
	r.Last = now.Unix()
	if ua != "" {
		r.UA = trunc(ua, maxUALen)
	}
	if host != "" {
		r.Host = trunc(host, 253)
	}
	h := now.Truncate(time.Hour).Unix()
	c := r.Hours[h]
	if c == nil {
		c = &Counts{}
		r.Hours[h] = c
		cut := now.Add(-o.cfg.Retention).Unix()
		for k := range r.Hours {
			if k+3600 < cut {
				delete(r.Hours, k)
			}
		}
	}
	var delta Counts
	f(&delta)
	c.add(delta)
	if delta.Solved > 0 {
		r.LastSolve = now.Unix()
	}
	if isFail(delta) {
		r.Fails = append(r.Fails, now.Unix())
		if len(r.Fails) > maxFailStamps {
			r.Fails = r.Fails[len(r.Fails)-maxFailStamps:]
		}
		o.evalLocked(ip, r, now)
	}
}

// evalLocked : déclenche le blocage si le seuil est atteint dans la fenêtre sans aucune résolution.
func (o *Offenders) evalLocked(ip string, r *ipRec, now time.Time) {
	if !o.cfg.Autoblock {
		return
	}
	if b := o.bans[ip]; b != nil && now.Unix() < b.Until {
		return
	}
	if r.LastSolve >= now.Add(-o.cfg.Retention).Unix() && r.LastSolve > 0 {
		return // a déjà résolu le challenge : navigateur réel (éventuellement derrière un NAT)
	}
	from := now.Add(-o.cfg.Window).Unix()
	n := 0
	for i := len(r.Fails) - 1; i >= 0 && r.Fails[i] >= from; i-- {
		n++
	}
	if n < o.cfg.Threshold {
		return
	}
	var tot Counts
	for _, c := range r.Hours {
		tot.add(*c)
	}
	o.seq++
	b := &Ban{
		Seq: o.seq, IP: ip, Since: now.Unix(), Until: now.Add(o.cfg.BanFor).Unix(), Attempts: n,
		Window: int(o.cfg.Window / time.Minute), Redirected: tot.Redirected, Failed: tot.Failed,
		RateLimited: tot.RateLimited, UA: r.UA, Host: r.Host,
	}
	o.bans[ip] = b
	o.log = append(o.log, *b)
	if o.onBan != nil {
		o.onBan(*b) // non bloquant (file bornée du client de décisions) : sûr sous le verrou
	}
	if len(o.log) > maxBanEvents {
		o.log = o.log[len(o.log)-maxBanEvents:]
	}
}

// Banned indique si l'IP est actuellement bloquée.
func (o *Offenders) Banned(ip string) bool {
	if o == nil {
		return false
	}
	ip = NormIP(ip)
	if ip == "" {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	b := o.bans[ip]
	if b == nil {
		return false
	}
	if o.now().Unix() >= b.Until {
		delete(o.bans, ip)
		return false
	}
	return true
}

// Unban retire un blocage et remet à zéro la fenêtre d'échecs de l'IP.
func (o *Offenders) Unban(ip string) bool {
	ip = NormIP(ip)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ver++
	_, ok := o.bans[ip]
	delete(o.bans, ip)
	if r := o.recs[ip]; r != nil {
		r.Fails = nil
	}
	return ok
}

// Bans : blocages actifs, du plus récent au plus ancien.
func (o *Offenders) Bans() []Ban {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now().Unix()
	out := []Ban{}
	for ip, b := range o.bans {
		if now >= b.Until {
			delete(o.bans, ip)
			continue
		}
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since > out[j].Since })
	return out
}

// BanEvents : blocages déclenchés depuis le numéro de séquence `since` (exclu), ordre croissant.
func (o *Offenders) BanEvents(since int64, limit int) []Ban {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := []Ban{}
	for _, b := range o.log {
		if b.Seq > since {
			out = append(out, b)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

// LatestSeq : numéro du dernier blocage déclenché (0 = aucun depuis le démarrage).
func (o *Offenders) LatestSeq() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.seq
}

// BlocklistText : IP actuellement bloquées, une par ligne (format attendu par les sources de blocklist).
func (o *Offenders) BlocklistText() string {
	var sb strings.Builder
	for _, b := range o.Bans() {
		sb.WriteString(b.IP)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// Offender : une ligne de l'analyse.
type Offender struct {
	IP          string `json:"ip"`
	Attempts    int    `json:"attempts"` // redirections + échecs + limitations
	Redirected  int    `json:"redirected"`
	Pages       int    `json:"pages"`
	Started     int    `json:"started"`
	Solved      int    `json:"solved"`
	Failed      int    `json:"failed"`
	RateLimited int    `json:"rateLimited"`
	First       int64  `json:"firstSeen"`
	Last        int64  `json:"lastSeen"`
	UA          string `json:"userAgent,omitempty"`
	Host        string `json:"host,omitempty"`
	BannedUntil int64  `json:"bannedUntil,omitempty"`
}

// Report : les IP en échec sur les `hours` dernières heures (au moins minAttempts tentatives),
// classées par nombre de tentatives, limitées à `limit`. neverSolved : exclut celles qui ont résolu.
func (o *Offenders) Report(hours, minAttempts, limit int, neverSolved bool) []Offender {
	if hours < 1 {
		hours = 24
	}
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	cut := now.Truncate(time.Hour).Add(-time.Duration(hours-1) * time.Hour).Unix()
	out := []Offender{}
	for ip, r := range o.recs {
		var t Counts
		for h, c := range r.Hours {
			if h >= cut {
				t.add(*c)
			}
		}
		att := t.Redirected + t.Failed + t.RateLimited
		if att < minAttempts || att == 0 || (neverSolved && t.Solved > 0) {
			continue
		}
		off := Offender{IP: ip, Attempts: att, Redirected: t.Redirected, Pages: t.Pages, Started: t.Started,
			Solved: t.Solved, Failed: t.Failed, RateLimited: t.RateLimited, First: r.First, Last: r.Last, UA: r.UA, Host: r.Host}
		if b := o.bans[ip]; b != nil && now.Unix() < b.Until {
			off.BannedUntil = b.Until
		}
		out = append(out, off)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Attempts != out[j].Attempts {
			return out[i].Attempts > out[j].Attempts
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (o *Offenders) purgeLocked(now time.Time) {
	cut := now.Add(-o.cfg.Retention).Unix()
	for ip, r := range o.recs {
		if r.Last < cut {
			delete(o.recs, ip)
		}
	}
	for ip, b := range o.bans {
		if now.Unix() >= b.Until {
			delete(o.bans, ip)
		}
	}
}

// Describe : résumé lisible de la configuration (journal de démarrage).
func (c OffendersConfig) Describe() string {
	if !c.Autoblock {
		return "blocage automatique désactivé (analyse des IP en échec active)"
	}
	return fmt.Sprintf("blocage automatique : %d échecs / %d min → %s", c.Threshold, int(c.Window/time.Minute), c.BanFor)
}

// redirDebounce : une même IP n'est comptée qu'une fois par intervalle pour les redirections. Un navigateur
// qui charge une page enchaîne en quelques millisecondes le document, le favicon, des ressources… tous
// renvoyés vers la page de vérification : sans cela, UNE navigation comptait pour 2 à 10 échecs.
const redirDebounce = 2 * time.Second

// IsNavigation indique si une requête est une navigation (document) plutôt qu'une sous-ressource
// (favicon, image, script, XHR/fetch). Les navigateurs modernes envoient Sec-Fetch-Dest ; son absence
// (robots, curl, vieux navigateurs) est comptée comme navigation.
func IsNavigation(secFetchDest string) bool {
	switch strings.ToLower(strings.TrimSpace(secFetchDest)) {
	case "", "document", "iframe", "frame", "embed", "object":
		return true
	}
	return false
}

// RecordRedirect compte une redirection vers la page de vérification dans le suivi par IP, sauf
// si elle suit de moins de redirDebounce une redirection déjà comptée pour cette IP.
func (o *Offenders) RecordRedirect(ip, ua, host string, f func(*Counts)) {
	if o == nil {
		return
	}
	nip := NormIP(ip)
	if nip == "" {
		return
	}
	nowMs := o.now().UnixMilli()
	o.mu.Lock()
	if last, ok := o.lastRedir[nip]; ok && nowMs-last < redirDebounce.Milliseconds() {
		o.mu.Unlock()
		return
	}
	if len(o.lastRedir) >= maxTrackedIPs {
		o.lastRedir = map[string]int64{}
	}
	o.lastRedir[nip] = nowMs
	o.mu.Unlock()
	o.Record(ip, ua, host, f)
}
