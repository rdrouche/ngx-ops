package challenge

import (
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nginx-challenge/internal/wire"
)

//go:embed web/*
var webFS embed.FS

// Prefix est le chemin (sous chaque vhost protégé) où nginx route le service.
const Prefix = "/.nc-challenge/"

// Server regroupe les gestionnaires HTTP.
type Server struct {
	cfg    Config
	sign   *Signer
	rl     *limiter
	used   *usedSet
	bots   *BotVerifier
	page   *template.Template
	assets http.Handler
	stats  *Stats
	off    *Offenders
	em     Emitter // décisions vers le log store (nil = aucun envoi)
	es     emitState
}

// New construit le serveur.
func New(cfg Config) (*Server, error) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}
	tpl, err := template.ParseFS(sub, "page.html")
	if err != nil {
		return nil, err
	}
	var bots *BotVerifier
	if cfg.GoodBots {
		bots = NewBotVerifier(append(DefaultBotRules(), cfg.ExtraBots...))
	}
	return &Server{
		cfg: cfg, sign: NewSigner(cfg), rl: newLimiter(cfg.RateLimit), used: newUsedSet(), bots: bots,
		page: tpl, assets: http.FileServer(http.FS(sub)),
		stats: NewStats(cfg.StatsFile), off: NewOffenders(cfg.Offenders),
	}, nil
}

// Handler renvoie le routeur. Routage manuel (pas de http.ServeMux) : le mux
// « nettoie » les chemins (// et ..), ce qui altérerait l'URL d'origine portée
// par /.nc-challenge/go<URI>.
// Stats expose l'accumulateur (flush périodique par main).
func (s *Server) Stats() *Stats { return s.stats }

// Offenders expose le suivi des IP en échec.
func (s *Server) Offenders() *Offenders { return s.off }

// note compte un évènement dans les statistiques agrégées ET dans le suivi par IP.
func (s *Server) note(r *http.Request, f func(*Counts)) {
	s.stats.Inc(f)
	s.off.Record(r.Header.Get("X-Real-IP"), r.UserAgent(), HostOnly(r.Host), f)
}

func (s *Server) Handler() http.Handler {
	return secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/check":
			s.handleCheck(w, r)
		case p == "/stats":
			s.handleStats(w, r)
		case p == "/offenders" || p == "/bans" || p == "/blocklist" || p == "/unban":
			s.handleOffenders(w, r)
		case p == "/healthz":
			_, _ = w.Write([]byte("ok"))
		case p == Prefix+"go" || strings.HasPrefix(p, Prefix+"go/"):
			s.handleGo(w, r)
		case p == Prefix+"api/start":
			s.handleStart(w, r)
		case p == Prefix+"api/verify":
			s.handleVerify(w, r)
		case strings.HasPrefix(p, Prefix+"assets/"):
			s.handleAsset(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
}

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// client lit l'adresse posée par nginx (X-Real-IP) et l'hôte (Host).
func (s *Server) client(r *http.Request) (key, host string, ok bool) {
	key = ClientKey(r.Header.Get("X-Real-IP"), s.cfg.BindIP)
	host = HostOnly(r.Host)
	return key, host, key != "" && host != ""
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// handleCheck : sous-requête auth_request de nginx. 204 = laisser passer,
// 401 = renvoyer vers la page de défi.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	key, host, ok := s.client(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// IP bloquée automatiquement (trop d'échecs au challenge) : refus immédiat, sans attendre
	// que la blocklist nginx soit régénérée. Un cookie valide ne contourne pas le blocage.
	if s.off.Banned(r.Header.Get("X-Real-IP")) {
		s.stats.Inc(func(c *Counts) { c.Blocked++ })
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if c, err := r.Cookie(s.cfg.CookieName); err == nil && s.sign.CheckCookie(c.Value, key, host) {
		s.stats.Inc(func(c *Counts) { c.PassCookie++ })
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Vhost « challenge tout le monde sauf les bons robots » : nginx pose
	// X-NC-Allow-Bots: 1 (jamais lisible ni modifiable par le client). Un robot
	// n'est accepté que si son adresse passe la vérification DNS inverse.
	if r.Header.Get("X-NC-Allow-Bots") == "1" && s.bots != nil {
		if ok, _ := s.bots.Verify(r.UserAgent(), strings.TrimSpace(r.Header.Get("X-Real-IP"))); ok {
			s.stats.Inc(func(c *Counts) { c.PassBot++ })
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	// Stats globales : toute redirection. Suivi par IP (et blocage automatique) : seulement les
	// navigations, une fois par rafale — le favicon et les ressources d'une même page ne sont pas
	// des « échecs » (v12.78.1).
	s.stats.Inc(func(c *Counts) { c.Redirected++ })
	if IsNavigation(r.Header.Get("Sec-Fetch-Dest")) {
		s.off.RecordRedirect(r.Header.Get("X-Real-IP"), r.UserAgent(), HostOnly(r.Host), func(c *Counts) { c.Redirected++ })
		s.emitRedirect(r)
	}
	w.WriteHeader(http.StatusUnauthorized)
}

type pageData struct {
	Target string
	Assets string
	Lang   string
	Text   pageText
}

// pageText : textes de la page avant exécution du JavaScript (le script reprend la même langue).
type pageText struct{ Title, Heading, Msg, NoScript, Retry string }

var pageTexts = map[string]pageText{
	"fr": {"Vérification…", "Vérification de votre navigateur", "Un instant, nous vérifions que vous n'êtes pas un robot…",
		"JavaScript est nécessaire pour cette vérification.", "Réessayer"},
	"en": {"Checking…", "Checking your browser", "One moment, we are checking that you are not a robot…",
		"JavaScript is required for this check.", "Retry"},
}

// pageLang : NC_LANG s'il est fixé, sinon la langue préférée du navigateur (fr, sinon en).
func pageLang(configured, acceptLanguage string) string {
	if configured == "fr" || configured == "en" {
		return configured
	}
	for _, part := range strings.Split(acceptLanguage, ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		if strings.HasPrefix(tag, "fr") {
			return "fr"
		}
		if strings.HasPrefix(tag, "en") {
			return "en"
		}
	}
	return "en"
}

// handleGo sert la page de vérification. L'URL d'origine est portée par le
// chemin (/.nc-challenge/go<URI d'origine>) : aucune re-échappée nécessaire.
func (s *Server) handleGo(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	target := SafeTarget(strings.TrimPrefix(r.URL.RequestURI(), strings.TrimSuffix(Prefix, "/")+"/go"))
	if key, host, ok := s.client(r); ok {
		if c, err := r.Cookie(s.cfg.CookieName); err == nil && s.sign.CheckCookie(c.Value, key, host) {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; worker-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusOK)
	s.note(r, func(c *Counts) { c.Pages++ })
	lang := pageLang(s.cfg.Lang, r.Header.Get("Accept-Language"))
	_ = s.page.Execute(w, pageData{Target: target, Assets: Prefix + "assets/", Lang: lang, Text: pageTexts[lang]})
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	r2 := r.Clone(r.Context())
	r2.URL.Path = strings.TrimPrefix(r.URL.Path, Prefix+"assets")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	s.assets.ServeHTTP(w, r2)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "méthode"})
		return
	}
	key, host, ok := s.client(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "client"})
		return
	}
	if !s.rl.allow(key) {
		s.note(r, func(c *Counts) { c.RateLimited++ })
		s.emitReq(r, wire.ActionBlocked, "rate_limited", map[string]any{"stage": "start"})
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "trop de tentatives"})
		return
	}
	tok, err := s.sign.NewChallenge(key, host)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "interne"})
		return
	}
	s.note(r, func(c *Counts) { c.Started++ })
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "bits": s.cfg.Bits})
}

type verifyReq struct {
	Token   string `json:"token"`
	Counter string `json:"counter"`
	Target  string `json:"target"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "méthode"})
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "origine"})
		return
	}
	key, host, ok := s.client(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "client"})
		return
	}
	if !s.rl.allow(key) {
		s.note(r, func(c *Counts) { c.RateLimited++ })
		s.emitReq(r, wire.ActionBlocked, "rate_limited", map[string]any{"stage": "verify"})
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "trop de tentatives"})
		return
	}
	var req verifyReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "requête"})
		return
	}
	bits, ok := s.sign.CheckChallenge(req.Token, key, host)
	if !ok {
		s.note(r, func(c *Counts) { c.Failed++ })
		s.emitReq(r, wire.ActionChallenged, "failed", map[string]any{"reason": "expired_or_invalid"})
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "défi expiré ou invalide", "retry": true})
		return
	}
	if !SolutionOK(req.Token, req.Counter, bits) {
		s.note(r, func(c *Counts) { c.Failed++ })
		s.emitReq(r, wire.ActionChallenged, "failed", map[string]any{"reason": "wrong_solution"})
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "solution incorrecte", "retry": true})
		return
	}
	if !s.used.add(req.Token, time.Now().Add(s.cfg.TokenTTL+time.Minute)) {
		s.note(r, func(c *Counts) { c.Failed++ })
		s.emitReq(r, wire.ActionChallenged, "failed", map[string]any{"reason": "reused"})
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "défi déjà utilisé", "retry": true})
		return
	}
	s.note(r, func(c *Counts) { c.Solved++ })
	s.emitReq(r, wire.ActionAllowed, "solved", map[string]any{"bits": bits})
	val, exp := s.sign.NewCookie(key, host)
	http.SetCookie(w, &http.Cookie{
		Name: s.cfg.CookieName, Value: val, Path: "/", Expires: exp, MaxAge: int(s.cfg.CookieTTL.Seconds()),
		HttpOnly: true, Secure: s.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "target": SafeTarget(req.Target)})
}

// handleStats : compteurs agrégés pour le dashboard. Réservé au réseau interne :
// nginx pose toujours X-Real-IP sur ce qu'il relaie, une requête qui en porte un
// vient donc d'un visiteur et est refusée.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Real-IP") != "" || r.Header.Get("X-Forwarded-For") != "" {
		http.NotFound(w, r)
		return
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			hours = n
		}
	}
	writeJSON(w, http.StatusOK, s.stats.Snapshot(hours))
}

// internalOnly : réservé au réseau interne (nginx pose toujours X-Real-IP sur ce qu'il relaie).
func internalOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Real-IP") != "" || r.Header.Get("X-Forwarded-For") != "" {
		http.NotFound(w, r)
		return false
	}
	return true
}

func qInt(r *http.Request, name string, def, lo, hi int) int {
	n := def
	if v := r.URL.Query().Get(name); v != "" {
		if x, err := strconv.Atoi(v); err == nil {
			n = x
		}
	}
	if n < lo {
		n = lo
	}
	if n > hi {
		n = hi
	}
	return n
}

// handleOffenders : analyse des IP en échec (/offenders), blocages actifs (/bans, avec
// ?since=<seq> pour l'historique des déclenchements), liste texte pour la blocklist
// (/blocklist) et levée d'un blocage (POST /unban?ip=). Réservé au réseau interne.
func (s *Server) handleOffenders(w http.ResponseWriter, r *http.Request) {
	if !internalOnly(w, r) {
		return
	}
	switch r.URL.Path {
	case "/offenders":
		list := s.off.Report(qInt(r, "hours", 24, 1, 168), qInt(r, "min", 3, 1, 100000), qInt(r, "limit", 200, 1, 1000), r.URL.Query().Get("neverSolved") != "0")
		cfg := s.cfg.Offenders
		writeJSON(w, http.StatusOK, map[string]any{
			"offenders": list,
			"config": map[string]any{"autoblock": cfg.Autoblock, "threshold": cfg.Threshold, "windowMinutes": int(cfg.Window / time.Minute),
				"banHours": int(cfg.BanFor / time.Hour), "retentionHours": int(cfg.Retention / time.Hour)},
		})
	case "/bans":
		if v := r.URL.Query().Get("since"); v != "" {
			since, _ := strconv.ParseInt(v, 10, 64)
			writeJSON(w, http.StatusOK, map[string]any{"events": s.off.BanEvents(since, qInt(r, "limit", 100, 1, 200)), "latest": s.off.LatestSeq()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"bans": s.off.Bans()})
	case "/blocklist":
		noStore(w)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(s.off.BlocklistText()))
	case "/unban":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "méthode"})
			return
		}
		ip := NormIP(r.URL.Query().Get("ip"))
		if ip == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": s.off.Unban(ip)})
	}
}
