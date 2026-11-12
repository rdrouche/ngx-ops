// Package api expose l'API HTTP du log store.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"ngxops/logstore/internal/auth"
	"ngxops/logstore/internal/config"
	"ngxops/logstore/internal/ipmode"
	"ngxops/logstore/internal/store"
)

// Version est renseignée à la compilation (-ldflags).
var Version = "dev"

// Server regroupe les dépendances des handlers.
type Server struct {
	cfg      config.Config
	store    *store.Store
	verifier *auth.Verifier
	ip       *ipmode.Transformer
	log      *slog.Logger
	limits   *limiter
	authFail *limiter
}

// New construit le serveur. Les jetons doivent être chargés avant (ReloadTokens).
func New(cfg config.Config, st *store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg: cfg, store: st, log: log,
		verifier: &auth.Verifier{},
		ip:       ipmode.New(cfg.PseudoKey),
		limits:   newLimiter(),
		authFail: newLimiter(),
	}
}

// ReloadTokens recharge les jetons actifs en mémoire.
func (s *Server) ReloadTokens(ctx context.Context) error {
	e, err := s.store.ActiveTokens(ctx)
	if err != nil {
		return err
	}
	s.verifier.Set(e)
	return nil
}

// FlushTokenUsage écrit les horodatages d'usage (appelé périodiquement).
func (s *Server) FlushTokenUsage(ctx context.Context) {
	if ids := s.verifier.FlushUsed(); len(ids) > 0 {
		if err := s.store.TouchTokens(ctx, ids); err != nil {
			s.log.Warn("last_used_at non mis à jour", "err", err.Error())
		}
	}
}

// Handler renvoie le routeur complet.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("POST /v1/ingest", s.guard(auth.RoleWrite, s.ingest))
	mux.HandleFunc("GET /v1/events", s.guard(auth.RoleRead, s.events))
	mux.HandleFunc("GET /v1/ips/{ip}", s.guard(auth.RoleRead, s.ipHistory))
	mux.HandleFunc("GET /v1/stats/visits", s.guard(auth.RoleRead, s.statsVisits))
	mux.HandleFunc("GET /v1/stats/top", s.guard(auth.RoleRead, s.statsTop))
	mux.HandleFunc("GET /v1/stats/security", s.guard(auth.RoleRead, s.statsSecurity))
	mux.HandleFunc("GET /v1/stats/ips", s.guard(auth.RoleRead, s.statsIPs))
	mux.HandleFunc("GET /v1/stats/campaigns", s.guard(auth.RoleRead, s.statsCampaigns))
	mux.HandleFunc("GET /v1/instances", s.guard(auth.RoleRead, s.instances))
	mux.HandleFunc("GET /v1/settings", s.guard(auth.RoleRead, s.getSettings))
	mux.HandleFunc("PUT /v1/settings", s.guard(auth.RoleAdmin, s.putSettings))
	mux.HandleFunc("GET /v1/tokens", s.guard(auth.RoleAdmin, s.listTokens))
	mux.HandleFunc("POST /v1/tokens", s.guard(auth.RoleAdmin, s.createToken))
	mux.HandleFunc("DELETE /v1/tokens/{id}", s.guard(auth.RoleAdmin, s.revokeToken))
	mux.HandleFunc("GET /v1/maintenance", s.guard(auth.RoleAdmin, s.getMaintenance))
	mux.HandleFunc("POST /v1/maintenance", s.guard(auth.RoleAdmin, s.runMaintenance))
	if s.cfg.UIEnabled {
		mux.HandleFunc("GET /ui/{$}", s.uiHandler)
		mux.HandleFunc("GET /ui/app.js", s.uiHandler)
		mux.HandleFunc("GET /ui/style.css", s.uiHandler)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, 404, "not_found", "") })
	return s.wrap(mux)
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

// wrap : en-têtes de sécurité, récupération de panique, journal d'accès
// (jamais de query string ni d'en-tête Authorization).
func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: 200}
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic dans un handler", "path", r.URL.Path)
				if sw.code == 200 {
					writeErr(sw, 500, "internal", "")
				}
			}
			s.log.Debug("requête", "method", r.Method, "path", r.URL.Path, "status", sw.code, "ms", time.Since(start).Milliseconds())
		}()
		next.ServeHTTP(sw, r)
	})
}

type handlerFn func(http.ResponseWriter, *http.Request, auth.Identity)

// guard authentifie, limite le débit puis autorise selon le rôle exigé.
func (s *Server) guard(need string, h handlerFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remote, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ok, retry := s.authFail.peek(remote, 5, 20); !ok {
			tooMany(w, retry)
			return
		}
		id, ok := s.verifier.Verify(auth.Bearer(r.Header.Get("Authorization")))
		if !ok {
			s.authFail.take(remote, 5, 20)
			w.Header().Set("WWW-Authenticate", `Bearer realm="logstore"`)
			writeErr(w, 401, "unauthorized", "")
			return
		}
		if !id.Allows(need) {
			writeErr(w, 403, "forbidden", "")
			return
		}
		rate := s.cfg.RateRead
		if id.Role == auth.RoleWrite {
			rate = s.cfg.RateWrite
		}
		if ok, retry := s.limits.take("t"+strconv.FormatInt(id.TokenID, 10), rate, rate*3); !ok {
			tooMany(w, retry)
			return
		}
		h(w, r, id)
	}
}

func tooMany(w http.ResponseWriter, retry time.Duration) {
	secs := int(retry.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, 429, "rate_limited", "")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr n'expose que des codes courts et, au plus, une précision issue de
// notre propre validation (jamais d'erreur SQL ni d'URL de base).
func writeErr(w http.ResponseWriter, code int, errCode, detail string) {
	body := map[string]string{"error": errCode}
	if detail != "" {
		body["detail"] = detail
	}
	writeJSON(w, code, body)
}

// ---- limiteur (seau à jetons par clé) ----

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu     sync.Mutex
	b      map[string]*bucket
	lastGC time.Time
}

func newLimiter() *limiter { return &limiter{b: map[string]*bucket{}} }

func (l *limiter) get(key string, rate, burst float64, now time.Time) *bucket {
	if now.Sub(l.lastGC) > time.Minute {
		for k, v := range l.b {
			if now.Sub(v.last) > 10*time.Minute {
				delete(l.b, k)
			}
		}
		l.lastGC = now
	}
	b := l.b[key]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		l.b[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	return b
}

// take consomme un jeton ; sinon renvoie le délai avant le suivant.
func (l *limiter) take(key string, rate, burst float64) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.get(key, rate, burst, time.Now())
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / rate * float64(time.Second))
}

// peek vérifie sans consommer (l'échec d'authentification consomme via take).
func (l *limiter) peek(key string, rate, burst float64) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.get(key, rate, burst, time.Now())
	if b.tokens >= 1 {
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / rate * float64(time.Second))
}
