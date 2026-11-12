package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ngxops/logstore/internal/auth"
	"ngxops/logstore/internal/ipmode"
	"ngxops/logstore/internal/store"
	"ngxops/logstore/pkg/wire"
)

const (
	maxWindow     = 31 * 24 * time.Hour
	maxIPWindow   = 7 * 24 * time.Hour
	defaultWindow = time.Hour
	maxPage       = 500
	maxText       = 200
)

type badRequest string

func (b badRequest) Error() string { return string(b) }

// parseFilter lit la fenêtre et les critères communs. Les valeurs de texte
// libre restent bornées ; l'IP est transformée selon le mode courant.
func (s *Server) parseFilter(r *http.Request, defWindow time.Duration) (store.Filter, error) {
	// Une query string mal encodée serait ignorée en silence par r.URL.Query() :
	// le filtre sauterait et l'appelant recevrait des données non filtrées.
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return store.Filter{}, badRequest("query string mal encodée")
	}
	now := time.Now().UTC()
	f := store.Filter{To: now, From: now.Add(-defWindow)}
	if v := q.Get("to"); v != "" {
		if f.To, err = time.Parse(time.RFC3339, v); err != nil {
			return f, badRequest("to : date RFC 3339 attendue")
		}
		f.To = f.To.UTC()
	}
	if v := q.Get("since"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return f, badRequest("since : durée attendue (ex. 24h)")
		}
		f.From = f.To.Add(-d)
	}
	if v := q.Get("from"); v != "" {
		if f.From, err = time.Parse(time.RFC3339, v); err != nil {
			return f, badRequest("from : date RFC 3339 attendue")
		}
		f.From = f.From.UTC()
	} else if q.Get("since") == "" {
		f.From = f.To.Add(-defWindow)
	}
	if !f.From.Before(f.To) {
		return f, badRequest("from doit précéder to")
	}
	if f.To.Sub(f.From) > maxWindow {
		return f, badRequest("fenêtre limitée à 31 jours")
	}

	for _, p := range []struct {
		name string
		dst  *string
	}{{"instance", &f.Instance}, {"site", &f.Site}, {"ua", &f.UA}, {"path", &f.Path}, {"rule", &f.Rule}, {"status", &f.Status}} {
		v := q.Get(p.name)
		if len(v) > maxText {
			return f, badRequest(p.name + " trop long")
		}
		*p.dst = v
	}
	if f.Source = q.Get("source"); f.Source != "" && !wire.ValidSource(f.Source) {
		return f, badRequest("source inconnue")
	}
	if f.Action = q.Get("action"); f.Action != "" && !wire.ValidAction(f.Action) {
		return f, badRequest("action inconnue")
	}
	if v := q.Get("ip"); v != "" {
		col, val, err := s.ip.Filter(s.store.Settings().IPMode, v)
		if err != nil {
			if errors.Is(err, ipmode.ErrBadIP) {
				return f, badRequest("ip invalide")
			}
			return f, badRequest("recherche par IP indisponible (clé de pseudonymisation absente)")
		}
		f.IPCol, f.IPVal = col, val
	}
	return f, nil
}

func intParam(r *http.Request, name string, def, min, max int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, badRequest(name + " hors bornes (" + strconv.Itoa(min) + "–" + strconv.Itoa(max) + ")")
	}
	return n, nil
}

func (s *Server) qctx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), s.cfg.QueryTimeout)
}

// fail traduit une erreur en réponse : validation -> 400, délai -> 504,
// le reste -> 500 sans détail.
func (s *Server) fail(w http.ResponseWriter, err error) {
	var br badRequest
	switch {
	case errors.As(err, &br):
		writeErr(w, 400, "bad_request", string(br))
	case errors.As(err, new(forbiddenErr)):
		writeErr(w, 403, "forbidden", "")
	case errors.Is(err, store.ErrBadFilter):
		writeErr(w, 400, "bad_request", err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		writeErr(w, 504, "query_timeout", "affiner la fenêtre ou les filtres")
	default:
		if strings.Contains(sqlClass(err), "57014") { // statement_timeout
			writeErr(w, 504, "query_timeout", "affiner la fenêtre ou les filtres")
			return
		}
		s.log.Error("requête en échec", "err", sqlClass(err))
		writeErr(w, 500, "internal", "")
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	f, err := s.parseFilter(r, defaultWindow)
	if err == nil {
		err = scopeFilter(id, &f)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	limit, err := intParam(r, "limit", 100, 1, maxPage)
	if err != nil {
		s.fail(w, err)
		return
	}
	var cur *store.Cursor
	if v := r.URL.Query().Get("cursor"); v != "" {
		if cur, err = store.DecodeCursor(v); err != nil {
			s.fail(w, badRequest("cursor invalide"))
			return
		}
	}
	ctx, cancel := s.qctx(r)
	defer cancel()
	rows, next, err := s.store.Events(ctx, f, limit, cur)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{"events": rows, "next_cursor": nil}
	if next != nil {
		out["next_cursor"] = next.Encode()
	}
	writeJSON(w, 200, out)
}

func (s *Server) ipHistory(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	q := r.URL.Query()
	q.Set("ip", r.PathValue("ip"))
	r.URL.RawQuery = q.Encode()
	f, err := s.parseFilter(r, 7*24*time.Hour)
	if err == nil {
		err = scopeFilter(id, &f)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	limit, err := intParam(r, "limit", 100, 1, maxPage)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := s.qctx(r)
	defer cancel()
	sum, err := s.store.IPSummary(ctx, f)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows, next, err := s.store.Events(ctx, f, limit, nil)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{"summary": sum, "events": rows, "next_cursor": nil, "ip_mode": s.store.Settings().IPMode}
	if next != nil {
		out["next_cursor"] = next.Encode()
	}
	writeJSON(w, 200, out)
}

func (s *Server) statsVisits(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	f, err := s.parseFilter(r, 24*time.Hour)
	if err == nil {
		err = scopeFilter(id, &f)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	unit := r.URL.Query().Get("bucket")
	switch unit {
	case "hour", "day":
	case "", "auto":
		unit = "hour"
		if f.To.Sub(f.From) > 72*time.Hour {
			unit = "day"
		}
	default:
		s.fail(w, badRequest("bucket : hour, day ou auto"))
		return
	}
	ctx, cancel := s.qctx(r)
	defer cancel()
	pts, err := s.store.Visits(ctx, f, unit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"bucket": unit, "points": pts})
}

func (s *Server) statsTop(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	f, err := s.parseFilter(r, 24*time.Hour)
	if err == nil {
		err = scopeFilter(id, &f)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	dim := r.URL.Query().Get("dimension")
	if dim == "" {
		s.fail(w, badRequest("dimension requise (path, ua, country, site, rule, referer_host, bot_class, source, action, status, ip)"))
		return
	}
	limit, err := intParam(r, "limit", 20, 1, 100)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := s.qctx(r)
	defer cancel()
	kv, err := s.store.Top(ctx, f, dim, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"dimension": dim, "items": kv})
}

func (s *Server) statsSecurity(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	f, err := s.parseFilter(r, 24*time.Hour)
	if err == nil {
		err = scopeFilter(id, &f)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	minPaths, err := intParam(r, "min_paths", 20, 1, 1000)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := s.qctx(r)
	defer cancel()
	rep, err := s.store.Security(ctx, f, minPaths)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, rep)
}

func (s *Server) instances(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	ctx, cancel := s.qctx(r)
	defer cancel()
	in, err := s.store.Instances(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	if sc := id.Scope(); sc != "" {
		only := in[:0:0]
		for _, x := range in {
			if x.ID == sc {
				only = append(only, x)
			}
		}
		in = only
	}
	writeJSON(w, 200, map[string]any{"instances": in})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeErr(w, 503, "database_unavailable", "")
		return
	}
	out := map[string]any{"status": "ok"}
	if id, ok := s.verifier.Verify(auth.Bearer(r.Header.Get("Authorization"))); ok && id.Allows(auth.RoleRead) && id.Scope() == "" {
		if h, err := s.store.Health(ctx); err == nil {
			out["version"] = Version
			out["detail"] = h
		}
	}
	writeJSON(w, 200, out)
}

// statsIPs : IP corrélées entre instances et sources (#62). Jeton `read`. Fenêtre limitée à 7 jours (balayage de la table brute).
// GET /v1/stats/ips?since=24h&min_instances=2&min_sources=1&limit=200
func (s *Server) statsIPs(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if id.Scope() != "" { // corrélation entre instances : par nature hors du périmètre d'un jeton limité (#89)
		writeErr(w, 403, "forbidden", "")
		return
	}
	f, err := s.parseFilter(r, 24*time.Hour)
	if err != nil {
		s.fail(w, err)
		return
	}
	if f.To.Sub(f.From) > maxIPWindow {
		s.fail(w, badRequest("fenêtre limitée à 7 jours pour cette route"))
		return
	}
	minInst, err := intParam(r, "min_instances", 2, 1, 1000)
	if err != nil {
		s.fail(w, err)
		return
	}
	minSrc, err := intParam(r, "min_sources", 1, 1, 10)
	if err != nil {
		s.fail(w, err)
		return
	}
	limit, err := intParam(r, "limit", 200, 1, maxPage)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := s.qctx(r)
	defer cancel()
	items, err := s.store.IPCorrelation(ctx, f, minInst, minSrc, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ip_mode": s.store.Settings().IPMode, "items": items})
}

// statsCampaigns : signatures d'attaque (règle + chemin) vues depuis plusieurs IP (#107). Jeton `read` (limité à son instance si lié).
// Fenêtre limitée à 7 jours (balayage de la table brute). GET /v1/stats/campaigns?since=24h&min_ips=3&limit=50
func (s *Server) statsCampaigns(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	f, err := s.parseFilter(r, 24*time.Hour)
	if err == nil {
		err = scopeFilter(id, &f)
	}
	if err == nil && f.To.Sub(f.From) > maxIPWindow {
		err = badRequest("fenêtre limitée à 7 jours pour cette route")
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	minIPs, err := intParam(r, "min_ips", 3, 2, 100000)
	if err != nil {
		s.fail(w, err)
		return
	}
	limit, err := intParam(r, "limit", 50, 1, 200)
	if err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := s.qctx(r)
	defer cancel()
	items, err := s.store.Campaigns(ctx, f, minIPs, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// scopeFilter limite la requête à l'instance du jeton (#89). Une instance explicitement demandée et
// différente de celle du jeton est refusée (403) plutôt que silencieusement réécrite.
func scopeFilter(id auth.Identity, f *store.Filter) error {
	sc := id.Scope()
	if sc == "" {
		return nil
	}
	if f.Instance != "" && f.Instance != sc {
		return forbiddenErr{}
	}
	f.Instance = sc
	return nil
}

type forbiddenErr struct{}

func (forbiddenErr) Error() string { return "forbidden" }
