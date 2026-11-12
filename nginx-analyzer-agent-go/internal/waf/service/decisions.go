package service

import (
	"strconv"
	"strings"
	"time"

	"nginx-analyzer-go/internal/waf/crs"
	"nginx-analyzer-go/internal/waf/store"
	"nginx-analyzer-go/internal/wire"
)

// Emitter reçoit les décisions du WAF (client local du shipper ; nil = désactivé).
type Emitter interface{ Emit(wire.Event) }

const maxExtraRules = 20

// hitEvent convertit un hit WAF retenu en événement du log store.
// Action « logged » : le WAF émulé détecte a posteriori, il ne bloque jamais lui-même.
// rule = identifiant de la règle de plus fort score ; extra = score, mode, liste bornée
// des règles et catégories (≪ 4 Kio).
func hitEvent(h store.Hit) wire.Event {
	path, query := h.URI, ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query = path[:i], path[i+1:]
	}
	best, bestScore := 0, -1
	ids := make([]int, 0, len(h.Rules))
	cats := []string{}
	seen := map[string]bool{}
	for _, r := range h.Rules {
		if r.Score > bestScore {
			best, bestScore = r.ID, r.Score
		}
		if len(ids) < maxExtraRules {
			ids = append(ids, r.ID)
		}
		c := r.Category
		if c == "" {
			c = crs.CategoryOfID(r.ID)
		}
		if c != "" && !seen[c] {
			seen[c] = true
			cats = append(cats, c)
		}
	}
	ev := wire.Event{
		TS: time.UnixMilli(h.TS).UTC(), Source: wire.SourceWAF, Action: wire.ActionLogged,
		Site: h.Vhost, IP: h.IP, Method: h.Method, Path: path, Query: query,
		Status: h.Status, UA: h.UA,
		Extra: map[string]any{"score": h.Score, "mode": h.Mode, "possibly_succeeded": h.PossiblySucceeded,
			"rules": ids, "categories": cats},
	}
	if bestScore >= 0 {
		ev.Rule = strconv.Itoa(best)
	}
	return ev
}

func (s *Service) emitHit(h store.Hit) {
	if s.cfg.Decisions != nil {
		s.cfg.Decisions.Emit(hitEvent(h))
	}
}
