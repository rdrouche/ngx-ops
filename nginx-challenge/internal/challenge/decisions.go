package challenge

import (
	"net/http"
	"sync"
	"time"

	"nginx-challenge/internal/wire"
)

// Emitter reçoit les décisions du challenge (client local du shipper, vers le log store ; nil = aucun envoi).
// On n'émet que des DÉCISIONS (réussi, échoué, limité, bloqué automatiquement, redirigé), pas chaque requête
// laissée passer par cookie ou robot vérifié : celles-ci figurent déjà dans le journal d'accès.
type Emitter interface{ Emit(wire.Event) }

const (
	redirEventEvery = time.Minute // au plus un événement « redirigé » par IP et par site et par minute
	maxRedirKeys    = 20000
)

type emitState struct {
	mu        sync.Mutex
	redirSeen map[string]int64 // clé ip|site -> dernier événement (ms)
}

// SetEmitter branche l'envoi des décisions (à appeler avant de servir). Ne fait rien si e est nil.
func (s *Server) SetEmitter(e Emitter) {
	if e == nil {
		return
	}
	s.em = e
	s.es.redirSeen = map[string]int64{}
	s.off.SetOnBan(s.banEvent)
}

// emitReq émet un événement pour la requête r (IP lue dans X-Real-IP, posé par nginx).
func (s *Server) emitReq(r *http.Request, action, rule string, extra map[string]any) {
	if s.em == nil {
		return
	}
	ip := NormIP(r.Header.Get("X-Real-IP"))
	if ip == "" {
		return
	}
	s.em.Emit(wire.Event{
		TS: time.Now().UTC(), Source: wire.SourceChallenge, Action: action, Rule: rule,
		Site: HostOnly(r.Host), IP: ip, UA: trunc(r.UserAgent(), 512), Extra: extra,
	})
}

// emitRedirect : navigation renvoyée vers la page de vérification, au plus une fois par minute et par IP/site
// (sinon un flot de visiteurs ou de robots saturerait la file ; la file bornée perdrait de toute façon).
func (s *Server) emitRedirect(r *http.Request) {
	if s.em == nil {
		return
	}
	ip := NormIP(r.Header.Get("X-Real-IP"))
	if ip == "" {
		return
	}
	k := ip + "|" + HostOnly(r.Host)
	now := time.Now().UnixMilli()
	s.es.mu.Lock()
	if last, ok := s.es.redirSeen[k]; ok && now-last < redirEventEvery.Milliseconds() {
		s.es.mu.Unlock()
		return
	}
	if len(s.es.redirSeen) >= maxRedirKeys {
		s.es.redirSeen = map[string]int64{}
	}
	s.es.redirSeen[k] = now
	s.es.mu.Unlock()
	s.emitReq(r, wire.ActionChallenged, "redirected", nil)
}

// banEvent : blocage automatique déclenché (une fois par blocage, pas par requête refusée ensuite).
func (s *Server) banEvent(b Ban) {
	if s.em == nil {
		return
	}
	s.em.Emit(wire.Event{
		TS: time.Unix(b.Since, 0).UTC(), Source: wire.SourceChallenge, Action: wire.ActionBlocked, Rule: "auto_ban",
		Site: b.Host, IP: b.IP, UA: trunc(b.UA, 512),
		Extra: map[string]any{"attempts": b.Attempts, "window_min": b.Window, "until": b.Until,
			"redirected": b.Redirected, "failed": b.Failed, "rate_limited": b.RateLimited},
	})
}
