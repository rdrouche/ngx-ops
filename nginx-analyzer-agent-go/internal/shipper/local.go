package shipper

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"nginx-analyzer-go/internal/wire"
)

const (
	maxLocalBody   = 4 << 20 // 4 Mio par requête
	maxLocalLine   = 64 << 10
	maxLocalEvents = 5000
)

// LocalAPI est l'entrée HTTP locale : les producteurs de décisions (WAF,
// blocklist, challenge, CrowdSec) y déposent leurs événements ; le shipper est
// le seul à parler au log store. Le statut y est aussi exposé, pour ne pas
// dépendre des journaux Docker.
type LocalAPI struct {
	token    [32]byte
	sink     committer
	status   func() any
	Accepted atomic.Int64
	Rejected atomic.Int64
	AuthFail atomic.Int64
}

func NewLocalAPI(token string, sink committer, status func() any) *LocalAPI {
	return &LocalAPI{token: sha256.Sum256([]byte(token)), sink: sink, status: status}
}

func (a *LocalAPI) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(h[len(p):])))
	return subtle.ConstantTimeCompare(got[:], a.token[:]) == 1
}

func (a *LocalAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("/status", a.guard(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, a.status())
	}))
	mux.HandleFunc("/v1/events", a.guard(http.MethodPost, a.events))
	return mux
}

func (a *LocalAPI) guard(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeJSON(w, 405, map[string]any{"error": "méthode non autorisée"})
			return
		}
		if !a.authorized(r) {
			a.AuthFail.Add(1)
			time.Sleep(200 * time.Millisecond) // freine l'énumération sans bloquer le service
			writeJSON(w, 401, map[string]any{"error": "jeton local requis"})
			return
		}
		h(w, r)
	}
}

type localResult struct {
	Accepted int           `json:"accepted"`
	Rejected []wire.Reject `json:"rejected,omitempty"`
}

// events reçoit du NDJSON de wire.Event. Réponse 202 seulement une fois les
// événements écrits durablement dans le tampon.
func (a *LocalAPI) events(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLocalBody)
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 0, 64<<10), maxLocalLine)
	var evs []wire.Event
	var res localResult
	line := 0
	rej := func(reason string) {
		if len(res.Rejected) < wire.MaxRejectedListed {
			res.Rejected = append(res.Rejected, wire.Reject{Line: line, Reason: reason})
		}
	}
	rejTotal := 0
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		line++
		if len(evs) >= maxLocalEvents {
			writeJSON(w, 413, map[string]any{"error": "trop d'événements dans la requête (max 5000)"})
			return
		}
		var ev wire.Event
		dec := json.NewDecoder(strings.NewReader(raw))
		if err := dec.Decode(&ev); err != nil {
			rej("JSON invalide")
			rejTotal++
			continue
		}
		switch {
		case ev.Source == wire.SourceAccess:
			rej("source « access » réservée à la lecture des fichiers")
		case !wire.ValidSource(ev.Source):
			rej("source inconnue")
		case !wire.ValidAction(ev.Action):
			rej("action inconnue")
		default:
			if ev.TS.IsZero() {
				ev.TS = time.Now().UTC()
			}
			evs = append(evs, ev)
			continue
		}
		rejTotal++
	}
	if err := sc.Err(); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok || err == bufio.ErrTooLong {
			writeJSON(w, 413, map[string]any{"error": "requête ou ligne trop grande"})
			return
		}
		writeJSON(w, 400, map[string]any{"error": "lecture impossible"})
		return
	}
	a.Rejected.Add(int64(rejTotal))
	if len(evs) == 0 {
		res.Accepted = 0
		writeJSON(w, 400, res)
		return
	}
	if err := a.sink.Commit(evs, ""); err != nil {
		writeJSON(w, 503, map[string]any{"error": "tampon indisponible"})
		return
	}
	a.Accepted.Add(int64(len(evs)))
	res.Accepted = len(evs)
	writeJSON(w, 202, res)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
