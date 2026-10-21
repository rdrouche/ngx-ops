// Package httpapi expose l'API JSON du WAF emule (contrat WAF-CONTRACT.md), protegee par
// l'en-tete X-WAF-Token (comparaison a temps constant), corps limites a 1 Mo.
package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/waf/service"
	"nginx-analyzer-go/internal/waf/store"
)

const (
	maxBody  = 1 << 20
	maxLimit = 500
)

// API est le handler HTTP.
type API struct {
	svc       *service.Service
	tokenHash [32]byte
	hasToken  bool
	routes    map[string]map[string]http.HandlerFunc
}

// New construit le handler. token vide = pas d'authentification (a eviter en production).
func New(svc *service.Service, token string) *API {
	a := &API{svc: svc, routes: map[string]map[string]http.HandlerFunc{}}
	if token != "" {
		a.tokenHash = sha256.Sum256([]byte(token))
		a.hasToken = true
	}
	a.handle("GET", "/api/health", a.health)
	a.handle("GET", "/api/status", a.status)
	a.handle("GET", "/api/vhosts", a.vhosts)
	a.handle("GET", "/api/rules", a.rules)
	a.handle("GET", "/api/rules/categories", a.categories)
	a.handle("GET", "/api/hits", a.hits)
	a.handle("GET", "/api/hits/stats", a.hitStats)
	a.handle("POST", "/api/simulate", a.simulate)
	a.handle("GET", "/api/lists", a.lists)
	a.handle("GET", "/api/lists/ips", a.listIPs)
	a.handle("POST", "/api/lists/unlist", a.unlist)
	a.handle("GET", "/api/alerts", a.alerts)
	a.handle("POST", "/api/alerts/ack", a.ack)
	a.handle("GET", "/api/settings", a.getSettings)
	a.handle("PUT", "/api/settings", a.putSettings)
	a.handle("POST", "/api/rules/update", a.rulesUpdate)
	a.handle("POST", "/api/engine/reload", a.reload)
	a.handle("GET", "/api/custom-rules", a.getCustom)
	a.handle("PUT", "/api/custom-rules", a.putCustom)
	return a
}

func (a *API) handle(method, path string, h http.HandlerFunc) {
	m := a.routes[path]
	if m == nil {
		m = map[string]http.HandlerFunc{}
		a.routes[path] = m
	}
	m[method] = h
}

// ServeHTTP route, authentifie et applique les limites.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m, ok := a.routes[r.URL.Path]
	if !ok {
		writeErr(w, http.StatusNotFound, "route inconnue")
		return
	}
	h, ok := m[r.Method]
	if !ok {
		allow := make([]string, 0, len(m))
		for k := range m {
			allow = append(allow, k)
		}
		w.Header().Set("Allow", strings.Join(allow, ", "))
		writeErr(w, http.StatusMethodNotAllowed, "methode non autorisee")
		return
	}
	if r.URL.Path != "/api/health" && a.hasToken {
		got := sha256.Sum256([]byte(r.Header.Get("X-WAF-Token")))
		if subtle.ConstantTimeCompare(got[:], a.tokenHash[:]) != 1 {
			writeErr(w, http.StatusUnauthorized, "token invalide")
			return
		}
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	h(w, r)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeErr(w, 500, "erreur de serialisation")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// fail traduit une erreur du service en reponse HTTP (details internes jamais exposes).
func fail(w http.ResponseWriter, err error) {
	var br *service.BadRequest
	var cf *service.ConflictError
	switch {
	case errors.As(err, &br):
		writeErr(w, http.StatusBadRequest, br.Msg)
	case errors.As(err, &cf):
		writeErr(w, http.StatusConflict, cf.Msg)
	default:
		writeErr(w, http.StatusInternalServerError, "erreur interne")
	}
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "corps trop volumineux (1 Mo max)")
		} else {
			writeErr(w, http.StatusBadRequest, "corps illisible")
		}
		return nil, false
	}
	return b, true
}

// decode : JSON strict (champs inconnus refuses).
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	b, ok := readBody(w, r)
	if !ok {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide : "+err.Error())
		return false
	}
	if dec.More() {
		writeErr(w, http.StatusBadRequest, "JSON invalide : donnees superflues")
		return false
	}
	return true
}

// ---------- parametres ----------

func qInt(w http.ResponseWriter, q map[string][]string, name string, def, min, max int) (int, bool) {
	v := first(q, name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		writeErr(w, http.StatusBadRequest, "parametre "+name+" invalide ("+strconv.Itoa(min)+" a "+strconv.Itoa(max)+")")
		return 0, false
	}
	return n, true
}

func first(q map[string][]string, name string) string {
	if v := q[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// qTime accepte des epoch ms, des epoch secondes (< 1e11) ou une date ISO 8601.
func qTime(w http.ResponseWriter, q map[string][]string, name string) (int64, bool) {
	v := first(q, name)
	if v == "" {
		return 0, true
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
		if n < 100000000000 {
			n *= 1000
		}
		return n, true
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UnixMilli(), true
	}
	writeErr(w, http.StatusBadRequest, "parametre "+name+" invalide (epoch ms ou ISO 8601)")
	return 0, false
}

func qOrder(w http.ResponseWriter, q map[string][]string, def string) (asc, ok bool) {
	switch first(q, "order") {
	case "":
		return def == "asc", true
	case "asc":
		return true, true
	case "desc":
		return false, true
	}
	writeErr(w, http.StatusBadRequest, "parametre order invalide (asc ou desc)")
	return false, false
}

// ---------- handlers ----------

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok", "version": a.svc.Version()})
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.svc.Status(r.Context()))
}

func (a *API) vhosts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"vhosts": a.svc.Vhosts(r.Context())})
}

func (a *API) rules(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, ok := qInt(w, q, "limit", 100, 1, maxLimit)
	if !ok {
		return
	}
	offset, ok := qInt(w, q, "offset", 0, 0, 1000000)
	if !ok {
		return
	}
	text := first(q, "q")
	if len(text) > 100 {
		writeErr(w, 400, "parametre q trop long")
		return
	}
	total, rules, err := a.svc.Rules(r.Context(), service.RulesQuery{Q: text, Category: first(q, "category"), State: first(q, "state"), Limit: limit, Offset: offset})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"total": total, "rules": rules})
}

func (a *API) categories(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"categories": a.svc.Categories(r.Context())})
}

func (a *API) hits(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var f store.HitFilter
	var ok bool
	if f.Since, ok = qTime(w, q, "since"); !ok {
		return
	}
	if f.Until, ok = qTime(w, q, "until"); !ok {
		return
	}
	f.IP = first(q, "ip")
	if f.IP != "" && !parse.LooksLikeIP(f.IP) {
		writeErr(w, 400, "parametre ip invalide")
		return
	}
	f.Vhost = strings.ToLower(first(q, "vhost"))
	if len(f.Vhost) > 253 {
		writeErr(w, 400, "parametre vhost invalide")
		return
	}
	if f.Rule, ok = qInt(w, q, "rule", 0, 0, 99999999); !ok {
		return
	}
	if f.MinScore, ok = qInt(w, q, "minScore", 0, 0, 1000000); !ok {
		return
	}
	f.Mode = first(q, "mode")
	if f.Mode != "" && f.Mode != "observe" && f.Mode != "remediate" {
		writeErr(w, 400, "parametre mode invalide (observe ou remediate)")
		return
	}
	if f.Limit, ok = qInt(w, q, "limit", 100, 1, maxLimit); !ok {
		return
	}
	if f.Offset, ok = qInt(w, q, "offset", 0, 0, 10000000); !ok {
		return
	}
	if f.Asc, ok = qOrder(w, q, "desc"); !ok {
		return
	}
	total, hits, err := a.svc.QueryHits(r.Context(), f)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"total": total, "hits": hits})
}

func (a *API) hitStats(w http.ResponseWriter, r *http.Request) {
	hours, ok := qInt(w, r.URL.Query(), "hours", 24, 1, 24*90)
	if !ok {
		return
	}
	d, err := a.svc.HitStats(r.Context(), hours)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, d)
}

func (a *API) simulate(w http.ResponseWriter, r *http.Request) {
	var in service.SimInput
	if !decode(w, r, &in) {
		return
	}
	res, err := a.svc.Simulate(in)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (a *API) lists(w http.ResponseWriter, r *http.Request) {
	list := first(r.URL.Query(), "list")
	docs, err := a.svc.Lists(list)
	if err != nil {
		fail(w, err)
		return
	}
	if list != "" {
		writeJSON(w, 200, docs[0])
		return
	}
	// Sans parametre : les deux listes, sous forme de tableau (lists) ET par cle (block/challenge).
	out := map[string]any{"lists": docs}
	for _, d := range docs {
		out[d.List] = d
	}
	writeJSON(w, 200, out)
}

func (a *API) listIPs(w http.ResponseWriter, r *http.Request) {
	txt, err := a.svc.ListIPs(first(r.URL.Query(), "list"))
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	_, _ = io.WriteString(w, txt)
}

func (a *API) unlist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP           string `json:"ip"`
		List         string `json:"list"`
		GraceMinutes int    `json:"graceMinutes"`
	}
	if !decode(w, r, &in) {
		return
	}
	removed, err := a.svc.Unlist(in.IP, in.List, in.GraceMinutes)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "ip": in.IP, "removed": removed})
}

func (a *API) alerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, ok := qInt(w, q, "sinceId", 0, 0, 1<<40)
	if !ok {
		return
	}
	limit, ok := qInt(w, q, "limit", 100, 1, maxLimit)
	if !ok {
		return
	}
	asc, ok := qOrder(w, q, "asc")
	if !ok {
		return
	}
	raw := first(q, "raw") == "1"
	alerts, latest, err := a.svc.Alerts(r.Context(), int64(since), asc, limit, raw)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"alerts": alerts, "latestId": latest})
}

func (a *API) ack(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []int64 `json:"ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := a.svc.AckAlerts(in.IDs); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "acked": len(in.IDs)})
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.svc.Settings())
}

func (a *API) putSettings(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	s, err := a.svc.UpdateSettings(b)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, s)
}

func (a *API) rulesUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Version string `json:"version"`
	}
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	if len(strings.TrimSpace(string(b))) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			writeErr(w, 400, "JSON invalide : "+err.Error())
			return
		}
	}
	if err := a.svc.StartRulesUpdate(in.Version); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

func (a *API) reload(w http.ResponseWriter, r *http.Request) {
	if err := a.svc.ReloadEngine(); err != nil {
		writeErr(w, http.StatusConflict, "rechargement impossible : "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) getCustom(w http.ResponseWriter, r *http.Request) {
	t, err := a.svc.CustomRules()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"text": t})
}

func (a *API) putCustom(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Text string `json:"text"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := a.svc.PutCustomRules(in.Text); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
