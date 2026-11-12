package shipper

import (
	"strings"
	"time"

	"nginx-analyzer-go/internal/botclass"
	"nginx-analyzer-go/internal/geoip"
	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/wire"
)

// Mapper convertit une ligne d'access log analysée en événement du log store.
type Mapper struct {
	Country  bool // enrichit avec geoip.CountryOf (base MaxMind locale)
	BotClass bool // enrichit avec botclass.ClassifyAgent
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	if *p == "-" {
		return ""
	}
	return *p
}

// Map renvoie false si la ligne n'est pas exploitable (horodatage invalide).
// Action : « allowed » (l'access log ne dit pas ce que nginx a refusé en amont ;
// les décisions WAF/blocklist/challenge arrivent par l'entrée locale).
func (m Mapper) Map(e parse.AccessEntry) (wire.Event, bool) {
	if !e.TSValid || e.IP == "" {
		return wire.Event{}, false
	}
	path := deref(e.Path)
	query := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query = path[:i], path[i+1:]
	}
	ev := wire.Event{
		TS:      time.UnixMilli(e.TS).UTC(),
		Source:  wire.SourceAccess,
		Action:  wire.ActionAllowed,
		Site:    e.Vhost,
		IP:      e.IP,
		Method:  deref(e.Method),
		Path:    path,
		Query:   query,
		Status:  e.Status,
		Bytes:   e.Bytes,
		UA:      deref(e.UA),
		Referer: deref(e.Referer),
	}
	if m.Country {
		ev.Country = geoip.CountryOf(e.IP)
	}
	if m.BotClass && ev.UA != "" {
		ev.BotClass = botclass.ClassifyAgent(ev.UA).Category
	}
	return ev, true
}

// MapBlocklist convertit une ligne du journal dédié des hits de blocklist (`blocklist-hits.log`) :
// requête refusée par nginx à cause d'une liste d'IP. Le journal ne porte pas le nom de la liste
// (l'attribution par liste est faite par l'analyseur, via le dashboard) : `rule` reste vide.
func MapBlocklist(e parse.BlocklistEntry) (wire.Event, bool) {
	if !e.TSValid || e.IP == nil || *e.IP == "" {
		return wire.Event{}, false
	}
	path, query := deref(e.URI), ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query = path[:i], path[i+1:]
	}
	return wire.Event{
		TS: time.UnixMilli(e.TS).UTC(), Source: wire.SourceBlocklist, Action: wire.ActionBlocked,
		Site: deref(e.Vhost), IP: *e.IP, Method: deref(e.Method), Path: path, Query: query, Status: e.Status,
	}, true
}
