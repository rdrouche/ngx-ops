// COPIE de ngxops/logstore/pkg/wire (module log store). Garder synchronise.
// Package wire définit le contrat d'échange entre les producteurs d'événements
// (analyseur, challenge, WAF, blocklist, CrowdSec) et le log store.
// Stdlib uniquement : importable par l'analyseur sans dépendance supplémentaire.
package wire

import "time"

// Sources d'événements.
const (
	SourceAccess    = "access"
	SourceChallenge = "challenge"
	SourceWAF       = "waf"
	SourceBlocklist = "blocklist"
	SourceCrowdSec  = "crowdsec"
	SourceAnalysis  = "analysis" // verdicts de l'analyseur (alertes du détecteur), #110
)

// Actions.
const (
	ActionAllowed    = "allowed"
	ActionBlocked    = "blocked"
	ActionChallenged = "challenged"
	ActionLogged     = "logged"
)

// ValidSource indique si s est une source connue.
func ValidSource(s string) bool {
	switch s {
	case SourceAccess, SourceChallenge, SourceWAF, SourceBlocklist, SourceCrowdSec, SourceAnalysis:
		return true
	}
	return false
}

// ValidAction indique si a est une action connue.
func ValidAction(a string) bool {
	switch a {
	case ActionAllowed, ActionBlocked, ActionChallenged, ActionLogged:
		return true
	}
	return false
}

// Event est une ligne NDJSON envoyée à POST /v1/ingest.
// L'instance n'est pas dans l'événement : elle est portée par le jeton d'écriture.
// La query string brute et le referer complet ne sont jamais stockés
// (empreinte et hôte seulement).
type Event struct {
	TS       time.Time      `json:"ts"`
	Source   string         `json:"source"`
	Action   string         `json:"action"`
	Site     string         `json:"site,omitempty"`
	IP       string         `json:"ip,omitempty"`
	Method   string         `json:"method,omitempty"`
	Path     string         `json:"path,omitempty"`
	Query    string         `json:"query,omitempty"`
	Status   int            `json:"status,omitempty"`
	Bytes    int64          `json:"bytes,omitempty"`
	RTMs     int            `json:"rt_ms,omitempty"`
	UA       string         `json:"ua,omitempty"`
	Referer  string         `json:"referer,omitempty"`
	Country  string         `json:"country,omitempty"`
	BotClass string         `json:"bot_class,omitempty"`
	Rule     string         `json:"rule,omitempty"`
	Extra    map[string]any `json:"extra,omitempty"`
}

// Reject décrit une ligne refusée (numérotée à partir de 1).
type Reject struct {
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

// Result est la réponse de POST /v1/ingest.
type Result struct {
	Accepted      int      `json:"accepted"`
	Duplicate     bool     `json:"duplicate"`
	Rejected      []Reject `json:"rejected,omitempty"`
	RejectedTotal int      `json:"rejected_total"`
}

// En-têtes et limites du protocole.
const (
	HeaderIdempotencyKey = "Idempotency-Key"
	HeaderInstanceName   = "X-Instance-Name"
	MaxRejectedListed    = 100
)
