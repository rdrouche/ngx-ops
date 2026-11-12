package app

import (
	"strings"
	"time"

	"nginx-analyzer-go/internal/store"
	"nginx-analyzer-go/internal/wire"
)

// analysisEvidenceKeys : champs de la preuve repris dans `extra` (scalaires seulement, jamais d'échantillons de requêtes).
var analysisEvidenceKeys = []string{
	"requests", "distinctPaths", "authFailures", "notFound", "requestsPerSecond", "ruleId", "ruleName", "matches",
	"globalMatches", "globalIPs", "country", "observed", "expected", "deviation",
}

const analysisSummaryMax = 300

// AlertEvent convertit une alerte du détecteur en événement du log store (#110) : source `analysis`, action `logged`,
// `rule` = type d'alerte (ou « custom:<nom> » pour une règle personnalisée), `extra` = sévérité, résumé borné et chiffres clés.
func AlertEvent(a store.Alert) wire.Event {
	ev, _ := a.Evidence.(map[string]any)
	rule := a.Type
	if strings.HasPrefix(a.Type, "custom_") {
		if n, ok := ev["ruleName"].(string); ok && n != "" {
			rule = "custom:" + n
		}
	}
	extra := map[string]any{"severity": a.Severity, "alert_id": a.ID}
	if s := a.Summary; s != "" {
		if r := []rune(s); len(r) > analysisSummaryMax {
			s = string(r[:analysisSummaryMax])
		}
		extra["summary"] = s
	}
	for _, k := range analysisEvidenceKeys {
		switch v := ev[k].(type) {
		case string:
			if len(v) <= 120 {
				extra[k] = v
			}
		case int, int64, float64, bool:
			extra[k] = v
		}
	}
	ts := time.UnixMilli(a.Ts).UTC()
	if a.Ts <= 0 {
		ts = time.Now().UTC()
	}
	return wire.Event{TS: ts, Source: wire.SourceAnalysis, Action: wire.ActionLogged, Site: a.Vhost, IP: a.IP, Rule: rule, Extra: extra}
}
