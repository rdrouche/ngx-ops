package api

import (
	"embed"
	"net/http"
)

// Interface web minimale de gestion des jetons (#91). Fichiers statiques embarqués, sans secret : toutes
// les opérations passent par l'API /v1/tokens, authentifiée par le jeton admin saisi dans la page
// (conservé en mémoire seulement). Désactivable : LOGSTORE_UI=false.
//
//go:embed ui/index.html ui/app.js ui/style.css
var uiFS embed.FS

var uiFiles = map[string]struct{ file, ctype string }{
	"/ui/":          {"ui/index.html", "text/html; charset=utf-8"},
	"/ui/app.js":    {"ui/app.js", "text/javascript; charset=utf-8"},
	"/ui/style.css": {"ui/style.css", "text/css; charset=utf-8"},
}

// uiHandler sert la page avec une CSP stricte : aucun script ni style inline, aucune ressource externe,
// pas d'intégration dans un cadre, pas de fuite de Referer.
func (s *Server) uiHandler(w http.ResponseWriter, r *http.Request) {
	f, ok := uiFiles[r.URL.Path]
	if !ok {
		writeErr(w, 404, "not_found", "")
		return
	}
	b, err := uiFS.ReadFile(f.file)
	if err != nil {
		writeErr(w, 404, "not_found", "")
		return
	}
	h := w.Header()
	h.Set("Content-Type", f.ctype)
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(b)
}
