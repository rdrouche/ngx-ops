package shipper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"nginx-analyzer-go/internal/wire"
)

// ListLookup attribue un nom de liste aux hits du journal blocklist (#110) en interrogeant l'analyseur
// (GET /api/blocklist-sources/lookup?ip=), seul à connaître les sources synchronisées par le dashboard.
// Jamais bloquant pour l'expédition : délai court, cache par IP, et coupe-circuit après un échec (les hits partent sans nom de liste).
type ListLookup struct {
	base, token string
	hc          *http.Client
	now         func() time.Time

	mu        sync.Mutex
	cache     map[string]lookupEntry
	downUntil time.Time
}

type lookupEntry struct {
	names []string
	until time.Time
}

const (
	lookupTTL      = 10 * time.Minute
	lookupMaxCache = 20000
	lookupCooldown = 30 * time.Second
	lookupMaxBody  = 16 << 10
)

func lookupLocalHost(h string) bool {
	if h == "localhost" || (!strings.Contains(h, ".") && !strings.Contains(h, ":")) {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return false
}

// NewListLookup renvoie (nil, nil) si rawURL est vide (fonction désactivée). http:// réservé à un hôte local (le jeton circule en clair).
func NewListLookup(rawURL, token string) (*ListLookup, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("LOGSHIP_ANALYZER_URL invalide (schéma://hôte:port, sans chemin ni identifiants)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !lookupLocalHost(u.Hostname()) {
			return nil, errors.New("LOGSHIP_ANALYZER_URL : http:// réservé à un hôte local (boucle locale, nom de service ou IP privée)")
		}
	default:
		return nil, errors.New("LOGSHIP_ANALYZER_URL : schéma http ou https requis")
	}
	return &ListLookup{
		base: strings.TrimRight(u.String(), "/"), token: token, now: time.Now, cache: map[string]lookupEntry{},
		hc: &http.Client{Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// Names renvoie les listes qui contiennent ip (triées, vide si inconnu ou analyseur injoignable). Sûr pour un récepteur nil.
func (l *ListLookup) Names(ip string) []string {
	if l == nil || ip == "" {
		return nil
	}
	now := l.now()
	l.mu.Lock()
	if e, ok := l.cache[ip]; ok && now.Before(e.until) {
		l.mu.Unlock()
		return e.names
	}
	if now.Before(l.downUntil) {
		l.mu.Unlock()
		return nil
	}
	l.mu.Unlock()

	names, ok := l.fetch(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	if !ok {
		l.downUntil = l.now().Add(lookupCooldown)
		return nil
	}
	if len(l.cache) >= lookupMaxCache {
		l.cache = map[string]lookupEntry{}
	}
	ttl := lookupTTL
	l.cache[ip] = lookupEntry{names: names, until: l.now().Add(ttl)}
	return names
}

func (l *ListLookup) fetch(ip string) ([]string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), l.hc.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.base+"/api/blocklist-sources/lookup?ip="+url.QueryEscape(ip), nil)
	if err != nil {
		return nil, false
	}
	if l.token != "" {
		req.Header.Set("X-Analyzer-Token", l.token)
	}
	resp, err := l.hc.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var out struct {
		Sources []string `json:"sources"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, lookupMaxBody)).Decode(&out); err != nil {
		return nil, false
	}
	if len(out.Sources) > 10 {
		out.Sources = out.Sources[:10]
	}
	for i, s := range out.Sources {
		if len(s) > 120 {
			out.Sources[i] = s[:120]
		}
	}
	return out.Sources, true
}

// Apply renseigne rule (première liste, ordre alphabétique) et extra.lists (≤ 10) sur un événement blocklist.
func (l *ListLookup) Apply(ev *wire.Event) {
	names := l.Names(ev.IP)
	if len(names) == 0 {
		return
	}
	ev.Rule = names[0]
	if len(names) > 1 {
		ev.Extra = map[string]any{"lists": names}
	}
}
