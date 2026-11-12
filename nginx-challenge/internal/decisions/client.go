// Package decisions : client léger des producteurs de décisions (WAF émulé,
// blocklist, challenge, CrowdSec) vers l'API locale du shipper (POST /v1/events).
//
// Le shipper est le seul point de sortie vers le log store : les producteurs ne
// connaissent que son adresse locale et un jeton local. Compromis assumé : un
// shipper arrêté ou injoignable fait perdre les événements au-delà d'un court
// nombre d'essais (compté). Sans SHIPPER_URL, New renvoie nil : tous les appels
// sont des no-op et le producteur se comporte exactement comme avant.
//
// Stdlib uniquement.
package decisions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"nginx-challenge/internal/wire"
)

type Config struct {
	URL       string // ex. http://shipper:9181 (vide = désactivé)
	Token     string // jeton local du shipper (LOGSHIP_LOCAL_TOKEN)
	QueueSize int    // défaut 5000
	BatchSize int    // défaut 200 (≤ 5000)
	Flush     time.Duration
	Timeout   time.Duration
	Retries   int           // essais supplémentaires après le premier, défaut 2
	Backoff   time.Duration // 1er délai entre essais, défaut 1 s (doublé ensuite)
	Logger    *slog.Logger
	Client    *http.Client
}

type Stats struct {
	Emitted, QueueDropped, Sent, SendDropped, Batches, Rejected int64
	Failing                                                     bool
}

type Client struct {
	cfg    Config
	url    string
	queue  chan wire.Event
	client *http.Client
	log    *slog.Logger

	emitted, queueDropped, sent, sendDropped, batches, rejected atomic.Int64
	failing                                                     atomic.Bool
}

// localHost : hôte acceptable en HTTP clair (le jeton circule sans TLS) : boucle
// locale, nom à un seul label (service Docker) ou IP privée.
func localHost(h string) bool {
	if h == "localhost" || (!strings.Contains(h, ".") && !strings.Contains(h, ":")) {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return false
}

// New valide la configuration. Renvoie (nil, nil) si cfg.URL est vide.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, nil
	}
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("decisions : URL invalide (schéma://hôte:port, sans chemin ni identifiants)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !localHost(u.Hostname()) {
			return nil, errors.New("decisions : http:// réservé à un hôte local (boucle locale, nom de service ou IP privée) ; utiliser https")
		}
	default:
		return nil, errors.New("decisions : schéma http ou https requis")
	}
	if len(cfg.Token) < 24 {
		return nil, errors.New("decisions : jeton local requis (24 caractères minimum)")
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 5000
	}
	if cfg.BatchSize <= 0 || cfg.BatchSize > 5000 {
		cfg.BatchSize = 200
	}
	if cfg.Flush <= 0 {
		cfg.Flush = time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	} else if cfg.Retries == 0 {
		cfg.Retries = 2
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = time.Second
	}
	c := &Client{cfg: cfg, url: strings.TrimRight(u.String(), "/") + "/v1/events",
		queue: make(chan wire.Event, cfg.QueueSize), log: cfg.Logger}
	if c.log == nil {
		c.log = slog.Default()
	}
	hc := cfg.Client
	if hc == nil {
		hc = &http.Client{Timeout: cfg.Timeout}
	}
	cp := *hc
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.client = &cp
	return c, nil
}

// Emit met un événement en file. Non bloquant ; file pleine = perdu (compté). nil-safe.
func (c *Client) Emit(ev wire.Event) {
	if c == nil {
		return
	}
	select {
	case c.queue <- ev:
		c.emitted.Add(1)
	default:
		c.queueDropped.Add(1)
	}
}

func (c *Client) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	return Stats{Emitted: c.emitted.Load(), QueueDropped: c.queueDropped.Load(), Sent: c.sent.Load(),
		SendDropped: c.sendDropped.Load(), Batches: c.batches.Load(), Rejected: c.rejected.Load(), Failing: c.failing.Load()}
}

// Run envoie jusqu'à l'annulation de ctx ; à l'arrêt, tente un dernier envoi de ce qui reste.
func (c *Client) Run(ctx context.Context) {
	if c == nil {
		return
	}
	buf := make([]wire.Event, 0, c.cfg.BatchSize)
	t := time.NewTicker(c.cfg.Flush)
	defer t.Stop()
	flush := func(ctx context.Context) {
		if len(buf) > 0 {
			c.send(ctx, buf)
			buf = buf[:0]
		}
	}
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case ev := <-c.queue:
					buf = append(buf, ev)
					if len(buf) >= c.cfg.BatchSize {
						flush(context.Background())
					}
				default:
					fctx, cancel := context.WithTimeout(context.Background(), 2*c.cfg.Timeout)
					flush(fctx)
					cancel()
					return
				}
			}
		case ev := <-c.queue:
			buf = append(buf, ev)
			if len(buf) >= c.cfg.BatchSize {
				flush(ctx)
			}
		case <-t.C:
			flush(ctx)
		}
	}
}

func (c *Client) send(ctx context.Context, evs []wire.Event) {
	var body bytes.Buffer
	for i := range evs {
		b, err := json.Marshal(evs[i])
		if err != nil {
			continue
		}
		body.Write(b)
		body.WriteByte('\n')
	}
	payload := body.Bytes()
	delay := c.cfg.Backoff
	for attempt := 0; ; attempt++ {
		code := c.post(ctx, payload)
		switch {
		case code >= 200 && code < 300:
			c.sent.Add(int64(len(evs)))
			c.batches.Add(1)
			c.failing.Store(false)
			return
		case code >= 400 && code < 500 && code != 429:
			// refus définitif (jeton, validation) : réessayer ne change rien
			c.rejected.Add(int64(len(evs)))
			if !c.failing.Swap(true) {
				c.log.Warn("decisions : lot refusé par le shipper", "status", code)
			}
			return
		}
		if attempt >= c.cfg.Retries || ctx.Err() != nil {
			c.sendDropped.Add(int64(len(evs)))
			if !c.failing.Swap(true) {
				c.log.Warn("decisions : shipper injoignable, événements abandonnés")
			}
			return
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
		}
		delay *= 2
	}
}

// post renvoie le statut HTTP, 0 si erreur réseau (jamais d'URL ni de jeton dans les journaux).
func (c *Client) post(ctx context.Context, payload []byte) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(payload))
	if err != nil {
		return 0
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := c.client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode
}
