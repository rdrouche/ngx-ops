// Package logsink envoie les événements de l'analyseur au log store.
//
// Fonctionnement : Emit (non bloquant) -> file en mémoire -> lots écrits sur
// disque (tampon) -> envoi du plus ancien au plus récent avec le protocole de
// reprise de l'API Intelligence (Idempotency-Key, Retry-After, backoff).
// Un lot n'est supprimé du disque qu'après un 2xx : livraison au moins une
// fois, dédupliquée côté serveur. Sans URL configurée, New renvoie nil et
// tous les appels sont des no-op : aucun changement de comportement.
//
// Stdlib uniquement.
package logsink

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ngxops/logstore/pkg/wire"
)

// Config configure le Sink. URL vide = désactivé.
type Config struct {
	URL           string // ex. https://logstore.example:8443
	Token         string // jeton « write » de l'instance
	InstanceName  string // libellé facultatif
	SpoolDir      string // tampon disque (obligatoire si URL)
	SpoolMaxBytes int64  // défaut 256 Mio
	SpoolMaxAge   time.Duration
	BatchSize     int           // défaut 500 événements
	FlushInterval time.Duration // défaut 2 s
	QueueSize     int           // défaut 10 000
	Timeout       time.Duration // défaut 15 s
	AllowInsecure bool          // autorise http:// (réseau interne compose)
	MinBackoff    time.Duration // premier délai de reprise après échec, défaut 1 s
	PollInterval  time.Duration // cadence de lecture du tampon, défaut 500 ms
	HTTPClient    *http.Client
	Logger        *slog.Logger
}

// Stats expose des compteurs pour le monitoring.
type Stats struct {
	Emitted      int64 // événements acceptés dans la file
	QueueDropped int64 // perdus : file pleine
	SpoolDropped int64 // lots perdus : tampon plein/expiré ou refus définitif
	BatchesSent  int64
	EventsSent   int64
	Rejected     int64 // lignes refusées par le serveur (validation)
	SpoolFiles   int
	SpoolBytes   int64
	Suspended    bool // jeton refusé : envoi en attente de correction
}

// Sink est le client d'envoi. Le pointeur nil est valide (désactivé).
type Sink struct {
	cfg    Config
	base   string
	queue  chan wire.Event
	client *http.Client
	log    *slog.Logger

	emitted, queueDropped, spoolDropped, batches, events, rejected atomic.Int64
	suspended                                                      atomic.Bool
	retryAt                                                        atomic.Int64 // UnixNano
	backoff                                                        time.Duration
	progress                                                       map[string]int // lot -> prochain sous-lot à envoyer (goroutine d'envoi seule)
}

// New valide la configuration. Renvoie (nil, nil) si cfg.URL est vide.
func New(cfg Config) (*Sink, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, nil
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("logsink : URL invalide")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && cfg.AllowInsecure) {
		return nil, errors.New("logsink : https requis (http seulement avec AllowInsecure, réseau interne)")
	}
	if cfg.Token == "" {
		return nil, errors.New("logsink : jeton d'écriture requis")
	}
	if cfg.SpoolDir == "" {
		return nil, errors.New("logsink : SpoolDir requis")
	}
	if err := os.MkdirAll(cfg.SpoolDir, 0o700); err != nil {
		return nil, fmt.Errorf("logsink : tampon disque inutilisable : %w", err)
	}
	if cfg.SpoolMaxBytes <= 0 {
		cfg.SpoolMaxBytes = 256 << 20
	}
	if cfg.SpoolMaxAge <= 0 {
		cfg.SpoolMaxAge = 24 * time.Hour
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 2 * time.Second
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 10000
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}
	s := &Sink{cfg: cfg, base: strings.TrimRight(u.String(), "/"), queue: make(chan wire.Event, cfg.QueueSize), log: cfg.Logger, progress: map[string]int{}}
	if s.log == nil {
		s.log = slog.Default()
	}
	s.client = cfg.HTTPClient
	if s.client == nil {
		s.client = &http.Client{Timeout: cfg.Timeout}
	}
	// Jamais de redirection suivie : un 3xx ne doit pas envoyer le jeton ailleurs.
	c := *s.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s.client = &c
	return s, nil
}

// Emit met un événement en file. Non bloquant ; file pleine = événement perdu (compté).
func (s *Sink) Emit(ev wire.Event) {
	if s == nil {
		return
	}
	select {
	case s.queue <- ev:
		s.emitted.Add(1)
	default:
		s.queueDropped.Add(1)
	}
}

// Stats renvoie les compteurs courants.
func (s *Sink) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	files, bytes := s.spoolUsage()
	return Stats{
		Emitted: s.emitted.Load(), QueueDropped: s.queueDropped.Load(), SpoolDropped: s.spoolDropped.Load(),
		BatchesSent: s.batches.Load(), EventsSent: s.events.Load(), Rejected: s.rejected.Load(),
		SpoolFiles: files, SpoolBytes: bytes, Suspended: s.suspended.Load(),
	}
}

// Run collecte et envoie jusqu'à l'annulation de ctx. À l'arrêt, les
// événements en mémoire sont écrits sur disque (envoyés au prochain démarrage).
func (s *Sink) Run(ctx context.Context) {
	if s == nil {
		return
	}
	done := make(chan struct{})
	go func() { defer close(done); s.sendLoop(ctx) }()

	buf := make([]wire.Event, 0, s.cfg.BatchSize)
	tick := time.NewTicker(s.cfg.FlushInterval)
	defer tick.Stop()
	flush := func() {
		if len(buf) == 0 {
			return
		}
		if err := s.spool(buf); err != nil {
			s.log.Error("logsink : écriture du tampon impossible", "err", err.Error())
			s.spoolDropped.Add(1)
		}
		buf = buf[:0]
	}
	for {
		select {
		case ev := <-s.queue:
			buf = append(buf, ev)
			if len(buf) >= s.cfg.BatchSize {
				flush()
			}
		case <-tick.C:
			flush()
		case <-ctx.Done():
			for {
				select {
				case ev := <-s.queue:
					buf = append(buf, ev)
					if len(buf) >= s.cfg.BatchSize {
						flush()
					}
				default:
					flush()
					<-done
					return
				}
			}
		}
	}
}

// ---- tampon disque ----

const spoolExt = ".ndjson.gz"

func newID() string {
	b := make([]byte, 12)
	_, _ = cryptoRand(b)
	return hex.EncodeToString(b)
}

func (s *Sink) spool(evs []wire.Event) error {
	var raw bytes.Buffer
	for i := range evs {
		b, err := json.Marshal(evs[i])
		if err != nil {
			continue
		}
		raw.Write(b)
		raw.WriteByte('\n')
	}
	return s.spoolRaw(time.Now().UnixNano(), raw.Bytes())
}

func (s *Sink) spoolRaw(ts int64, ndjson []byte) error {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(ndjson); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	name := fmt.Sprintf("%020d-%s", ts, newID())
	tmp := filepath.Join(s.cfg.SpoolDir, name+".tmp")
	if err := writeFileSync(tmp, gz.Bytes()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.cfg.SpoolDir, name+spoolExt)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(s.cfg.SpoolDir)
	s.enforceSpool()
	return nil
}

// writeFileSync écrit et force sur disque : un lot annoncé « durable » survit à un crash.
func writeFileSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// metaPrefix marque la ligne de métadonnées d'une unité de tampon. Elle n'est
// jamais envoyée au serveur (les lignes commençant par « # » sont ignorées).
const metaPrefix = "#meta "

// Commit écrit durablement (fsync) un bloc d'événements comme UNE unité de
// tampon, puis rend la main : à son retour, le bloc survit à un crash et sera
// envoyé. meta (une ligne, facultatif) est conservée avec l'unité et relue par
// PendingMeta : un producteur qui suit une position de lecture (shipper) y note
// la position de fin du bloc, pour reprendre sans perte ni doublon après un
// crash survenu entre cette écriture et l'enregistrement de sa position.
//
// L'unité est envoyée en sous-lots de BatchSize événements avec des clés
// d'idempotence déterministes (<id>.<n>) : un rejeu retombe sur les mêmes clés
// et le serveur le déduplique. Une erreur signifie que rien n'est durable : le
// producteur ne doit PAS avancer sa position.
func (s *Sink) Commit(evs []wire.Event, meta string) error {
	if s == nil {
		return nil
	}
	if strings.ContainsAny(meta, "\r\n") {
		return errors.New("logsink : meta sur une seule ligne")
	}
	var raw bytes.Buffer
	n := 0
	for i := range evs {
		b, err := json.Marshal(evs[i])
		if err != nil {
			continue
		}
		raw.Write(b)
		raw.WriteByte('\n')
		n++
	}
	if n == 0 && meta == "" {
		return nil
	}
	if meta != "" {
		raw.WriteString(metaPrefix + meta + "\n")
	}
	return s.spoolRaw(time.Now().UnixNano(), raw.Bytes())
}

// PendingMeta renvoie les métadonnées des unités encore en attente d'envoi
// (de la plus ancienne à la plus récente). À lire AVANT de reprendre la lecture
// des fichiers après un redémarrage.
func (s *Sink) PendingMeta() []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, f := range s.listSpool() {
		fh, err := os.Open(f.path)
		if err != nil {
			continue
		}
		if zr, err := gzip.NewReader(fh); err == nil {
			br := bufio.NewReader(io.LimitReader(zr, 1<<20))
			// la ligne meta est écrite après les événements : on la cherche sur tout le début
			// borné du flux ; les unités sans meta n'en ont pas.
			for {
				line, err := br.ReadString('\n')
				if strings.HasPrefix(line, metaPrefix) {
					out = append(out, strings.TrimSpace(strings.TrimPrefix(line, metaPrefix)))
					break
				}
				if err != nil {
					break
				}
			}
		}
		fh.Close()
	}
	return out
}

// readUnit lit une unité : lignes d'événements (sans commentaires ni lignes vides).
func readUnit(path string) ([][]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(zr, 256<<20))
	if err != nil {
		return nil, err
	}
	var lines [][]byte
	for _, l := range bytes.Split(raw, []byte{'\n'}) {
		l = bytes.TrimSpace(l)
		if len(l) == 0 || l[0] == '#' {
			continue
		}
		lines = append(lines, l)
	}
	return lines, nil
}

type spoolFile struct {
	path string
	name string
	size int64
	ts   int64
}

func (s *Sink) listSpool() []spoolFile {
	ents, err := os.ReadDir(s.cfg.SpoolDir)
	if err != nil {
		return nil
	}
	var out []spoolFile
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, spoolExt) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		ts, _ := strconv.ParseInt(strings.SplitN(n, "-", 2)[0], 10, 64)
		out = append(out, spoolFile{path: filepath.Join(s.cfg.SpoolDir, n), name: n, size: info.Size(), ts: ts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (s *Sink) spoolUsage() (int, int64) {
	var total int64
	fs := s.listSpool()
	for _, f := range fs {
		total += f.size
	}
	return len(fs), total
}

// enforceSpool supprime les lots expirés puis les plus anciens au-delà du plafond.
func (s *Sink) enforceSpool() {
	fs := s.listSpool()
	var total int64
	for _, f := range fs {
		total += f.size
	}
	cutoff := time.Now().Add(-s.cfg.SpoolMaxAge).UnixNano()
	for _, f := range fs {
		if f.ts < cutoff || total > s.cfg.SpoolMaxBytes {
			if os.Remove(f.path) == nil {
				total -= f.size
				s.spoolDropped.Add(1)
			}
		}
	}
}

// ---- envoi ----

func (s *Sink) sendLoop(ctx context.Context) {
	t := time.NewTicker(s.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sendReady(ctx)
		}
	}
}

func (s *Sink) sendReady(ctx context.Context) {
	if time.Now().UnixNano() < s.retryAt.Load() {
		return
	}
	for _, f := range s.listSpool() {
		if ctx.Err() != nil || !s.sendOne(ctx, f) {
			return
		}
	}
}

func (s *Sink) pause(d time.Duration) { s.retryAt.Store(time.Now().Add(d).UnixNano()) }

type chunkResult int

const (
	chunkOK   chunkResult = iota // accepté (ou refus définitif : on passe au suivant)
	chunkStop                    // arrêter la passe (pause déjà posée)
)

// sendOne envoie une unité de tampon en sous-lots de BatchSize événements.
// Chaque sous-lot a une clé d'idempotence déterministe (<id>.<n>) : après un
// crash, le rejeu retombe sur les mêmes clés et le serveur déduplique. Renvoie
// true si l'unité est entièrement traitée (supprimée), false pour s'arrêter.
func (s *Sink) sendOne(ctx context.Context, f spoolFile) bool {
	lines, err := readUnit(f.path)
	if err != nil {
		s.log.Warn("logsink : unité illisible, abandonnée", "fichier", f.name)
		s.spoolDropped.Add(1)
		_ = os.Remove(f.path)
		delete(s.progress, f.name)
		return true
	}
	id := strings.TrimSuffix(strings.SplitN(f.name, "-", 2)[1], spoolExt)
	size := s.cfg.BatchSize
	for n := s.progress[f.name]; n*size < len(lines); n++ {
		end := (n + 1) * size
		if end > len(lines) {
			end = len(lines)
		}
		if s.sendChunk(ctx, fmt.Sprintf("%s.%d", id, n), lines[n*size:end], 0) == chunkStop {
			s.progress[f.name] = n
			return false
		}
	}
	_ = os.Remove(f.path)
	delete(s.progress, f.name)
	return true
}

// sendChunk envoie un sous-lot ; sur 413 il est coupé en deux avec des clés dérivées.
func (s *Sink) sendChunk(ctx context.Context, key string, lines [][]byte, depth int) chunkResult {
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	for _, l := range lines {
		zw.Write(l)
		zw.Write([]byte{'\n'})
	}
	if err := zw.Close(); err != nil {
		return chunkStop
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/v1/ingest", &raw)
	if err != nil {
		return chunkStop
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set(wire.HeaderIdempotencyKey, key)
	if s.cfg.InstanceName != "" {
		req.Header.Set(wire.HeaderInstanceName, s.cfg.InstanceName)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		// Réseau / délai : ne jamais journaliser l'erreur brute (peut contenir l'URL).
		s.retryBackoff("réseau ou délai")
		return chunkStop
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		var res wire.Result
		if json.Unmarshal(respBody, &res) == nil {
			s.events.Add(int64(res.Accepted))
			if res.RejectedTotal > 0 {
				s.rejected.Add(int64(res.RejectedTotal))
				s.log.Warn("logsink : lignes refusées par le log store", "count", res.RejectedTotal, "exemple", firstReason(res))
			}
		}
		s.batches.Add(1)
		s.backoff = 0
		s.suspended.Store(false)
		return chunkOK
	case code == 429:
		s.pause(retryAfter(resp.Header.Get("Retry-After"), s.nextBackoff()))
		return chunkStop
	case code == 401 || code == 403:
		if !s.suspended.Swap(true) {
			s.log.Error("logsink : jeton refusé, envoi suspendu (nouvel essai toutes les 10 min)", "status", code)
		}
		s.pause(10 * time.Minute)
		return chunkStop
	case code == 413:
		if len(lines) < 2 || depth >= 8 {
			s.log.Warn("logsink : lot trop gros et indivisible, abandonné")
			s.spoolDropped.Add(1)
			return chunkOK
		}
		mid := len(lines) / 2
		if s.sendChunk(ctx, key+".0", lines[:mid], depth+1) == chunkStop {
			return chunkStop
		}
		return s.sendChunk(ctx, key+".1", lines[mid:], depth+1)
	case code >= 300 && code < 400:
		s.log.Error("logsink : redirection refusée (URL à corriger)", "status", code)
		s.pause(10 * time.Minute)
		return chunkStop
	case code >= 400 && code < 500:
		s.log.Warn("logsink : lot refusé définitivement", "status", code)
		s.spoolDropped.Add(1)
		return chunkOK
	default:
		s.retryBackoff("erreur serveur " + strconv.Itoa(code))
		return chunkStop
	}
}

func firstReason(r wire.Result) string {
	if len(r.Rejected) > 0 {
		return r.Rejected[0].Reason
	}
	return ""
}

func (s *Sink) nextBackoff() time.Duration {
	if s.backoff == 0 {
		s.backoff = s.cfg.MinBackoff
	} else if s.backoff < 5*time.Minute {
		s.backoff *= 2
		if s.backoff > 5*time.Minute {
			s.backoff = 5 * time.Minute
		}
	}
	return s.backoff
}

func (s *Sink) retryBackoff(why string) {
	d := s.nextBackoff()
	d += time.Duration(mrand.Int64N(int64(d)/4 + 1))
	if s.backoff >= 30*time.Second {
		s.log.Warn("logsink : log store injoignable, nouvel essai", "cause", why, "dans", d.Round(time.Second).String())
	}
	s.pause(d)
}

// retryAfter lit un Retry-After (secondes ou date HTTP), borné à [1 s ; 1 h].
func retryAfter(h string, def time.Duration) time.Duration {
	d := def
	if h != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil {
			d = time.Duration(n) * time.Second
		} else if t, err := http.ParseTime(h); err == nil {
			d = time.Until(t)
		}
	}
	if d < time.Second {
		d = time.Second
	}
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

func cryptoRand(b []byte) (int, error) { return crand.Read(b) }
