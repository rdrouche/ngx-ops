// Package shipper lit les access logs nginx (tailer de l'analyseur) et les
// remet au log store via un tampon disque durable. C'est aussi le SEUL point de
// sortie vers le log store : les producteurs de décisions (WAF, blocklist,
// challenge, CrowdSec) lui parlent en HTTP local.
package shipper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"time"

	"nginx-analyzer-go/internal/geoip"
	"nginx-analyzer-go/internal/logsink"
	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/tail"
)

// follower : un fichier (ou un motif de fichiers) suivi, avec son propre état de lecture.
// Un Store par suiveur : le Store attribue les événements accumulés au fichier qu'il lit.
type follower struct {
	name    string // « access » | « blocklist »
	store   *Store
	tailer  *tail.Tailer
	skipped atomic.Int64 // lignes analysées mais inexploitables (horodatage/IP)
}

type Shipper struct {
	cfg     Config
	log     *slog.Logger
	sink    *logsink.Sink
	follows []*follower
	api     *LocalAPI
	mapper  Mapper
	lists   *ListLookup // nil = pas d'attribution de liste (LOGSHIP_ANALYZER_URL vide)

	started   time.Time
	recovered int
}

// newFollower crée le Store (état + reprise) d'un suiveur ; le tailer est attaché par l'appelant.
func (s *Shipper) newFollower(name, stateFile string, pattern *regexp.Regexp) *follower {
	f := &follower{name: name}
	f.store = NewStore(stateFile, s.sink, s.cfg.MaxQueue, s.log)
	f.store.SetFilter(func(file string) bool {
		return filepath.Dir(file) == filepath.Clean(s.cfg.Dir) && pattern.MatchString(filepath.Base(file))
	})
	if err := f.store.Load(); err != nil {
		// État illisible : on le met de côté et on repart (les fichiers déjà vus
		// reprendront à leur fin : pas de doublon, l'historique non expédié est perdu).
		bad := stateFile + ".corrupt"
		_ = os.Rename(stateFile, bad)
		s.log.Error("shipper : fichier d'offsets illisible, mis de côté", "suiveur", name, "vers", bad)
	}
	return f
}

// New construit le shipper et récupère l'état : offsets + positions des unités
// encore dans le tampon (reprise après crash).
func New(cfg Config, log *slog.Logger) (*Shipper, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.Sink.Logger = log
	sink, err := logsink.New(cfg.Sink)
	if err != nil {
		return nil, err
	}
	if sink == nil {
		return nil, errors.New("LOGSINK_URL requis")
	}
	s := &Shipper{cfg: cfg, log: log, sink: sink, started: time.Now()}
	if cfg.WithCountry {
		geoip.Init()
	}
	s.mapper = Mapper{Country: cfg.WithCountry, BotClass: cfg.WithBotClass}

	acc := s.newFollower("access", cfg.StateFile, cfg.Pattern)
	acc.tailer = tail.New(tail.Options{
		Dir: cfg.Dir, Pattern: cfg.Pattern, Store: acc.store, PollMs: cfg.PollMs,
		DetectFormat: parse.DetectFormat,
		ParseLine: func(line, format, defaultVhost string) (any, bool) {
			return parse.ParseLine(line, format, defaultVhost)
		},
		VhostFromFilename: parse.VhostFromFilename,
		OnEntry: func(entry any) {
			e, ok := entry.(parse.AccessEntry)
			if !ok {
				return
			}
			if ev, ok := s.mapper.Map(e); ok {
				acc.store.Add(ev)
			} else {
				acc.skipped.Add(1)
			}
		},
	})
	s.follows = append(s.follows, acc)

	if cfg.WithBlocklist && cfg.BlocklistPattern != nil {
		ll, err := NewListLookup(cfg.AnalyzerURL, cfg.AnalyzerToken)
		if err != nil {
			return nil, err
		}
		s.lists = ll
		bl := s.newFollower("blocklist", cfg.BlocklistState, cfg.BlocklistPattern)
		bl.tailer = tail.New(tail.Options{
			Dir: cfg.Dir, Pattern: cfg.BlocklistPattern, Store: bl.store, PollMs: cfg.PollMs,
			DetectFormat: parse.BlocklistDetectFormat,
			ParseLine: func(line, format, defaultVhost string) (any, bool) {
				return parse.BlocklistParseLine(line, format, defaultVhost)
			},
			VhostFromFilename: parse.BlocklistVhostFromFilename,
			OnEntry: func(entry any) {
				e, ok := entry.(parse.BlocklistEntry)
				if !ok {
					return
				}
				if ev, ok := MapBlocklist(e); ok {
					s.lists.Apply(&ev)
					bl.store.Add(ev)
				} else {
					bl.skipped.Add(1)
				}
			},
		})
		s.follows = append(s.follows, bl)
	}

	// Reprise après crash : chaque suiveur ne retient que les positions de ses propres fichiers.
	metas := sink.PendingMeta()
	for _, f := range s.follows {
		s.recovered += f.store.ApplyPendingMeta(metas)
	}
	if s.recovered > 0 {
		log.Info("shipper : positions reprises depuis le tampon", "unités", s.recovered)
	}
	if cfg.LocalToken != "" {
		s.api = NewLocalAPI(cfg.LocalToken, sink, s.Status)
	}
	return s, nil
}

// Run démarre la lecture, l'envoi et l'API locale ; retourne à l'annulation de ctx.
func (s *Shipper) Run(ctx context.Context) error {
	sinkDone := make(chan struct{})
	go func() { s.sink.Run(ctx); close(sinkDone) }()

	var srv *http.Server
	srvErr := make(chan error, 1)
	if s.cfg.Listen != "" {
		var h http.Handler
		if s.api != nil {
			h = s.api.Handler()
		} else {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, map[string]any{"ok": true})
			})
			h = mux
			s.log.Warn("shipper : LOGSHIP_LOCAL_TOKEN absent, seule /healthz est servie (pas d'entrée de décisions, pas de /status)")
		}
		srv = &http.Server{
			Addr: s.cfg.Listen, Handler: h,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		}
		ln, err := net.Listen("tcp", s.cfg.Listen)
		if err != nil {
			return fmt.Errorf("écoute %s impossible : %w", s.cfg.Listen, err)
		}
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				srvErr <- err
			}
		}()
		s.log.Info("shipper : API locale en écoute", "addr", s.cfg.Listen, "jeton", s.api != nil)
	}

	for _, f := range s.follows {
		f.tailer.Start()
	}
	s.log.Info("shipper démarré", "version", Version, "dir", s.cfg.Dir, "logstore", hostOf(s.cfg.Sink.URL))

	t := time.NewTicker(time.Second)
	defer t.Stop()
	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case runErr = <-srvErr:
			break loop
		case <-t.C:
			for _, f := range s.follows {
				f.store.Retry()
			}
		}
	}
	for _, f := range s.follows {
		f.tailer.Stop()
	}
	for _, f := range s.follows {
		f.store.Retry()
	}
	if srv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(sctx)
		cancel()
	}
	<-sinkDone
	return runErr
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// Status décrit l'état courant, sans aucun secret (ni jeton ni URL complète).
func (s *Shipper) Status() any {
	ss := s.sink.Stats()
	out := map[string]any{
		"version":   Version,
		"uptime_s":  int(time.Since(s.started).Seconds()),
		"logstore":  hostOf(s.cfg.Sink.URL),
		"suspended": ss.Suspended,
		"recovered": s.recovered,
	}
	var committed, commitErrs, retryQ, qDrop, persistErr int64
	for _, f := range s.follows {
		ts, following := f.tailer.Status()
		files := make([]map[string]any, 0, len(following))
		for _, fl := range following {
			files = append(files, map[string]any{
				"file": fl.File, "vhost": fl.Vhost, "format": fl.Format, "offset": fl.Offset,
				"lines": fl.Lines, "parsed": fl.Parsed, "dropped": fl.Dropped, "suspect_format": fl.SuspectFormat,
			})
		}
		key := "tail"
		if f.name != "access" {
			key = "tail_" + f.name
		}
		out[key] = map[string]any{
			"dir": s.cfg.Dir, "files": ts.Files, "lines": ts.Lines, "parsed": ts.Parsed,
			"dropped": ts.Dropped, "rotations": ts.Rotations, "skipped": f.skipped.Load(),
			"following": files,
		}
		committed += f.store.Committed.Load()
		commitErrs += f.store.CommitErrs.Load()
		retryQ += int64(f.store.QueueLen())
		qDrop += f.store.QueueDrop.Load()
		persistErr += f.store.PersistErr.Load()
	}
	out["buffer"] = map[string]any{
		"committed": committed, "commit_errors": commitErrs, "retry_queue": retryQ, "queue_dropped": qDrop,
		"offsets_write_errors": persistErr,
		"spool_files":          ss.SpoolFiles, "spool_bytes": ss.SpoolBytes, "spool_dropped": ss.SpoolDropped,
	}
	out["sent"] = map[string]any{"events": ss.EventsSent, "batches": ss.BatchesSent, "rejected": ss.Rejected}
	if s.api != nil {
		out["local"] = map[string]any{
			"accepted": s.api.Accepted.Load(), "rejected": s.api.Rejected.Load(), "auth_failures": s.api.AuthFail.Load(),
		}
	}
	return out
}
