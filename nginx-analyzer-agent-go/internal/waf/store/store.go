// Package store : persistance SQLite du WAF emule (waf.db). Toutes les ecritures passent par
// une file d'attente groupee par lots dans une seule goroutine : les appelants (tailer,
// agregateur) n'attendent jamais le disque. Les lectures partagent l'unique connexion.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
)

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS waf_hits (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts       INTEGER NOT NULL,
  vhost    TEXT    NOT NULL,
  ip       TEXT    NOT NULL,
  method   TEXT,
  uri      TEXT,
  status   INTEGER,
  ua       TEXT,
  score    INTEGER NOT NULL,
  mode     TEXT    NOT NULL,
  format   TEXT,
  rules    TEXT    NOT NULL,
  possibly INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_waf_hits_ts ON waf_hits(ts);
CREATE INDEX IF NOT EXISTS idx_waf_hits_ip ON waf_hits(ip, ts);
CREATE INDEX IF NOT EXISTS idx_waf_hits_vhost ON waf_hits(vhost, ts);

CREATE TABLE IF NOT EXISTS waf_hit_rules (
  hit_id   INTEGER NOT NULL,
  ts       INTEGER NOT NULL,
  rule_id  INTEGER NOT NULL,
  vhost    TEXT    NOT NULL,
  score    INTEGER NOT NULL,
  category TEXT    NOT NULL,
  msg      TEXT
);
CREATE INDEX IF NOT EXISTS idx_waf_hit_rules_hit ON waf_hit_rules(hit_id);
CREATE INDEX IF NOT EXISTS idx_waf_hit_rules_rule ON waf_hit_rules(rule_id, ts);
CREATE INDEX IF NOT EXISTS idx_waf_hit_rules_ts ON waf_hit_rules(ts);

CREATE TABLE IF NOT EXISTS waf_req_stats (
  bucket   INTEGER NOT NULL,
  vhost    TEXT    NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  hits     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, vhost)
);

CREATE TABLE IF NOT EXISTS waf_alerts (
  id       INTEGER PRIMARY KEY,
  ts       INTEGER NOT NULL,
  severity TEXT    NOT NULL,
  ip       TEXT    NOT NULL,
  vhost    TEXT    NOT NULL,
  ack      INTEGER NOT NULL DEFAULT 0,
  evidence TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_waf_alerts_ts ON waf_alerts(ts);

CREATE TABLE IF NOT EXISTS waf_listed (
  ip       TEXT NOT NULL,
  list     TEXT NOT NULL,
  score    INTEGER NOT NULL,
  hits     INTEGER NOT NULL,
  since    INTEGER NOT NULL,
  until    INTEGER NOT NULL,
  vhosts   TEXT NOT NULL,
  toprules TEXT NOT NULL,
  PRIMARY KEY (ip, list)
);

CREATE TABLE IF NOT EXISTS waf_grace (
  ip    TEXT PRIMARY KEY,
  until INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS waf_offsets (
  file   TEXT PRIMARY KEY,
  inode  INTEGER,
  offset INTEGER,
  format TEXT
);

CREATE TABLE IF NOT EXISTS waf_vhosts (
  name     TEXT PRIMARY KEY,
  lines    INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  format   TEXT
);
`

// Store : base SQLite + file d'ecriture groupee.
type Store struct {
	db   *sql.DB
	path string

	ops     chan op
	done    chan struct{}
	closing atomic.Bool
	wg      sync.WaitGroup

	// Compteurs diagnostics.
	Dropped atomic.Int64 // operations d'ecriture perdues (file pleine)
	errOnce sync.Once
}

type op struct {
	fn   func(tx *sql.Tx) error
	done chan error // non nil : appelant synchrone (barriere)
}

const (
	opQueue       = 32768
	batchMax      = 1000
	batchInterval = 150 * time.Millisecond
)

// Open ouvre (ou cree) la base. En cas d'echec renvoie une erreur ; l'appelant peut
// continuer avec un Store nul (Disabled()) : les operations deviennent des no-op.
func Open(path string) (s *Store, err error) {
	defer func() {
		if r := recover(); r != nil {
			s, err = nil, fmt.Errorf("panique a l'ouverture de SQLite : %v", r)
		}
	}()
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite3", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	s = &Store{db: db, path: path, ops: make(chan op, opQueue), done: make(chan struct{})}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

// Disabled renvoie un Store sans base (repli) : ecritures ignorees, lectures vides.
func Disabled() *Store { return &Store{} }

// OK : la base est ouverte.
func (s *Store) OK() bool { return s != nil && s.db != nil }

// Do enfile une ecriture sans attendre. Renvoie false (et compte) si la file est pleine.
func (s *Store) Do(fn func(tx *sql.Tx) error) bool {
	if !s.OK() || s.closing.Load() {
		return false
	}
	select {
	case s.ops <- op{fn: fn}:
		return true
	default:
		s.Dropped.Add(1)
		return false
	}
}

// DoSync enfile une ecriture et attend son execution (utilise pour ack/unlist/tests).
func (s *Store) DoSync(fn func(tx *sql.Tx) error) error {
	if !s.OK() {
		return nil
	}
	if s.closing.Load() {
		return errors.New("base fermee")
	}
	d := make(chan error, 1)
	s.ops <- op{fn: fn, done: d}
	return <-d
}

// Flush attend que toutes les ecritures enfilees avant l'appel soient validees.
func (s *Store) Flush() {
	_ = s.DoSync(func(*sql.Tx) error { return nil })
}

func (s *Store) writer() {
	defer s.wg.Done()
	for {
		first, ok := <-s.ops
		if !ok {
			return
		}
		batch := []op{first}
		hasSync := first.done != nil
		timer := time.NewTimer(batchInterval)
	collect:
		for len(batch) < batchMax && !hasSync {
			select {
			case o, ok := <-s.ops:
				if !ok {
					break collect
				}
				batch = append(batch, o)
				if o.done != nil {
					hasSync = true
				}
			case <-timer.C:
				break collect
			}
		}
		timer.Stop()
		s.runBatch(batch)
	}
}

func (s *Store) runBatch(batch []op) {
	tx, err := s.db.Begin()
	if err != nil {
		s.logErr("begin", err)
		for _, o := range batch {
			if o.done != nil {
				o.done <- err
			}
		}
		return
	}
	errs := make([]error, len(batch))
	for i, o := range batch {
		func() {
			defer func() {
				if r := recover(); r != nil {
					errs[i] = fmt.Errorf("panique : %v", r)
				}
			}()
			errs[i] = o.fn(tx)
		}()
		if errs[i] != nil {
			s.logErr("ecriture", errs[i])
		}
	}
	cerr := tx.Commit()
	if cerr != nil {
		s.logErr("commit", cerr)
	}
	for i, o := range batch {
		if o.done != nil {
			if errs[i] == nil {
				errs[i] = cerr
			}
			o.done <- errs[i]
		}
	}
}

func (s *Store) logErr(what string, err error) {
	log.Printf("[waf-store] %s : %v", what, err)
}

// Close vide la file puis ferme la base.
func (s *Store) Close() error {
	if !s.OK() {
		return nil
	}
	if s.closing.Swap(true) {
		return nil
	}
	close(s.ops)
	s.wg.Wait()
	return s.db.Close()
}

func (s *Store) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if !s.OK() {
		return nil, errors.New("base indisponible")
	}
	return s.db.QueryContext(ctx, q, args...)
}
