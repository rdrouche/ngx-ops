// Package store accède à PostgreSQL / TimescaleDB.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ngxops/logstore/internal/auth"
	"ngxops/logstore/internal/config"
	"ngxops/logstore/internal/ipmode"
)

//go:embed sql/*.sql
var migrationsFS embed.FS

// Settings sont les réglages modifiables depuis l'application.
type Settings struct {
	RetentionDays    int         `json:"retention_days"`     // journaux bruts
	AggRetentionDays int         `json:"agg_retention_days"` // cumuls horaires / journaliers
	IPMode           ipmode.Mode `json:"ip_mode"`
}

// Valeurs par défaut / bornes des cumuls.
const (
	DefaultAggRetentionDays = 400
	MinAggRetentionDays     = 30
	MaxAggRetentionDays     = 800
)

// Options d'ouverture.
type Options struct {
	AdminURL, ReadURL, WriteURL string
	QueryTimeout                time.Duration
	RequireTimescale            bool
	SeedRetentionDays           int
	SeedIPMode                  ipmode.Mode
	PseudoKeyPresent            bool
}

// Store regroupe les pools (rôles PostgreSQL distincts) et les réglages.
type Store struct {
	admin, read, write *pgxpool.Pool
	timescale          bool
	settings           atomic.Pointer[Settings]
	log                *slog.Logger
	maint              maintState
	started            time.Time
}

// Open ouvre les pools, migre le schéma et charge les réglages.
func Open(ctx context.Context, o Options, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{log: log, started: time.Now()}
	var err error
	if s.admin, err = pool(ctx, o.AdminURL, 30*time.Second, false, 4); err != nil {
		return nil, fmt.Errorf("connexion administrateur : %w", err)
	}
	if s.read, err = pool(ctx, o.ReadURL, o.QueryTimeout, true, 8); err != nil {
		s.Close()
		return nil, fmt.Errorf("connexion lecture : %w", err)
	}
	if s.write, err = pool(ctx, o.WriteURL, 30*time.Second, false, 4); err != nil {
		s.Close()
		return nil, fmt.Errorf("connexion écriture : %w", err)
	}
	if err := s.migrate(ctx); err != nil {
		s.Close()
		return nil, fmt.Errorf("migration : %w", err)
	}
	ts, err := s.setupTimescale(ctx)
	if err != nil {
		log.Warn("TimescaleDB indisponible", "err", err.Error())
	}
	if !ts && o.RequireTimescale {
		s.Close()
		return nil, errors.New("TimescaleDB requis (LOGSTORE_REQUIRE_TIMESCALE=true) mais indisponible")
	}
	s.timescale = ts
	if !ts {
		if err := s.setupPlainViews(ctx); err != nil {
			s.Close()
			return nil, fmt.Errorf("vues de cumul : %w", err)
		}
		log.Warn("mode PostgreSQL simple : pas de compression ni de cumuls à 13 mois (usage dev/test)")
	}
	if err := s.seedSettings(ctx, o); err != nil {
		s.Close()
		return nil, err
	}
	cur := s.Settings()
	if cur.IPMode == ipmode.Pseudonymized && !o.PseudoKeyPresent {
		s.Close()
		return nil, errors.New("ip_mode=pseudonymized en base mais LOGSTORE_PSEUDO_KEY absente ou trop courte")
	}
	if err := s.applyRetention(ctx, cur); err != nil {
		log.Warn("rétention non appliquée", "err", err.Error())
	}
	return s, nil
}

func pool(ctx context.Context, url string, stmtTimeout time.Duration, readOnly bool, max int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		// pgx met parfois l'URL (mot de passe compris) dans l'erreur : on masque.
		return nil, errors.New("URL de base invalide")
	}
	cfg.MaxConns = max
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.Itoa(int(stmtTimeout / time.Millisecond))
	cfg.ConnConfig.RuntimeParams["application_name"] = "ngx-logstore"
	if readOnly {
		cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	}
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("ouverture du pool impossible")
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := p.Ping(pctx); err != nil {
		p.Close()
		return nil, fmt.Errorf("base injoignable : %s", errClass(err))
	}
	return p, nil
}

// errClass évite de remonter un message pouvant contenir un DSN.
func errClass(err error) string {
	var pe interface{ SQLState() string }
	if errors.As(err, &pe) {
		return "SQLSTATE " + pe.SQLState()
	}
	return "erreur réseau ou d'authentification"
}

// Close ferme les pools.
func (s *Store) Close() {
	for _, p := range []*pgxpool.Pool{s.admin, s.read, s.write} {
		if p != nil {
			p.Close()
		}
	}
}

// Timescale indique si TimescaleDB est actif.
func (s *Store) Timescale() bool { return s.timescale }

// Ping vérifie la base (lecture).
func (s *Store) Ping(ctx context.Context) error { return s.read.Ping(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.admin.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	ents, err := migrationsFS.ReadDir("sql")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		var done bool
		if err := s.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, n).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		b, _ := migrationsFS.ReadFile("sql/" + n)
		tx, err := s.admin.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(b)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("%s : %w", n, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, n); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		s.log.Info("migration appliquée", "version", n)
	}
	return nil
}

func (s *Store) seedSettings(ctx context.Context, o Options) error {
	seeds := map[string]string{
		"retention_days":     strconv.Itoa(o.SeedRetentionDays),
		"agg_retention_days": strconv.Itoa(DefaultAggRetentionDays),
		"ip_mode":            string(o.SeedIPMode),
	}
	for k, v := range seeds {
		if _, err := s.admin.Exec(ctx, `INSERT INTO settings(key,value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING`, k, v); err != nil {
			return err
		}
	}
	return s.reloadSettings(ctx)
}

func (s *Store) reloadSettings(ctx context.Context) error {
	rows, err := s.admin.Query(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cur := Settings{RetentionDays: config.MaxRetentionDays, AggRetentionDays: DefaultAggRetentionDays, IPMode: ipmode.Clear}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		switch k {
		case "retention_days":
			if n, err := strconv.Atoi(v); err == nil {
				cur.RetentionDays = n
			}
		case "agg_retention_days":
			if n, err := strconv.Atoi(v); err == nil {
				cur.AggRetentionDays = n
			}
		case "ip_mode":
			if m, err := ipmode.Parse(v); err == nil {
				cur.IPMode = m
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.settings.Store(&cur)
	return nil
}

// Settings renvoie les réglages courants (cache mémoire).
func (s *Store) Settings() Settings { return *s.settings.Load() }

// Refresh recharge les réglages depuis la base (autres réplicas, édition directe).
func (s *Store) Refresh(ctx context.Context) error { return s.reloadSettings(ctx) }

// ErrInvalidSettings est renvoyée pour des réglages hors bornes.
var ErrInvalidSettings = errors.New("réglages invalides")

// Validate vérifie les bornes (rétention 7–30 j pour le brut).
func (c Settings) Validate() error {
	if c.RetentionDays < config.MinRetentionDays || c.RetentionDays > config.MaxRetentionDays {
		return fmt.Errorf("%w : retention_days doit être entre %d et %d", ErrInvalidSettings, config.MinRetentionDays, config.MaxRetentionDays)
	}
	if c.AggRetentionDays < MinAggRetentionDays || c.AggRetentionDays > MaxAggRetentionDays {
		return fmt.Errorf("%w : agg_retention_days doit être entre %d et %d", ErrInvalidSettings, MinAggRetentionDays, MaxAggRetentionDays)
	}
	if _, err := ipmode.Parse(string(c.IPMode)); err != nil {
		return fmt.Errorf("%w : %v", ErrInvalidSettings, err)
	}
	return nil
}

// SaveSettings enregistre, applique la rétention et met le cache à jour.
func (s *Store) SaveSettings(ctx context.Context, c Settings) error {
	if err := c.Validate(); err != nil {
		return err
	}
	tx, err := s.admin.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	for k, v := range map[string]string{
		"retention_days":     strconv.Itoa(c.RetentionDays),
		"agg_retention_days": strconv.Itoa(c.AggRetentionDays),
		"ip_mode":            string(c.IPMode),
	} {
		if _, err := tx.Exec(ctx, `INSERT INTO settings(key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, k, v); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if err := s.applyRetention(ctx, c); err != nil {
		s.log.Warn("rétention non appliquée", "err", err.Error())
	}
	s.settings.Store(&c)
	return nil
}

// ---- Jetons ----

// TokenRow est un jeton (sans empreinte).
type TokenRow struct {
	ID         int64      `json:"id"`
	Label      string     `json:"label"`
	Role       string     `json:"role"`
	InstanceID *string    `json:"instance_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// CreateToken enregistre l'empreinte d'un nouveau jeton.
func (s *Store) CreateToken(ctx context.Context, label, role, instanceID string, hash []byte) (int64, error) {
	var inst any
	if instanceID != "" {
		inst = instanceID
	}
	var id int64
	err := s.admin.QueryRow(ctx, `INSERT INTO api_tokens(label, role, instance_id, hash) VALUES ($1,$2,$3,$4) RETURNING id`, label, role, inst, hash).Scan(&id)
	return id, err
}

// EnsureBootstrapAdmin enregistre l'empreinte du jeton d'amorçage et
// vérifie qu'au moins un jeton administrateur actif existe.
func (s *Store) EnsureBootstrapAdmin(ctx context.Context, hash []byte) error {
	if hash != nil {
		if _, err := s.admin.Exec(ctx, `INSERT INTO api_tokens(label, role, hash) VALUES ('bootstrap','admin',$1) ON CONFLICT (hash) DO NOTHING`, hash); err != nil {
			return err
		}
	}
	var n int
	if err := s.admin.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE role='admin' AND revoked_at IS NULL`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return errors.New("aucun jeton administrateur : définir LOGSTORE_ADMIN_TOKEN (≥ 32 caractères, ex. openssl rand -hex 32)")
	}
	return nil
}

// ActiveTokens charge les jetons non révoqués pour le vérificateur.
func (s *Store) ActiveTokens(ctx context.Context) ([]auth.Entry, error) {
	rows, err := s.admin.Query(ctx, `SELECT id, role, COALESCE(instance_id,''), hash FROM api_tokens WHERE revoked_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.Entry
	for rows.Next() {
		var e auth.Entry
		var h []byte
		if err := rows.Scan(&e.TokenID, &e.Role, &e.InstanceID, &h); err != nil {
			return nil, err
		}
		if len(h) != len(e.Hash) {
			continue
		}
		copy(e.Hash[:], h)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListTokens liste tous les jetons (révoqués compris), sans empreinte.
func (s *Store) ListTokens(ctx context.Context) ([]TokenRow, error) {
	rows, err := s.admin.Query(ctx, `SELECT id, label, role, instance_id, created_at, last_used_at, revoked_at FROM api_tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TokenRow{}
	for rows.Next() {
		var t TokenRow
		if err := rows.Scan(&t.ID, &t.Label, &t.Role, &t.InstanceID, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		t.CreatedAt, t.LastUsedAt, t.RevokedAt = t.CreatedAt.UTC(), utcPtr(t.LastUsedAt), utcPtr(t.RevokedAt)
		out = append(out, t)
	}
	return out, rows.Err()
}

// ErrLastAdmin protège contre la révocation du dernier administrateur.
var ErrLastAdmin = errors.New("impossible de révoquer le dernier jeton administrateur")

// RevokeToken révoque un jeton. Renvoie false s'il n'existe pas ou l'est déjà.
func (s *Store) RevokeToken(ctx context.Context, id int64) (bool, error) {
	tx, err := s.admin.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var role string
	err = tx.QueryRow(ctx, `SELECT role FROM api_tokens WHERE id=$1 AND revoked_at IS NULL FOR UPDATE`, id).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if role == "admin" {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE role='admin' AND revoked_at IS NULL`).Scan(&n); err != nil {
			return false, err
		}
		if n <= 1 {
			return false, ErrLastAdmin
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at=now() WHERE id=$1`, id); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// TouchTokens met à jour last_used_at.
func (s *Store) TouchTokens(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.admin.Exec(ctx, `UPDATE api_tokens SET last_used_at=now() WHERE id = ANY($1)`, ids)
	return err
}

// Maintain purge ce qui n'est pas géré par TimescaleDB : en mode simple, les
// événements au-delà de la rétention ; toujours, les identifiants de lots anciens.
func (s *Store) Maintain(ctx context.Context) error {
	if _, err := s.admin.Exec(ctx, `DELETE FROM ingest_batches WHERE received_at < now() - interval '7 days'`); err != nil {
		return err
	}
	if s.timescale {
		return nil
	}
	cutoff := time.Now().Add(-time.Duration(s.Settings().RetentionDays) * 24 * time.Hour)
	for i := 0; i < 40; i++ {
		ct, err := s.admin.Exec(ctx, `DELETE FROM events WHERE ctid IN (SELECT ctid FROM events WHERE ts < $1 LIMIT 50000)`, cutoff)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			break
		}
	}
	return nil
}

// Instance décrit une instance productrice.
type Instance struct {
	ID          string    `json:"id"`
	Name        string    `json:"name,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	EventsTotal int64     `json:"events_total"`
}

// Instances liste les instances connues.
func (s *Store) Instances(ctx context.Context) ([]Instance, error) {
	rows, err := s.read.Query(ctx, `SELECT id, COALESCE(name,''), first_seen, last_seen, events_total FROM instances ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Instance{}
	for rows.Next() {
		var i Instance
		if err := rows.Scan(&i.ID, &i.Name, &i.FirstSeen, &i.LastSeen, &i.EventsTotal); err != nil {
			return nil, err
		}
		i.FirstSeen, i.LastSeen = i.FirstSeen.UTC(), i.LastSeen.UTC()
		out = append(out, i)
	}
	return out, rows.Err()
}

// HealthInfo est le détail de santé (jeton de lecture).
type HealthInfo struct {
	Timescale     bool       `json:"timescale"`
	DBSizeBytes   int64      `json:"db_size_bytes"`
	LastIngest    *time.Time `json:"last_ingest,omitempty"`
	RetentionDays int        `json:"retention_days"`
	IPMode        string     `json:"ip_mode"`
}

// Health collecte l'état détaillé.
func (s *Store) Health(ctx context.Context) (HealthInfo, error) {
	h := HealthInfo{Timescale: s.timescale, RetentionDays: s.Settings().RetentionDays, IPMode: string(s.Settings().IPMode)}
	err := s.read.QueryRow(ctx, `SELECT pg_database_size(current_database()), (SELECT max(last_seen) FROM instances)`).Scan(&h.DBSizeBytes, &h.LastIngest)
	h.LastIngest = utcPtr(h.LastIngest)
	return h, err
}
