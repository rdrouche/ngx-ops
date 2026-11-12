package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Filter regroupe les critères de recherche (tous optionnels sauf la fenêtre).
type Filter struct {
	From, To time.Time
	Instance string
	Site     string
	Source   string
	Action   string
	IPCol    string // "ip" ou "ip_key" (déjà transformé selon le mode)
	IPVal    any
	Status   string // « 404 » ou « 4xx »
	Rule     string // égalité exacte (règle WAF / blocklist)
	UA, Path string // contient (insensible à la casse)
}

var statusRe = regexp.MustCompile(`^([1-5])(xx|\d\d)$`)

// ErrBadFilter est renvoyée pour un critère invalide.
var ErrBadFilter = errors.New("filtre invalide")

type builder struct {
	args []any
	cond []string
}

func (b *builder) add(v any) string {
	b.args = append(b.args, v)
	return "$" + strconv.Itoa(len(b.args))
}

func (b *builder) and(c string) { b.cond = append(b.cond, c) }

func (b *builder) where() string {
	if len(b.cond) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(b.cond, " AND ")
}

func (f Filter) build() (*builder, error) {
	b := &builder{}
	b.and("ts >= " + b.add(f.From))
	b.and("ts <= " + b.add(f.To))
	if f.Instance != "" {
		b.and("instance_id = " + b.add(f.Instance))
	}
	if f.Site != "" {
		b.and("site = " + b.add(strings.ToLower(f.Site)))
	}
	if f.Source != "" {
		b.and("source = " + b.add(f.Source))
	}
	if f.Action != "" {
		b.and("action = " + b.add(f.Action))
	}
	if f.IPCol != "" {
		if f.IPCol != "ip" && f.IPCol != "ip_key" {
			return nil, ErrBadFilter
		}
		b.and(f.IPCol + " = " + b.add(f.IPVal))
	}
	if f.Status != "" {
		m := statusRe.FindStringSubmatch(strings.ToLower(f.Status))
		if m == nil {
			return nil, fmt.Errorf("%w : status", ErrBadFilter)
		}
		if m[2] == "xx" {
			c, _ := strconv.Atoi(m[1])
			b.and(fmt.Sprintf("status BETWEEN %d AND %d", c*100, c*100+99))
		} else {
			n, _ := strconv.Atoi(m[1] + m[2])
			b.and("status = " + b.add(int16(n)))
		}
	}
	if f.Rule != "" {
		b.and("rule = " + b.add(f.Rule))
	}
	if f.UA != "" {
		b.and("position(lower(" + b.add(f.UA) + ") in lower(ua)) > 0")
	}
	if f.Path != "" {
		b.and("position(lower(" + b.add(f.Path) + ") in lower(path)) > 0")
	}
	return b, nil
}

// EventOut est un événement renvoyé par l'API.
type EventOut struct {
	ID          int64           `json:"id"`
	TS          time.Time       `json:"ts"`
	InstanceID  string          `json:"instance_id"`
	Source      string          `json:"source"`
	Action      string          `json:"action"`
	Site        *string         `json:"site"`
	IP          *string         `json:"ip"`
	IPKey       *string         `json:"ip_key"`
	Method      *string         `json:"method"`
	Path        *string         `json:"path"`
	QueryHash   *string         `json:"query_hash"`
	Status      *int16          `json:"status"`
	Bytes       *int64          `json:"bytes"`
	RTMs        *int32          `json:"rt_ms"`
	UA          *string         `json:"ua"`
	RefererHost *string         `json:"referer_host"`
	Country     *string         `json:"country"`
	BotClass    *string         `json:"bot_class"`
	Rule        *string         `json:"rule"`
	Extra       json.RawMessage `json:"extra,omitempty"`
}

// Cursor est la position de pagination (ts, id décroissants).
type Cursor struct {
	TS time.Time `json:"t"`
	ID int64     `json:"i"`
}

// Encode sérialise le curseur (opaque côté client).
func (c Cursor) Encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor lit un curseur ; erreur si invalide.
func DecodeCursor(s string) (*Cursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrBadFilter
	}
	var c Cursor
	if err := json.Unmarshal(b, &c); err != nil || c.TS.IsZero() {
		return nil, ErrBadFilter
	}
	return &c, nil
}

const eventSelect = `SELECT id, ts, instance_id, source, action, site, abbrev(ip), ip_key, method, path, query_hash,
    status, bytes, rt_ms, ua, referer_host, country, bot_class, rule, extra FROM events`

// Events renvoie une page d'événements (du plus récent au plus ancien).
func (s *Store) Events(ctx context.Context, f Filter, limit int, cur *Cursor) ([]EventOut, *Cursor, error) {
	b, err := f.build()
	if err != nil {
		return nil, nil, err
	}
	if cur != nil {
		b.and("(ts, id) < (" + b.add(cur.TS) + ", " + b.add(cur.ID) + ")")
	}
	q := eventSelect + b.where() + " ORDER BY ts DESC, id DESC LIMIT " + b.add(limit+1)
	rows, err := s.read.Query(ctx, q, b.args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	out := make([]EventOut, 0, limit)
	for rows.Next() {
		var e EventOut
		var extra []byte
		if err := rows.Scan(&e.ID, &e.TS, &e.InstanceID, &e.Source, &e.Action, &e.Site, &e.IP, &e.IPKey, &e.Method,
			&e.Path, &e.QueryHash, &e.Status, &e.Bytes, &e.RTMs, &e.UA, &e.RefererHost, &e.Country, &e.BotClass, &e.Rule, &extra); err != nil {
			return nil, nil, err
		}
		e.TS = e.TS.UTC()
		if len(extra) > 0 {
			e.Extra = extra
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	var next *Cursor
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = &Cursor{TS: last.TS, ID: last.ID}
	}
	return out, next, nil
}

// KV est une paire clé / compteur.
type KV struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// IPSummary résume l'historique d'une IP (ou clé) sur la fenêtre du filtre.
type IPSummary struct {
	FirstSeen *time.Time `json:"first_seen"`
	LastSeen  *time.Time `json:"last_seen"`
	Total     int64      `json:"total"`
	BySource  []SrcAct   `json:"by_source_action"`
}

// SrcAct compte les événements par source et action.
type SrcAct struct {
	Source string `json:"source"`
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

// IPSummary calcule le résumé.
func (s *Store) IPSummary(ctx context.Context, f Filter) (IPSummary, error) {
	var out IPSummary
	b, err := f.build()
	if err != nil {
		return out, err
	}
	if err := s.read.QueryRow(ctx, `SELECT min(ts), max(ts), count(*) FROM events`+b.where(), b.args...).Scan(&out.FirstSeen, &out.LastSeen, &out.Total); err != nil {
		return out, err
	}
	out.FirstSeen, out.LastSeen = utcPtr(out.FirstSeen), utcPtr(out.LastSeen)
	rows, err := s.read.Query(ctx, `SELECT source, action, count(*) FROM events`+b.where()+` GROUP BY 1, 2 ORDER BY 3 DESC`, b.args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.BySource = []SrcAct{}
	for rows.Next() {
		var x SrcAct
		if err := rows.Scan(&x.Source, &x.Action, &x.Count); err != nil {
			return out, err
		}
		out.BySource = append(out.BySource, x)
	}
	return out, rows.Err()
}

// VisitPoint est un point de la série de visites.
type VisitPoint struct {
	Bucket   time.Time `json:"bucket"`
	Requests int64     `json:"requests"`
	S2xx     int64     `json:"s2xx"`
	S3xx     int64     `json:"s3xx"`
	S4xx     int64     `json:"s4xx"`
	S5xx     int64     `json:"s5xx"`
	Bytes    int64     `json:"bytes"`
	Visitors *int64    `json:"visitors"` // IP distinctes ; null au-delà de la rétention brute
}

// Visits renvoie la série depuis les cumuls (unit = "hour" ou "day").
func (s *Store) Visits(ctx context.Context, f Filter, unit string) ([]VisitPoint, error) {
	table, trunc := "events_1h", time.Hour
	if unit == "day" {
		table, trunc = "events_1d", 24*time.Hour
	} else if unit != "hour" {
		return nil, fmt.Errorf("%w : bucket", ErrBadFilter)
	}
	b := &builder{}
	b.and("bucket >= " + b.add(f.From.UTC().Truncate(trunc)))
	b.and("bucket <= " + b.add(f.To.UTC()))
	if f.Instance != "" {
		b.and("instance_id = " + b.add(f.Instance))
	}
	if f.Site != "" {
		b.and("site = " + b.add(strings.ToLower(f.Site)))
	}
	src := f.Source
	if src == "" {
		src = "access"
	}
	b.and("source = " + b.add(src))
	if f.Action != "" {
		b.and("action = " + b.add(f.Action))
	}
	q := `SELECT bucket, sum(requests)::bigint, sum(s2xx)::bigint, sum(s3xx)::bigint, sum(s4xx)::bigint, sum(s5xx)::bigint, sum(bytes)::bigint
          FROM ` + table + b.where() + ` GROUP BY 1 ORDER BY 1`
	rows, err := s.read.Query(ctx, q, b.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VisitPoint{}
	for rows.Next() {
		var p VisitPoint
		if err := rows.Scan(&p.Bucket, &p.Requests, &p.S2xx, &p.S3xx, &p.S4xx, &p.S5xx, &p.Bytes); err != nil {
			return nil, err
		}
		p.Bucket = p.Bucket.UTC()
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Visiteurs distincts : uniquement sur la période encore en brut.
	rawFrom := time.Now().Add(-time.Duration(s.Settings().RetentionDays) * 24 * time.Hour)
	if len(out) == 0 || f.To.Before(rawFrom) {
		return out, nil
	}
	vf := f
	if vf.From.Before(rawFrom) {
		vf.From = rawFrom
	}
	vf.Source = src
	vb, err := vf.build()
	if err != nil {
		return nil, err
	}
	vq := `SELECT date_trunc('` + unit + `', ts) AS b, count(DISTINCT COALESCE(ip_key, abbrev(ip)))::bigint FROM events` + vb.where() + ` GROUP BY 1`
	vr, err := s.read.Query(ctx, vq, vb.args...)
	if err != nil {
		return nil, err
	}
	defer vr.Close()
	visitors := map[time.Time]int64{}
	for vr.Next() {
		var t time.Time
		var n int64
		if err := vr.Scan(&t, &n); err != nil {
			return nil, err
		}
		visitors[t.UTC()] = n
	}
	if err := vr.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if n, ok := visitors[out[i].Bucket.UTC()]; ok {
			n := n
			out[i].Visitors = &n
		}
	}
	return out, nil
}

var topDims = map[string]string{
	"path":         "path",
	"ua":           "ua",
	"country":      "country",
	"site":         "site",
	"rule":         "rule",
	"referer_host": "referer_host",
	"bot_class":    "bot_class",
	"source":       "source",
	"action":       "action",
	"status":       "status::text",
	"ip":           "COALESCE(ip_key, abbrev(ip))",
}

// Top classe les valeurs d'une dimension par nombre d'événements.
func (s *Store) Top(ctx context.Context, f Filter, dim string, limit int) ([]KV, error) {
	expr, ok := topDims[dim]
	if !ok {
		return nil, fmt.Errorf("%w : dimension", ErrBadFilter)
	}
	b, err := f.build()
	if err != nil {
		return nil, err
	}
	b.and(expr + " IS NOT NULL")
	q := `SELECT ` + expr + ` AS k, count(*)::bigint FROM events` + b.where() + ` GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT ` + b.add(limit)
	rows, err := s.read.Query(ctx, q, b.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KV{}
	for rows.Next() {
		var kv KV
		if err := rows.Scan(&kv.Key, &kv.Count); err != nil {
			return nil, err
		}
		out = append(out, kv)
	}
	return out, rows.Err()
}

// Scanner est une IP qui sonde de nombreux chemins en erreur.
type Scanner struct {
	Key           string    `json:"key"`
	Errors        int64     `json:"errors"`
	DistinctPaths int64     `json:"distinct_paths"`
	LastSeen      time.Time `json:"last_seen"`
}

// SecurityReport est la synthèse sécurité d'une fenêtre.
type SecurityReport struct {
	Status struct {
		S2xx int64 `json:"s2xx"`
		S3xx int64 `json:"s3xx"`
		S4xx int64 `json:"s4xx"`
		S5xx int64 `json:"s5xx"`
	} `json:"status_classes"`
	Blocked  []SrcAct  `json:"blocked"`
	Scanners []Scanner `json:"scanners"`
	ErrorUAs []KV      `json:"error_user_agents"`
}

// Security calcule la synthèse (accès uniquement pour les statuts HTTP).
func (s *Store) Security(ctx context.Context, f Filter, minPaths int) (SecurityReport, error) {
	var r SecurityReport
	f.Source, f.Action, f.Status, f.UA, f.Path, f.IPCol = "", "", "", "", "", ""
	base := func(extra ...string) (*builder, error) {
		b, err := f.build()
		if err != nil {
			return nil, err
		}
		for _, e := range extra {
			b.and(e)
		}
		return b, nil
	}

	b, err := base("source = 'access'")
	if err != nil {
		return r, err
	}
	if err := s.read.QueryRow(ctx, `SELECT
        count(*) FILTER (WHERE status BETWEEN 200 AND 299), count(*) FILTER (WHERE status BETWEEN 300 AND 399),
        count(*) FILTER (WHERE status BETWEEN 400 AND 499), count(*) FILTER (WHERE status BETWEEN 500 AND 599)
        FROM events`+b.where(), b.args...).Scan(&r.Status.S2xx, &r.Status.S3xx, &r.Status.S4xx, &r.Status.S5xx); err != nil {
		return r, err
	}

	b, _ = base("action IN ('blocked','challenged')")
	rows, err := s.read.Query(ctx, `SELECT source, action, count(*)::bigint FROM events`+b.where()+` GROUP BY 1, 2 ORDER BY 3 DESC`, b.args...)
	if err != nil {
		return r, err
	}
	r.Blocked = []SrcAct{}
	for rows.Next() {
		var x SrcAct
		if err := rows.Scan(&x.Source, &x.Action, &x.Count); err != nil {
			rows.Close()
			return r, err
		}
		r.Blocked = append(r.Blocked, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}

	b, _ = base("source = 'access'", "status IN (400,401,403,404,405)", "COALESCE(ip_key, abbrev(ip)) IS NOT NULL")
	q := `SELECT COALESCE(ip_key, abbrev(ip)), count(*)::bigint, count(DISTINCT path)::bigint, max(ts) FROM events` + b.where() +
		` GROUP BY 1 HAVING count(DISTINCT path) >= ` + b.add(minPaths) + ` ORDER BY 3 DESC, 2 DESC LIMIT 50`
	rows, err = s.read.Query(ctx, q, b.args...)
	if err != nil {
		return r, err
	}
	r.Scanners = []Scanner{}
	for rows.Next() {
		var x Scanner
		if err := rows.Scan(&x.Key, &x.Errors, &x.DistinctPaths, &x.LastSeen); err != nil {
			rows.Close()
			return r, err
		}
		x.LastSeen = x.LastSeen.UTC()
		r.Scanners = append(r.Scanners, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}

	b, _ = base("source = 'access'", "status >= 400", "ua IS NOT NULL")
	rows, err = s.read.Query(ctx, `SELECT ua, count(*)::bigint FROM events`+b.where()+` GROUP BY 1 ORDER BY 2 DESC LIMIT 20`, b.args...)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	r.ErrorUAs = []KV{}
	for rows.Next() {
		var x KV
		if err := rows.Scan(&x.Key, &x.Count); err != nil {
			return r, err
		}
		r.ErrorUAs = append(r.ErrorUAs, x)
	}
	return r, rows.Err()
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// IPCorr est une IP (ou /24, ou clé de pseudonyme selon le mode IP) vue dans la fenêtre, avec ce qui la caractérise
// à travers les instances et les sources. Aucun chemin, User-Agent ni requête : des comptes et des listes d'identifiants.
type IPCorr struct {
	Key       string    `json:"key"`
	Events    int64     `json:"events"`
	Blocked   int64     `json:"blocked"`
	Errors    int64     `json:"errors"` // accès en 4xx/5xx
	Instances []string  `json:"instances"`
	NInst     int64     `json:"instance_count"`
	Sources   []string  `json:"sources"`
	Sites     int64     `json:"sites"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

const maxCorrInstances = 20

// Campaign est une signature d'attaque (règle + chemin) observée depuis plusieurs IP : sondage distribué.
type Campaign struct {
	Rule      string    `json:"rule"`
	Path      string    `json:"path"`
	Events    int64     `json:"events"`
	Blocked   int64     `json:"blocked"`
	IPs       int64     `json:"ip_count"`
	Sites     int64     `json:"site_count"`
	NInst     int64     `json:"instance_count"`
	Sources   []string  `json:"sources"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Campaigns regroupe les événements porteurs d'une règle (WAF, blocklist, challenge…) par (règle, chemin) et ne garde que les
// signatures vues depuis au moins minIPs adresses distinctes. Pas d'IP en sortie : le détail passe par l'explorateur (filtre rule/path).
func (s *Store) Campaigns(ctx context.Context, f Filter, minIPs, limit int) ([]Campaign, error) {
	b, err := f.build()
	if err != nil {
		return nil, err
	}
	b.and("rule IS NOT NULL")
	b.and("COALESCE(ip_key, abbrev(ip)) IS NOT NULL")
	q := `SELECT rule, COALESCE(path, ''), count(*)::bigint,
        count(*) FILTER (WHERE action IN ('blocked','challenged'))::bigint,
        count(DISTINCT COALESCE(ip_key, abbrev(ip)))::bigint, count(DISTINCT site)::bigint, count(DISTINCT instance_id)::bigint,
        COALESCE(string_agg(DISTINCT source, ','), ''), min(ts), max(ts)
        FROM events` + b.where() + ` GROUP BY 1, 2
        HAVING count(DISTINCT COALESCE(ip_key, abbrev(ip))) >= ` + b.add(minIPs) + `
        ORDER BY 5 DESC, 3 DESC, 1, 2 LIMIT ` + b.add(limit)
	rows, err := s.read.Query(ctx, q, b.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Campaign{}
	for rows.Next() {
		var c Campaign
		var src string
		if err := rows.Scan(&c.Rule, &c.Path, &c.Events, &c.Blocked, &c.IPs, &c.Sites, &c.NInst, &src, &c.FirstSeen, &c.LastSeen); err != nil {
			return nil, err
		}
		c.Sources = strings.Split(src, ",")
		c.FirstSeen, c.LastSeen = c.FirstSeen.UTC(), c.LastSeen.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// IPCorrelation liste les IP vues par au moins minInst instances ET minSrc sources distinctes (corrélation inter-instances).
// Le filtre d'instance, de source, d'action, d'IP, de statut, de UA et de chemin du Filter est ignoré : la corrélation porte
// sur l'ensemble de la base pour la fenêtre.
func (s *Store) IPCorrelation(ctx context.Context, f Filter, minInst, minSrc, limit int) ([]IPCorr, error) {
	f.Instance, f.Site, f.Source, f.Action, f.IPCol, f.Status, f.UA, f.Path, f.Rule = "", "", "", "", "", "", "", "", ""
	b, err := f.build()
	if err != nil {
		return nil, err
	}
	b.and("COALESCE(ip_key, abbrev(ip)) IS NOT NULL")
	q := `SELECT COALESCE(ip_key, abbrev(ip)) AS k, count(*)::bigint,
        count(*) FILTER (WHERE action IN ('blocked','challenged'))::bigint,
        count(*) FILTER (WHERE source = 'access' AND status >= 400)::bigint,
        count(DISTINCT instance_id)::bigint, COALESCE(string_agg(DISTINCT instance_id, ','), ''),
        COALESCE(string_agg(DISTINCT source, ','), ''), count(DISTINCT site)::bigint, min(ts), max(ts)
        FROM events` + b.where() + ` GROUP BY 1
        HAVING count(DISTINCT instance_id) >= ` + b.add(minInst) + ` AND count(DISTINCT source) >= ` + b.add(minSrc) + `
        ORDER BY 5 DESC, 3 DESC, 2 DESC, 1 LIMIT ` + b.add(limit)
	rows, err := s.read.Query(ctx, q, b.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPCorr{}
	for rows.Next() {
		var x IPCorr
		var inst, src string
		if err := rows.Scan(&x.Key, &x.Events, &x.Blocked, &x.Errors, &x.NInst, &inst, &src, &x.Sites, &x.FirstSeen, &x.LastSeen); err != nil {
			return nil, err
		}
		x.Instances = strings.Split(inst, ",")
		if len(x.Instances) > maxCorrInstances {
			x.Instances = x.Instances[:maxCorrInstances]
		}
		x.Sources = strings.Split(src, ",")
		x.FirstSeen, x.LastSeen = x.FirstSeen.UTC(), x.LastSeen.UTC()
		out = append(out, x)
	}
	return out, rows.Err()
}
