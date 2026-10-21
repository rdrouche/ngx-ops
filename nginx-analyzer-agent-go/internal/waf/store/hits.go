package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// HitRule : une regle declenchee, telle qu'exposee par l'API.
type HitRule struct {
	ID       int      `json:"id"`
	Msg      string   `json:"msg"`
	Severity string   `json:"severity"`
	Score    int      `json:"score"`
	Data     string   `json:"data"`
	Tags     []string `json:"tags"`
	Category string   `json:"-"`
}

// Hit : une requete ayant declenche au moins une regle retenue.
type Hit struct {
	ID                int64     `json:"id"`
	TS                int64     `json:"ts"`
	Vhost             string    `json:"vhost"`
	IP                string    `json:"ip"`
	Method            string    `json:"method"`
	URI               string    `json:"uri"`
	Status            int       `json:"status"`
	UA                string    `json:"ua"`
	Score             int       `json:"score"`
	Mode              string    `json:"mode"`
	Format            string    `json:"format"`
	Rules             []HitRule `json:"rules"`
	PossiblySucceeded bool      `json:"possiblySucceeded"`
}

// ReqStat : compteur par minute et par vhost (requetes analysees / requetes avec hit).
type ReqStat struct {
	Bucket   int64 // minute epoch (ts_ms / 60000)
	Vhost    string
	Requests int
	Hits     int
}

// InsertHits ecrit un lot de hits (et leurs regles) dans la transaction.
func InsertHits(tx *sql.Tx, hits []Hit) error {
	hs, err := tx.Prepare(`INSERT INTO waf_hits(ts,vhost,ip,method,uri,status,ua,score,mode,format,rules,possibly) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer hs.Close()
	rs, err := tx.Prepare(`INSERT INTO waf_hit_rules(hit_id,ts,rule_id,vhost,score,category,msg) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer rs.Close()
	for _, h := range hits {
		rj, _ := json.Marshal(h.Rules)
		poss := 0
		if h.PossiblySucceeded {
			poss = 1
		}
		res, err := hs.Exec(h.TS, h.Vhost, h.IP, h.Method, h.URI, h.Status, h.UA, h.Score, h.Mode, h.Format, string(rj), poss)
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		for _, r := range h.Rules {
			if _, err := rs.Exec(id, h.TS, r.ID, h.Vhost, r.Score, r.Category, r.Msg); err != nil {
				return err
			}
		}
	}
	return nil
}

// AddReqStats ajoute (additif) des compteurs de requetes.
func AddReqStats(tx *sql.Tx, stats []ReqStat) error {
	st, err := tx.Prepare(`INSERT INTO waf_req_stats(bucket,vhost,requests,hits) VALUES(?,?,?,?)
		ON CONFLICT(bucket,vhost) DO UPDATE SET requests=requests+excluded.requests, hits=hits+excluded.hits`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, s := range stats {
		if _, err := st.Exec(s.Bucket, s.Vhost, s.Requests, s.Hits); err != nil {
			return err
		}
	}
	return nil
}

// HitFilter : filtres de GET /api/hits.
type HitFilter struct {
	Since, Until int64 // epoch ms (0 = sans borne)
	IP, Vhost    string
	Rule         int
	MinScore     int
	Mode         string
	Limit        int
	Offset       int
	Asc          bool
}

func (f HitFilter) where() (string, []any) {
	var c []string
	var a []any
	if f.Since > 0 {
		c = append(c, "h.ts >= ?")
		a = append(a, f.Since)
	}
	if f.Until > 0 {
		c = append(c, "h.ts <= ?")
		a = append(a, f.Until)
	}
	if f.IP != "" {
		c = append(c, "h.ip = ?")
		a = append(a, f.IP)
	}
	if f.Vhost != "" {
		c = append(c, "h.vhost = ?")
		a = append(a, f.Vhost)
	}
	if f.Rule > 0 {
		c = append(c, "h.id IN (SELECT hit_id FROM waf_hit_rules WHERE rule_id = ?)")
		a = append(a, f.Rule)
	}
	if f.MinScore > 0 {
		c = append(c, "h.score >= ?")
		a = append(a, f.MinScore)
	}
	if f.Mode != "" {
		c = append(c, "h.mode = ?")
		a = append(a, f.Mode)
	}
	if len(c) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(c, " AND "), a
}

// QueryHits renvoie (total, hits) pour le filtre.
func (s *Store) QueryHits(ctx context.Context, f HitFilter) (int, []Hit, error) {
	w, args := f.where()
	var total int
	rows, err := s.query(ctx, "SELECT COUNT(*) FROM waf_hits h"+w, args...)
	if err != nil {
		return 0, nil, err
	}
	if rows.Next() {
		_ = rows.Scan(&total)
	}
	rows.Close()
	order := "DESC"
	if f.Asc {
		order = "ASC"
	}
	q := fmt.Sprintf(`SELECT h.id,h.ts,h.vhost,h.ip,h.method,h.uri,h.status,h.ua,h.score,h.mode,h.format,h.rules,h.possibly
		FROM waf_hits h%s ORDER BY h.ts %s, h.id %s LIMIT ? OFFSET ?`, w, order, order)
	rows, err = s.query(ctx, q, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	out := []Hit{}
	for rows.Next() {
		var h Hit
		var rj string
		var poss int
		var method, uri, ua, format sql.NullString
		var status sql.NullInt64
		if err := rows.Scan(&h.ID, &h.TS, &h.Vhost, &h.IP, &method, &uri, &status, &ua, &h.Score, &h.Mode, &format, &rj, &poss); err != nil {
			return 0, nil, err
		}
		h.Method, h.URI, h.UA, h.Format = method.String, uri.String, ua.String, format.String
		h.Status = int(status.Int64)
		h.PossiblySucceeded = poss == 1
		_ = json.Unmarshal([]byte(rj), &h.Rules)
		if h.Rules == nil {
			h.Rules = []HitRule{}
		}
		out = append(out, h)
	}
	return total, out, rows.Err()
}
