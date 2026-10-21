package store

import (
	"context"
	"database/sql"
)

// RuleCount / IPCount / VhostCount / CatCount / TimePoint : agregats de /api/hits/stats.
type RuleCount struct {
	ID    int    `json:"id"`
	Msg   string `json:"msg"`
	Count int    `json:"count"`
	Score int    `json:"score"`
}
type IPCount struct {
	IP    string   `json:"ip"`
	Hits  int      `json:"hits"`
	Score int      `json:"score"`
	Lists []string `json:"lists"`
}
type VhostCount struct {
	Vhost    string `json:"vhost"`
	Requests int    `json:"requests"`
	Hits     int    `json:"hits"`
}
type CatCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}
type TimePoint struct {
	T        int64 `json:"t"`
	Requests int   `json:"requests"`
	Hits     int   `json:"hits"`
}

// Stats : resultat brut (les listes d'IP sont completees par l'appelant).
type Stats struct {
	Requests    int
	HitRequests int
	IPs         int
	TopRules    []RuleCount
	TopIPs      []IPCount
	TopVhosts   []VhostCount
	ByCategory  []CatCount
	Timeline    []TimePoint
}

func (s *Store) scalar(ctx context.Context, q string, args ...any) int {
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return 0
	}
	defer rows.Close()
	var n sql.NullInt64
	if rows.Next() {
		_ = rows.Scan(&n)
	}
	return int(n.Int64)
}

// QueryStats agrege la fenetre [sinceMs, now]. stepMin = pas de la serie temporelle.
func (s *Store) QueryStats(ctx context.Context, sinceMs, nowMs int64, stepMin int) (Stats, error) {
	var st Stats
	if !s.OK() {
		return st, nil
	}
	sinceBucket := sinceMs / 60000
	st.Requests = s.scalar(ctx, `SELECT SUM(requests) FROM waf_req_stats WHERE bucket >= ?`, sinceBucket)
	st.HitRequests = s.scalar(ctx, `SELECT COUNT(*) FROM waf_hits WHERE ts >= ?`, sinceMs)
	st.IPs = s.scalar(ctx, `SELECT COUNT(DISTINCT ip) FROM waf_hits WHERE ts >= ?`, sinceMs)

	if rows, err := s.query(ctx, `SELECT rule_id, MAX(msg), COUNT(*), SUM(score) FROM waf_hit_rules WHERE ts >= ?
		GROUP BY rule_id ORDER BY COUNT(*) DESC, rule_id LIMIT 10`, sinceMs); err == nil {
		for rows.Next() {
			var r RuleCount
			var msg sql.NullString
			if rows.Scan(&r.ID, &msg, &r.Count, &r.Score) == nil {
				r.Msg = msg.String
				st.TopRules = append(st.TopRules, r)
			}
		}
		rows.Close()
	}
	if rows, err := s.query(ctx, `SELECT ip, COUNT(*), SUM(score) FROM waf_hits WHERE ts >= ?
		GROUP BY ip ORDER BY SUM(score) DESC, COUNT(*) DESC LIMIT 10`, sinceMs); err == nil {
		for rows.Next() {
			var r IPCount
			if rows.Scan(&r.IP, &r.Hits, &r.Score) == nil {
				st.TopIPs = append(st.TopIPs, r)
			}
		}
		rows.Close()
	}
	if rows, err := s.query(ctx, `SELECT vhost, SUM(requests), SUM(hits) FROM waf_req_stats WHERE bucket >= ?
		GROUP BY vhost ORDER BY SUM(requests) DESC LIMIT 10`, sinceBucket); err == nil {
		for rows.Next() {
			var r VhostCount
			if rows.Scan(&r.Vhost, &r.Requests, &r.Hits) == nil {
				st.TopVhosts = append(st.TopVhosts, r)
			}
		}
		rows.Close()
	}
	if rows, err := s.query(ctx, `SELECT category, COUNT(*) FROM waf_hit_rules WHERE ts >= ?
		GROUP BY category ORDER BY COUNT(*) DESC`, sinceMs); err == nil {
		for rows.Next() {
			var r CatCount
			if rows.Scan(&r.Category, &r.Count) == nil {
				st.ByCategory = append(st.ByCategory, r)
			}
		}
		rows.Close()
	}
	// Serie temporelle : buckets alignes sur stepMin (epoch), de since a now.
	if stepMin < 1 {
		stepMin = 1
	}
	step := int64(stepMin)
	first := sinceBucket / step * step
	last := nowMs / 60000 / step * step
	byT := map[int64]*TimePoint{}
	if rows, err := s.query(ctx, `SELECT (bucket / ?) * ?, SUM(requests), SUM(hits) FROM waf_req_stats
		WHERE bucket >= ? GROUP BY 1`, step, step, first); err == nil {
		for rows.Next() {
			var b int64
			var r, h int
			if rows.Scan(&b, &r, &h) == nil {
				byT[b] = &TimePoint{T: b * 60000, Requests: r, Hits: h}
			}
		}
		rows.Close()
	}
	for b := first; b <= last; b += step {
		if p, ok := byT[b]; ok {
			st.Timeline = append(st.Timeline, *p)
		} else {
			st.Timeline = append(st.Timeline, TimePoint{T: b * 60000})
		}
	}
	return st, nil
}

// Hits24h : nombre de requetes avec hit par vhost depuis sinceMs (pour /api/vhosts).
func (s *Store) HitsByVhost(ctx context.Context, sinceMs int64) map[string]int {
	out := map[string]int{}
	rows, err := s.query(ctx, `SELECT vhost, SUM(hits) FROM waf_req_stats WHERE bucket >= ? GROUP BY vhost`, sinceMs/60000)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		var n int
		if rows.Scan(&v, &n) == nil {
			out[v] = n
		}
	}
	return out
}

// RuleHits : nombre de hits par regle depuis sinceMs (hits7d).
func (s *Store) RuleHits(ctx context.Context, sinceMs int64) map[int]int {
	out := map[int]int{}
	rows, err := s.query(ctx, `SELECT rule_id, COUNT(*) FROM waf_hit_rules WHERE ts >= ? GROUP BY rule_id`, sinceMs)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, n int
		if rows.Scan(&id, &n) == nil {
			out[id] = n
		}
	}
	return out
}

// CategoryHits : hits par categorie depuis sinceMs.
func (s *Store) CategoryHits(ctx context.Context, sinceMs int64) map[string]int {
	out := map[string]int{}
	rows, err := s.query(ctx, `SELECT category, COUNT(*) FROM waf_hit_rules WHERE ts >= ? GROUP BY category`, sinceMs)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		var n int
		if rows.Scan(&c, &n) == nil {
			out[c] = n
		}
	}
	return out
}

// Summary24h : requetes / hits / IP distinctes sur la fenetre.
func (s *Store) Summary(ctx context.Context, sinceMs int64) (requests, hits, ips int) {
	if !s.OK() {
		return
	}
	requests = s.scalar(ctx, `SELECT SUM(requests) FROM waf_req_stats WHERE bucket >= ?`, sinceMs/60000)
	hits = s.scalar(ctx, `SELECT COUNT(*) FROM waf_hits WHERE ts >= ?`, sinceMs)
	ips = s.scalar(ctx, `SELECT COUNT(DISTINCT ip) FROM waf_hits WHERE ts >= ?`, sinceMs)
	return
}
