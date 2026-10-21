package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// ---------- Alertes ----------

// AlertRow : alerte persistee (evidence = JSON brut).
type AlertRow struct {
	ID       int64
	TS       int64
	Severity string
	IP       string
	Vhost    string
	Ack      bool
	Evidence json.RawMessage
}

// InsertAlert ecrit une alerte (id fourni par l'appelant, voir MaxAlertID).
func InsertAlert(tx *sql.Tx, a AlertRow) error {
	_, err := tx.Exec(`INSERT INTO waf_alerts(id,ts,severity,ip,vhost,ack,evidence) VALUES(?,?,?,?,?,0,?)`,
		a.ID, a.TS, a.Severity, a.IP, a.Vhost, string(a.Evidence))
	return err
}

// MaxAlertID : plus grand id d'alerte (0 si aucune).
func (s *Store) MaxAlertID(ctx context.Context) int64 {
	return int64(s.scalar(ctx, `SELECT MAX(id) FROM waf_alerts`))
}

// QueryAlerts lit une page d'alertes : id > sinceID (et id < beforeID si beforeID > 0).
func (s *Store) QueryAlerts(ctx context.Context, sinceID, beforeID int64, asc bool, limit int) ([]AlertRow, error) {
	q := `SELECT id,ts,severity,ip,vhost,ack,evidence FROM waf_alerts WHERE id > ?`
	args := []any{sinceID}
	if beforeID > 0 {
		q += ` AND id < ?`
		args = append(args, beforeID)
	}
	if asc {
		q += ` ORDER BY id ASC LIMIT ?`
	} else {
		q += ` ORDER BY id DESC LIMIT ?`
	}
	args = append(args, limit)
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRow
	for rows.Next() {
		var a AlertRow
		var ack int
		var ev string
		if err := rows.Scan(&a.ID, &a.TS, &a.Severity, &a.IP, &a.Vhost, &ack, &ev); err != nil {
			return nil, err
		}
		a.Ack = ack == 1
		a.Evidence = json.RawMessage(ev)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AckAlerts marque des alertes comme acquittees (synchrone).
func (s *Store) AckAlerts(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	return s.DoSync(func(tx *sql.Tx) error {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		args := make([]any, len(ids))
		for i, id := range ids {
			args[i] = id
		}
		_, err := tx.Exec(`UPDATE waf_alerts SET ack=1 WHERE id IN (`+ph+`)`, args...)
		return err
	})
}

// RecentAlerts : derniere alerte par IP depuis sinceMs (restauration des marques au demarrage).
func (s *Store) RecentAlerts(ctx context.Context, sinceMs int64) []AlertRow {
	rows, err := s.query(ctx, `SELECT id,ts,severity,ip,vhost,ack,'' FROM waf_alerts WHERE ts >= ? ORDER BY id`, sinceMs)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []AlertRow
	for rows.Next() {
		var a AlertRow
		var ack int
		var ev string
		if rows.Scan(&a.ID, &a.TS, &a.Severity, &a.IP, &a.Vhost, &ack, &ev) == nil {
			out = append(out, a)
		}
	}
	return out
}

// ---------- Listes ----------

// ListedRow : IP listee.
type ListedRow struct {
	IP       string
	List     string
	Score    int
	Hits     int
	Since    int64
	Until    int64
	Vhosts   []string
	TopRules []int
}

// UpsertListed ecrit ou remplace une entree de liste.
func UpsertListed(tx *sql.Tx, r ListedRow) error {
	v, _ := json.Marshal(r.Vhosts)
	t, _ := json.Marshal(r.TopRules)
	_, err := tx.Exec(`INSERT OR REPLACE INTO waf_listed(ip,list,score,hits,since,until,vhosts,toprules) VALUES(?,?,?,?,?,?,?,?)`,
		r.IP, r.List, r.Score, r.Hits, r.Since, r.Until, string(v), string(t))
	return err
}

// DeleteListed retire une IP de la liste donnee ("" = toutes).
func DeleteListed(tx *sql.Tx, ip, list string) error {
	if list == "" {
		_, err := tx.Exec(`DELETE FROM waf_listed WHERE ip=?`, ip)
		return err
	}
	_, err := tx.Exec(`DELETE FROM waf_listed WHERE ip=? AND list=?`, ip, list)
	return err
}

// SetGrace memorise « ne plus lister avant until ».
func SetGrace(tx *sql.Tx, ip string, until int64) error {
	_, err := tx.Exec(`INSERT OR REPLACE INTO waf_grace(ip,until) VALUES(?,?)`, ip, until)
	return err
}

// LoadListed charge les listes non expirees.
func (s *Store) LoadListed(ctx context.Context, nowMs int64) []ListedRow {
	rows, err := s.query(ctx, `SELECT ip,list,score,hits,since,until,vhosts,toprules FROM waf_listed WHERE until > ?`, nowMs)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ListedRow
	for rows.Next() {
		var r ListedRow
		var v, t string
		if rows.Scan(&r.IP, &r.List, &r.Score, &r.Hits, &r.Since, &r.Until, &v, &t) == nil {
			_ = json.Unmarshal([]byte(v), &r.Vhosts)
			_ = json.Unmarshal([]byte(t), &r.TopRules)
			out = append(out, r)
		}
	}
	return out
}

// LoadGrace charge les delais de grace non expires.
func (s *Store) LoadGrace(ctx context.Context, nowMs int64) map[string]int64 {
	out := map[string]int64{}
	rows, err := s.query(ctx, `SELECT ip,until FROM waf_grace WHERE until > ?`, nowMs)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var u int64
		if rows.Scan(&ip, &u) == nil {
			out[ip] = u
		}
	}
	return out
}

// ---------- Offsets (tail.OffsetStore) et vhosts ----------

// OffsetRow : position de lecture d'un fichier.
type OffsetRow struct {
	Inode  uint64
	Offset int64
	Format string
}

// LoadOffsets charge tous les offsets.
func (s *Store) LoadOffsets(ctx context.Context) map[string]OffsetRow {
	out := map[string]OffsetRow{}
	rows, err := s.query(ctx, `SELECT file,inode,offset,format FROM waf_offsets`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var f string
		var ino, off sql.NullInt64
		var fm sql.NullString
		if rows.Scan(&f, &ino, &off, &fm) == nil {
			out[f] = OffsetRow{Inode: uint64(ino.Int64), Offset: off.Int64, Format: fm.String}
		}
	}
	return out
}

// SaveOffsets ecrit un lot d'offsets.
func SaveOffsets(tx *sql.Tx, m map[string]OffsetRow) error {
	for f, r := range m {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO waf_offsets(file,inode,offset,format) VALUES(?,?,?,?)`,
			f, int64(r.Inode), r.Offset, r.Format); err != nil {
			return err
		}
	}
	return nil
}

// VhostRow : vhost vu dans les logs.
type VhostRow struct {
	Name     string
	Lines    int64
	LastSeen int64
	Format   string
}

// LoadVhosts charge les vhosts connus.
func (s *Store) LoadVhosts(ctx context.Context) []VhostRow {
	rows, err := s.query(ctx, `SELECT name,lines,last_seen,format FROM waf_vhosts`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []VhostRow
	for rows.Next() {
		var r VhostRow
		var f sql.NullString
		if rows.Scan(&r.Name, &r.Lines, &r.LastSeen, &f) == nil {
			r.Format = f.String
			out = append(out, r)
		}
	}
	return out
}

// SaveVhosts ecrit (remplace) un lot de vhosts.
func SaveVhosts(tx *sql.Tx, rs []VhostRow) error {
	for _, r := range rs {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO waf_vhosts(name,lines,last_seen,format) VALUES(?,?,?,?)`,
			r.Name, r.Lines, r.LastSeen, r.Format); err != nil {
			return err
		}
	}
	return nil
}

// ---------- Retention ----------

// Purge supprime les donnees plus anciennes que la retention.
func (s *Store) Purge(nowMs int64, hitDays, alertDays int) {
	hitCut := nowMs - int64(hitDays)*24*int64(time.Hour/time.Millisecond)
	alertCut := nowMs - int64(alertDays)*24*int64(time.Hour/time.Millisecond)
	s.Do(func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql string
			arg int64
		}{
			{`DELETE FROM waf_hit_rules WHERE ts < ?`, hitCut},
			{`DELETE FROM waf_hits WHERE ts < ?`, hitCut},
			{`DELETE FROM waf_req_stats WHERE bucket < ?`, hitCut / 60000},
			{`DELETE FROM waf_alerts WHERE ts < ?`, alertCut},
			{`DELETE FROM waf_listed WHERE until < ?`, nowMs},
			{`DELETE FROM waf_grace WHERE until < ?`, nowMs},
		} {
			if _, err := tx.Exec(q.sql, q.arg); err != nil {
				return err
			}
		}
		return nil
	})
}
