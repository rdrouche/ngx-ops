// Package model normalise et valide les événements reçus avant stockage.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"ngxops/logstore/internal/ipmode"
	"ngxops/logstore/pkg/wire"
)

// Limites de taille (octets) appliquées aux champs texte.
const (
	MaxPath    = 2048
	MaxUA      = 512
	MaxSite    = 253
	MaxRule    = 128
	MaxBotCls  = 64
	MaxExtra   = 4096
	maxFuture  = 5 * time.Minute
	maxRTMs    = 3_600_000
	maxMethodL = 16
)

var methodRe = regexp.MustCompile(`^[A-Z]{1,16}$`)

// Row est un événement prêt à être inséré (champs vides = NULL).
type Row struct {
	TS          time.Time
	Source      string
	Action      string
	Site        *string
	IP          any
	IPKey       *string
	Method      *string
	Path        *string
	QueryHash   *string
	Status      *int16
	Bytes       *int64
	RTMs        *int32
	UA          *string
	RefererHost *string
	Country     *string
	BotClass    *string
	Rule        *string
	Extra       json.RawMessage
}

// Params regroupe le contexte de normalisation d'un lot.
type Params struct {
	Now    time.Time
	MaxAge time.Duration // événements plus anciens refusés (rétention brute)
	Mode   ipmode.Mode
	T      *ipmode.Transformer
}

// Normalize valide ev et produit la ligne à stocker. L'erreur est un code
// court (« bad_source », « too_old », …) renvoyé tel quel au producteur :
// jamais de contenu de l'événement ni de secret dedans.
func Normalize(ev wire.Event, p Params) (Row, error) {
	var r Row
	if ev.TS.IsZero() {
		return r, code("bad_ts")
	}
	if ev.TS.After(p.Now.Add(maxFuture)) {
		return r, code("ts_in_future")
	}
	if p.MaxAge > 0 && ev.TS.Before(p.Now.Add(-p.MaxAge)) {
		return r, code("too_old")
	}
	if !wire.ValidSource(ev.Source) {
		return r, code("bad_source")
	}
	if !wire.ValidAction(ev.Action) {
		return r, code("bad_action")
	}
	r.TS = ev.TS.UTC()
	r.Source, r.Action = ev.Source, ev.Action

	if ev.Method != "" {
		m := strings.ToUpper(ev.Method)
		if !methodRe.MatchString(m) {
			return r, code("bad_method")
		}
		r.Method = &m
	}
	if ev.Status != 0 {
		if ev.Status < 100 || ev.Status > 599 {
			return r, code("bad_status")
		}
		s := int16(ev.Status)
		r.Status = &s
	}
	if ev.Bytes < 0 {
		return r, code("bad_bytes")
	} else if ev.Bytes > 0 {
		b := ev.Bytes
		r.Bytes = &b
	}
	if ev.RTMs < 0 || ev.RTMs > maxRTMs {
		return r, code("bad_rt")
	} else if ev.RTMs > 0 {
		v := int32(ev.RTMs)
		r.RTMs = &v
	}
	if ev.Country != "" {
		c := strings.ToUpper(ev.Country)
		if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
			return r, code("bad_country")
		}
		r.Country = &c
	}

	r.Site = text(strings.ToLower(ev.Site), MaxSite)
	r.Path = text(ev.Path, MaxPath)
	r.UA = text(ev.UA, MaxUA)
	r.BotClass = text(ev.BotClass, MaxBotCls)
	r.Rule = text(ev.Rule, MaxRule)
	r.RefererHost = refererHost(ev.Referer)
	if ev.Query != "" {
		sum := sha256.Sum256([]byte(ev.Query))
		h := hex.EncodeToString(sum[:8])
		r.QueryHash = &h
	}

	st, err := p.T.Apply(p.Mode, ev.IP)
	if err != nil {
		if err == ipmode.ErrBadIP {
			return r, code("bad_ip")
		}
		return r, code("ip_mode_unavailable")
	}
	r.IP, r.IPKey = st.IP, st.IPKey

	if len(ev.Extra) > 0 {
		b, err := json.Marshal(ev.Extra)
		if err != nil || len(b) > MaxExtra {
			return r, code("extra_too_large")
		}
		r.Extra = b
	}
	return r, nil
}

type code string

func (c code) Error() string { return string(c) }

// text nettoie (caractères de contrôle supprimés, UTF-8 valide) et tronque.
func text(s string, max int) *string {
	if s == "" {
		return nil
	}
	s = clean(s)
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) && len(s) > 0 {
			s = s[:len(s)-1]
		}
	}
	if s == "" {
		return nil
	}
	return &s
}

func clean(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func refererHost(ref string) *string {
	if ref == "" || ref == "-" {
		return nil
	}
	u, err := url.Parse(ref)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	return text(strings.ToLower(u.Hostname()), MaxSite)
}
