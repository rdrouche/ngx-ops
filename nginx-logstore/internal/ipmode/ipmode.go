// Package ipmode applique le mode de stockage des adresses IP (RGPD).
package ipmode

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Mode est le mode de stockage des IP, réglable par l'administrateur.
type Mode string

const (
	Clear         Mode = "clear"
	Pseudonymized Mode = "pseudonymized"
	Truncated     Mode = "truncated"
)

// MinKeyLen est la longueur minimale de la clé de pseudonymisation (octets).
const MinKeyLen = 32

// ErrBadIP est renvoyée pour une adresse illisible.
var ErrBadIP = errors.New("bad_ip")

// Parse valide un mode.
func Parse(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case Clear, Pseudonymized, Truncated:
		return m, nil
	}
	return "", fmt.Errorf("mode IP inconnu %q (clear, pseudonymized, truncated)", s)
}

// Transformer porte la clé HMAC (jamais journalisée, jamais en base).
type Transformer struct{ key []byte }

// New crée un Transformer. La clé peut être vide (mode pseudonymized alors refusé).
func New(key string) *Transformer { return &Transformer{key: []byte(key)} }

// HasKey indique si une clé exploitable est configurée.
func (t *Transformer) HasKey() bool { return len(t.key) >= MinKeyLen }

// Normalize lit une IP, retire la zone IPv6 et déplie les IPv4 mappées.
func Normalize(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexByte(raw, '%'); i >= 0 {
		raw = raw[:i]
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, ErrBadIP
	}
	return a.Unmap(), nil
}

// Stored est la valeur à écrire en base pour une IP donnée.
type Stored struct {
	IP    any     // netip.Addr, netip.Prefix ou nil
	IPKey *string // pseudonyme ou nil
}

// Apply transforme raw selon le mode. raw vide -> valeurs nulles.
func (t *Transformer) Apply(mode Mode, raw string) (Stored, error) {
	if strings.TrimSpace(raw) == "" {
		return Stored{}, nil
	}
	a, err := Normalize(raw)
	if err != nil {
		return Stored{}, err
	}
	switch mode {
	case Clear:
		return Stored{IP: a}, nil
	case Truncated:
		bits := 24
		if a.Is6() {
			bits = 48
		}
		p, _ := a.Prefix(bits)
		return Stored{IP: p}, nil
	case Pseudonymized:
		if !t.HasKey() {
			return Stored{}, errors.New("clé de pseudonymisation absente ou trop courte")
		}
		m := hmac.New(sha256.New, t.key)
		m.Write([]byte(a.String()))
		k := hex.EncodeToString(m.Sum(nil)[:16])
		return Stored{IPKey: &k}, nil
	}
	return Stored{}, fmt.Errorf("mode IP inconnu %q", mode)
}

// Filter donne la colonne et la valeur à comparer pour retrouver une IP saisie
// par un utilisateur, selon le mode courant. Une clé déjà pseudonymisée
// (32 hex) est acceptée telle quelle.
func (t *Transformer) Filter(mode Mode, raw string) (col string, val any, err error) {
	raw = strings.TrimSpace(raw)
	if isKey(raw) {
		return "ip_key", strings.ToLower(raw), nil
	}
	s, err := t.Apply(mode, raw)
	if err != nil {
		return "", nil, err
	}
	if s.IPKey != nil {
		return "ip_key", *s.IPKey, nil
	}
	if s.IP == nil {
		return "", nil, ErrBadIP
	}
	return "ip", s.IP, nil
}

func isKey(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
