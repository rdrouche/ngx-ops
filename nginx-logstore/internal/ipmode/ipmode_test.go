package ipmode

import (
	"net/netip"
	"strings"
	"testing"
)

const key = "0123456789abcdef0123456789abcdef"

func TestApplyModes(t *testing.T) {
	tr := New(key)

	s, err := tr.Apply(Clear, "203.0.113.7")
	if err != nil || s.IP != netip.MustParseAddr("203.0.113.7") || s.IPKey != nil {
		t.Fatalf("clear: %+v %v", s, err)
	}

	s, _ = tr.Apply(Truncated, "203.0.113.7")
	if s.IP != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("truncated v4: %+v", s)
	}
	s, _ = tr.Apply(Truncated, "2001:db8:1:2:3:4:5:6")
	if s.IP != netip.MustParsePrefix("2001:db8:1::/48") {
		t.Fatalf("truncated v6: %+v", s)
	}

	s, _ = tr.Apply(Pseudonymized, "203.0.113.7")
	if s.IP != nil || s.IPKey == nil || len(*s.IPKey) != 32 {
		t.Fatalf("pseudonymized: %+v", s)
	}
	// stable, et indépendant de la forme d'écriture (IPv4 mappée)
	s2, _ := tr.Apply(Pseudonymized, "::ffff:203.0.113.7")
	if *s.IPKey != *s2.IPKey {
		t.Fatal("la clé doit être stable pour une même IP")
	}
	other, _ := New(strings.Repeat("z", 32)).Apply(Pseudonymized, "203.0.113.7")
	if *other.IPKey == *s.IPKey {
		t.Fatal("la clé dépend du secret")
	}
}

func TestApplyErrors(t *testing.T) {
	tr := New(key)
	if _, err := tr.Apply(Clear, "pas une ip"); err != ErrBadIP {
		t.Fatalf("attendu ErrBadIP, obtenu %v", err)
	}
	if _, err := New("").Apply(Pseudonymized, "1.2.3.4"); err == nil {
		t.Fatal("sans clé, la pseudonymisation doit échouer")
	}
	if _, err := New("court").Apply(Pseudonymized, "1.2.3.4"); err == nil {
		t.Fatal("clé trop courte refusée")
	}
	if s, err := tr.Apply(Clear, ""); err != nil || s.IP != nil || s.IPKey != nil {
		t.Fatal("IP vide = valeurs nulles")
	}
	if _, err := Parse("nimporte"); err == nil {
		t.Fatal("mode inconnu refusé")
	}
}

func TestFilter(t *testing.T) {
	tr := New(key)
	col, val, err := tr.Filter(Clear, "203.0.113.7")
	if err != nil || col != "ip" || val != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("clear: %s %v %v", col, val, err)
	}
	col, val, _ = tr.Filter(Truncated, "203.0.113.200")
	if col != "ip" || val != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("truncated: %s %v", col, val)
	}
	col, val, _ = tr.Filter(Pseudonymized, "203.0.113.7")
	k, _ := tr.Apply(Pseudonymized, "203.0.113.7")
	if col != "ip_key" || val != *k.IPKey {
		t.Fatalf("pseudonymized: %s %v", col, val)
	}
	// une clé déjà pseudonymisée passe telle quelle, quel que soit le mode
	col, val, _ = tr.Filter(Clear, strings.ToUpper(*k.IPKey))
	if col != "ip_key" || val != *k.IPKey {
		t.Fatalf("clé directe: %s %v", col, val)
	}
}
