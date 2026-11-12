package auth

import "testing"

func entry(id int64, role, inst, tok string) Entry {
	var e Entry
	e.TokenID, e.Role, e.InstanceID = id, role, inst
	copy(e.Hash[:], Hash(tok))
	return e
}

func TestVerifyAndRoles(t *testing.T) {
	w, _ := Generate()
	r, _ := Generate()
	a, _ := Generate()
	if w == r || len(w) < 40 || w[:4] != Prefix {
		t.Fatalf("jetons mal formés: %s", w)
	}
	var v Verifier
	v.Set([]Entry{entry(1, RoleWrite, "web1", w), entry(2, RoleRead, "", r), entry(3, RoleAdmin, "", a)})

	id, ok := v.Verify(w)
	if !ok || id.TokenID != 1 || !id.Allows(RoleWrite) || id.Allows(RoleRead) || id.Allows(RoleAdmin) {
		t.Fatalf("write: %+v %v", id, ok)
	}
	id, _ = v.Verify(r)
	if !id.Allows(RoleRead) || id.Allows(RoleAdmin) || id.Allows(RoleWrite) {
		t.Fatalf("read: %+v", id)
	}
	id, _ = v.Verify(a)
	if !id.Allows(RoleAdmin) || !id.Allows(RoleRead) || id.Allows(RoleWrite) {
		t.Fatalf("admin: %+v", id)
	}
	for _, bad := range []string{"", "lgs_inconnu", w + "x", w[:len(w)-1]} {
		if _, ok := v.Verify(bad); ok {
			t.Fatalf("jeton %q accepté", bad)
		}
	}
	if got := v.FlushUsed(); len(got) != 3 {
		t.Fatalf("usage: %v", got)
	}
	if got := v.FlushUsed(); got != nil {
		t.Fatalf("usage déjà vidé: %v", got)
	}
}

func TestRevokedTokenGone(t *testing.T) {
	tok, _ := Generate()
	var v Verifier
	v.Set([]Entry{entry(1, RoleRead, "", tok)})
	if _, ok := v.Verify(tok); !ok {
		t.Fatal("attendu valide")
	}
	v.Set(nil)
	if _, ok := v.Verify(tok); ok {
		t.Fatal("jeton retiré encore accepté")
	}
}

func TestBearer(t *testing.T) {
	if Bearer("Bearer abc") != "abc" || Bearer("bearer abc") != "" || Bearer("Basic abc") != "" || Bearer("Bearer ") != "" {
		t.Fatal("Bearer")
	}
}

func TestWriteNeedsInstance(t *testing.T) {
	if (Identity{Role: RoleWrite}).Allows(RoleWrite) {
		t.Fatal("un jeton write sans instance ne doit rien pouvoir écrire")
	}
}
