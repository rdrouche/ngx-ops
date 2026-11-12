// Package auth gère les jetons d'API : génération, hachage, vérification à
// temps constant, rôles.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"sync/atomic"
)

// Rôles.
const (
	RoleWrite = "write" // ingestion (lié à une instance)
	RoleRead  = "read"  // consultation
	RoleAdmin = "admin" // réglages + jetons (inclut la lecture)
)

// ValidRole indique si r est un rôle connu.
func ValidRole(r string) bool { return r == RoleWrite || r == RoleRead || r == RoleAdmin }

// Prefix reconnaissable (détection de fuite par les scanners de secrets).
const Prefix = "lgs_"

// Generate produit un jeton aléatoire de 256 bits.
func Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Hash est l'empreinte stockée en base (SHA-256 : le jeton est déjà à haute entropie).
func Hash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Identity est ce que l'on sait d'un jeton valide.
type Identity struct {
	TokenID    int64
	Role       string
	InstanceID string // pour RoleWrite
}

// Scope renvoie l'instance à laquelle un jeton `read` est limité ("" = toutes les instances).
// Un jeton `read` lié à une instance ne voit que les données de cette instance (#89) ;
// admin n'est jamais limité.
func (i Identity) Scope() string {
	if i.Role == RoleRead {
		return i.InstanceID
	}
	return ""
}

// Allows indique si l'identité peut effectuer une opération exigeant need.
func (i Identity) Allows(need string) bool {
	switch need {
	case RoleWrite:
		return i.Role == RoleWrite && i.InstanceID != ""
	case RoleRead:
		return i.Role == RoleRead || i.Role == RoleAdmin
	case RoleAdmin:
		return i.Role == RoleAdmin
	}
	return false
}

// Entry est une ligne de la table des jetons chargée en mémoire.
type Entry struct {
	Identity
	Hash [32]byte
}

// Verifier compare un jeton présenté à tous les jetons actifs, à temps
// constant (aucune sortie anticipée, aucune comparaison dépendant du secret).
type Verifier struct {
	mu      sync.RWMutex
	entries []Entry
	used    sync.Map // TokenID -> struct{} (horodatage d'usage, vidé par FlushUsed)
	dirty   atomic.Bool
}

// Set remplace la liste des jetons actifs.
func (v *Verifier) Set(entries []Entry) {
	v.mu.Lock()
	v.entries = entries
	v.mu.Unlock()
}

// Verify renvoie l'identité du jeton, ou false.
func (v *Verifier) Verify(token string) (Identity, bool) {
	if token == "" {
		return Identity{}, false
	}
	sum := sha256.Sum256([]byte(token))
	v.mu.RLock()
	defer v.mu.RUnlock()
	var (
		found Identity
		ok    int
	)
	for i := range v.entries {
		e := &v.entries[i]
		m := subtle.ConstantTimeCompare(sum[:], e.Hash[:])
		if m == 1 {
			found = e.Identity
		}
		ok |= m
	}
	if ok == 1 {
		v.used.Store(found.TokenID, struct{}{})
		v.dirty.Store(true)
		return found, true
	}
	return Identity{}, false
}

// FlushUsed renvoie les jetons utilisés depuis le dernier appel.
func (v *Verifier) FlushUsed() []int64 {
	if !v.dirty.Swap(false) {
		return nil
	}
	var ids []int64
	v.used.Range(func(k, _ any) bool {
		ids = append(ids, k.(int64))
		v.used.Delete(k)
		return true
	})
	return ids
}

// Bearer extrait le jeton d'un en-tête Authorization.
func Bearer(header string) string {
	const p = "Bearer "
	if len(header) > len(p) && header[:len(p)] == p {
		return header[len(p):]
	}
	return ""
}
