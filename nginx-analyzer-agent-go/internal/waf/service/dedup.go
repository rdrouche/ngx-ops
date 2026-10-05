package service

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"nginx-analyzer-go/internal/waf/logsource"
)

// Dedoublonnage combined <-> waf_json (v12.70.2).
//
// Quand un meme vhost ecrit a la fois un journal combined (access.log) et un journal waf_json
// (*.wafemu.log), chaque requete arrive deux fois. Le format waf_json est plus riche : il gagne.
//   - une ligne combined est retenue ~dedupHold avant d'etre analysee, le temps de voir arriver sa
//     jumelle waf_json (les deux fichiers sont suivis par des tailers independants, l'ordre est libre) ;
//   - une ligne waf_json supprime sa jumelle combined en attente ; si la combined n'est pas encore
//     arrivee, la cle est memorisee (recentJSON) et la combined sera ecartee a son arrivee ;
//   - la cle ignore le vhost (nom de fichier / server_name / $host peuvent differer) :
//     ip | seconde | methode | URI | statut. Les repetitions identiques sont comptees (pas de perte).
//
// Sans fichier waf_json suivi, ce mecanisme est inactif : aucune latence ajoutee.
const (
	dedupHold   = 3 * time.Second
	dedupMemory = 30 * time.Second
)

type pendingEntry struct {
	e  *logsource.Entry
	at time.Time
}

type dedup struct {
	mu         sync.Mutex
	pending    map[string][]pendingEntry
	recentJSON map[string][]time.Time
	jsonActive atomic.Bool
	skipped    atomic.Int64
}

func newDedup() *dedup {
	return &dedup{pending: map[string][]pendingEntry{}, recentJSON: map[string][]time.Time{}}
}

func dedupKey(e *logsource.Entry) string {
	return e.IP + "|" + strconv.FormatInt(e.TS/1000, 10) + "|" + e.Method + "|" + e.URI + "|" + strconv.Itoa(e.Status)
}

// admit renvoie true si l'entree doit etre traitee tout de suite.
func (d *dedup) admit(e *logsource.Entry, now time.Time) bool {
	if !d.jsonActive.Load() && !e.WafJSON {
		return true
	}
	k := dedupKey(e)
	d.mu.Lock()
	defer d.mu.Unlock()
	if e.WafJSON {
		if q := d.pending[k]; len(q) > 0 { // jumelle combined deja en attente : on la supprime
			if len(q) == 1 {
				delete(d.pending, k)
			} else {
				d.pending[k] = q[1:]
			}
			d.skipped.Add(1)
		} else {
			d.recentJSON[k] = append(d.recentJSON[k], now)
		}
		return true
	}
	if q := d.recentJSON[k]; len(q) > 0 { // jumelle waf_json deja traitee
		if len(q) == 1 {
			delete(d.recentJSON, k)
		} else {
			d.recentJSON[k] = q[1:]
		}
		d.skipped.Add(1)
		return false
	}
	d.pending[k] = append(d.pending[k], pendingEntry{e: e, at: now})
	return false
}

// flush renvoie les entrees combined en attente depuis plus de dedupHold (aucune jumelle n'est venue)
// et oublie les cles waf_json trop anciennes.
func (d *dedup) flush(now time.Time) []*logsource.Entry {
	var out []*logsource.Entry
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, q := range d.pending {
		keep := q[:0]
		for _, p := range q {
			if now.Sub(p.at) >= dedupHold {
				out = append(out, p.e)
			} else {
				keep = append(keep, p)
			}
		}
		if len(keep) == 0 {
			delete(d.pending, k)
		} else {
			d.pending[k] = keep
		}
	}
	for k, q := range d.recentJSON {
		keep := q[:0]
		for _, t := range q {
			if now.Sub(t) < dedupMemory {
				keep = append(keep, t)
			}
		}
		if len(keep) == 0 {
			delete(d.recentJSON, k)
		} else {
			d.recentJSON[k] = keep
		}
	}
	return out
}

// drain vide tout (arret).
func (d *dedup) drain() []*logsource.Entry {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*logsource.Entry
	for _, q := range d.pending {
		for _, p := range q {
			out = append(out, p.e)
		}
	}
	d.pending = map[string][]pendingEntry{}
	return out
}
