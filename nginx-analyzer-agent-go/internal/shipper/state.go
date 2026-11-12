package shipper

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"nginx-analyzer-go/internal/wire"
)

// committer est la partie de logsink.Sink utilisée ici (interface pour les tests).
type committer interface {
	Commit(evs []wire.Event, meta string) error
}

type offRec struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
	Format string `json:"format"`
}

type stateFile struct {
	Version int               `json:"version"`
	Files   map[string]offRec `json:"files"`
}

// metaRec est la position de fin d'une unité, conservée avec elle dans le tampon.
type metaRec struct {
	F  string `json:"f"`
	I  uint64 `json:"i"`
	O  int64  `json:"o"`
	Fm string `json:"fm"`
}

type item struct {
	file string
	rec  offRec
	evs  []wire.Event
}

// Store implémente tail.OffsetStore avec la garantie « position avancée seulement
// si les événements sont durables » :
//
//	OnEntry (Add) accumule -> le tailer appelle SetOffset juste après -> Commit
//	(fsync, avec la position en meta) -> seulement ensuite fichier d'offsets.
//
// Un crash entre Commit et l'écriture du fichier d'offsets est rattrapé au
// démarrage par ApplyPendingMeta (la meta de l'unité fait foi) : ni perte ni
// doublon. Un Commit en échec laisse l'unité en file mémoire (bornée) et la
// position n'avance pas sur disque ; un redémarrage relit alors depuis la
// dernière position durable (rien n'avait été écrit : pas de doublon).
type Store struct {
	path string
	log  *slog.Logger
	sink committer

	accept func(file string) bool // reprise : ne retient que les fichiers de CE suiveur (nil = tous)

	mu      sync.Mutex
	offs    map[string]offRec
	pending []wire.Event
	queue   []item
	queued  int
	maxQ    int

	Committed  atomic.Int64 // événements rendus durables
	CommitErrs atomic.Int64
	QueueDrop  atomic.Int64 // événements perdus : file de reprise pleine
	PersistErr atomic.Int64
}

func NewStore(path string, sink committer, maxQueueEvents int, log *slog.Logger) *Store {
	if maxQueueEvents <= 0 {
		maxQueueEvents = 200000
	}
	if log == nil {
		log = slog.Default()
	}
	return &Store{path: path, sink: sink, maxQ: maxQueueEvents, log: log, offs: map[string]offRec{}}
}

// SetFilter restreint ApplyPendingMeta aux fichiers suivis par ce Store (plusieurs suiveurs partagent un tampon).
func (s *Store) SetFilter(f func(file string) bool) { s.accept = f }

// Load lit le fichier d'offsets. Absent = vide. Corrompu = erreur (l'appelant décide).
func (s *Store) Load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var sf stateFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return fmt.Errorf("fichier d'offsets illisible : %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sf.Files != nil {
		s.offs = sf.Files
	}
	return nil
}

// ApplyPendingMeta applique les positions des unités encore en attente (de la
// plus ancienne à la plus récente : la dernière de chaque fichier l'emporte).
func (s *Store) ApplyPendingMeta(metas []string) int {
	n := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range metas {
		var r metaRec
		if json.Unmarshal([]byte(m), &r) != nil || r.F == "" || r.O < 0 {
			continue // meta d'un autre producteur (entrée locale) ou illisible
		}
		if s.accept != nil && !s.accept(r.F) {
			continue // fichier suivi par un autre suiveur
		}
		s.offs[r.F] = offRec{Inode: r.I, Offset: r.O, Format: r.Fm}
		n++
	}
	if n > 0 {
		s.persistLocked()
	}
	return n
}

// Add est appelé par OnEntry (goroutine du tailer).
func (s *Store) Add(ev wire.Event) {
	s.mu.Lock()
	s.pending = append(s.pending, ev)
	s.mu.Unlock()
}

func (s *Store) GetOffset(file string) (uint64, int64, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.offs[file]
	if !ok {
		return 0, 0, "", false
	}
	return r.Inode, r.Offset, r.Format, true
}

// SetOffset est appelé par le tailer après ses OnEntry : les événements
// accumulés appartiennent à ce fichier (le tailer lit les fichiers l'un après l'autre).
func (s *Store) SetOffset(file string, inode uint64, offset int64, format string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := item{file: file, rec: offRec{Inode: inode, Offset: offset, Format: format}, evs: s.pending}
	s.pending = nil
	s.queue = append(s.queue, it)
	s.queued += len(it.evs)
	s.boundQueueLocked()
	s.drainLocked()
}

// Retry retente les unités en attente (appelé périodiquement et à l'arrêt).
func (s *Store) Retry() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drainLocked()
}

// QueueLen renvoie le nombre d'événements en file de reprise.
func (s *Store) QueueLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queued
}

func (s *Store) drainLocked() {
	for len(s.queue) > 0 {
		it := s.queue[0]
		if len(it.evs) > 0 {
			meta, _ := json.Marshal(metaRec{F: it.file, I: it.rec.Inode, O: it.rec.Offset, Fm: it.rec.Format})
			if err := s.sink.Commit(it.evs, string(meta)); err != nil {
				if s.CommitErrs.Add(1) == 1 {
					s.log.Error("shipper : écriture du tampon impossible, nouvel essai", "err", err.Error())
				}
				return
			}
			s.Committed.Add(int64(len(it.evs)))
		}
		s.queued -= len(it.evs)
		s.queue[0] = item{}
		s.queue = s.queue[1:]
		s.offs[it.file] = it.rec
		s.persistLocked()
	}
	s.queue = nil
}

// boundQueueLocked abandonne les plus anciens événements au-delà du plafond
// (mémoire bornée si le disque est durablement en échec). Les positions des
// unités abandonnées sont conservées : la suivante les dépasse.
func (s *Store) boundQueueLocked() {
	for s.queued > s.maxQ && len(s.queue) > 1 {
		n := len(s.queue[0].evs)
		if n == 0 {
			break
		}
		s.QueueDrop.Add(int64(n))
		s.queued -= n
		s.queue[0].evs = nil
	}
}

func (s *Store) persistLocked() {
	b, err := json.Marshal(stateFile{Version: 1, Files: s.offs})
	if err == nil {
		err = writeAtomic(s.path, b)
	}
	if err != nil {
		if s.PersistErr.Add(1) == 1 {
			s.log.Error("shipper : écriture du fichier d'offsets impossible (la reprise s'appuiera sur le tampon)", "err", err.Error())
		}
	}
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".offsets-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
