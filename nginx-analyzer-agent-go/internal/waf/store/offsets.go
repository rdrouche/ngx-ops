package store

import "sync"

// Offsets implemente tail.OffsetStore en memoire ; les modifications sont recuperees par lots
// (TakeDirty) pour etre ecrites en base : le tailer n'attend jamais le disque.
type Offsets struct {
	mu        sync.Mutex
	m         map[string]OffsetRow
	dirty     map[string]OffsetRow
	fromStart bool
}

// NewOffsets : initial = offsets charges de la base ; fromStart : un fichier jamais vu est lu
// depuis son debut (tests, rattrapage) au lieu de sa fin.
func NewOffsets(initial map[string]OffsetRow, fromStart bool) *Offsets {
	if initial == nil {
		initial = map[string]OffsetRow{}
	}
	return &Offsets{m: initial, dirty: map[string]OffsetRow{}, fromStart: fromStart}
}

func (o *Offsets) GetOffset(file string) (uint64, int64, string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if r, ok := o.m[file]; ok {
		return r.Inode, r.Offset, r.Format, true
	}
	if o.fromStart {
		return 0, 0, "", true // inode different de tout inode reel : lecture depuis 0
	}
	return 0, 0, "", false
}

func (o *Offsets) SetOffset(file string, inode uint64, offset int64, format string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r := OffsetRow{Inode: inode, Offset: offset, Format: format}
	if old, ok := o.m[file]; ok && old == r {
		return
	}
	o.m[file] = r
	o.dirty[file] = r
}

// TakeDirty renvoie et vide les offsets modifies depuis le dernier appel.
func (o *Offsets) TakeDirty() map[string]OffsetRow {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.dirty) == 0 {
		return nil
	}
	d := o.dirty
	o.dirty = map[string]OffsetRow{}
	return d
}
