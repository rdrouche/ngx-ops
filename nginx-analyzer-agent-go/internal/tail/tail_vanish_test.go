package tail

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Regression : un fichier qui disparait entre le listage et le stat (rotation par
// renommage) ne doit pas bloquer le tailer (auto-verrouillage de t.mu).
func TestReadOfVanishedFileDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	tl := New(Options{Dir: dir, Store: NewMemoryOffsetStore()})
	gone := filepath.Join(dir, "gone.access.log")
	tl.files[gone] = &fileState{}

	done := make(chan struct{})
	go func() {
		tl.mu.Lock() // comme Poll()
		tl.read(gone)
		tl.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("read() est bloque : t.mu repris alors que Poll() le tient")
	}
	if _, ok := tl.files[gone]; ok {
		t.Fatal("le fichier disparu est toujours suivi")
	}
	// et le tailer reste utilisable ensuite
	if err := os.WriteFile(filepath.Join(dir, "a.access.log"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() { tl.Poll(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("Poll() bloque apres la disparition du fichier")
	}
}
