package shipper

import (
	"testing"

	"nginx-analyzer-go/internal/parse"
)

func parseOne(t *testing.T, l string) parse.AccessEntry {
	t.Helper()
	e, ok := parse.ParseLine(l, "combined", "site.example")
	if !ok {
		t.Fatalf("ligne non analysée : %s", l)
	}
	return e
}
