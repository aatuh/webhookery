package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestPostgresStoreIsSplitByResourceFamily(t *testing.T) {
	if _, err := os.Stat("store_ingest.go"); err != nil {
		t.Fatal("expected inbound capture methods to live in store_ingest.go")
	}
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "func (s *Store) CaptureInbound") {
		t.Fatal("CaptureInbound should live in the ingest resource-family file")
	}
}
