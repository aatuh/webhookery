package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestCaptureInboundUsesAtomicDedupeInsert(t *testing.T) {
	body, err := os.ReadFile("store_ingest.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	start := strings.Index(source, "func (s *Store) CaptureInbound")
	if start == -1 {
		t.Fatal("CaptureInbound not found")
	}
	capture := source[start:]
	if !strings.Contains(capture, "ON CONFLICT (tenant_id, dedupe_key) DO NOTHING") {
		t.Fatal("CaptureInbound must insert events with ON CONFLICT on the dedupe key")
	}
	if strings.Contains(capture, "SELECT id FROM events WHERE tenant_id=$1 AND dedupe_key=$2") {
		t.Fatal("CaptureInbound must not select-then-insert events by dedupe key")
	}
}
