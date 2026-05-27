package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestEventTimelineQueryIsVersionedAndIncludesReplayReasons(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	querySource := string(body)
	for _, want := range []string{"webhookery.event_timeline.v1", "reason_code=", "FROM replay_jobs"} {
		if !strings.Contains(querySource, want) {
			t.Fatalf("event timeline query missing %q", want)
		}
	}
}
