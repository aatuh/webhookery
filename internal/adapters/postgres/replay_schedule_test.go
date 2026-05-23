package postgres

import (
	"testing"
	"time"
)

func TestReplayScheduleDelaySpacesItemsByRateLimit(t *testing.T) {
	if got := replayScheduleDelay(0, 60); got != 0 {
		t.Fatalf("first replay item should be immediately eligible, got %s", got)
	}
	if got := replayScheduleDelay(1, 60); got != time.Second {
		t.Fatalf("second item at 60/min should be delayed 1s, got %s", got)
	}
	if got := replayScheduleDelay(2, 30); got != 4*time.Second {
		t.Fatalf("third item at 30/min should be delayed 4s, got %s", got)
	}
}

func TestReplayScheduleDelayIgnoresInvalidRateLimit(t *testing.T) {
	if got := replayScheduleDelay(10, 0); got != 0 {
		t.Fatalf("zero rate limit should not delay replay, got %s", got)
	}
	if got := replayScheduleDelay(10, -1); got != 0 {
		t.Fatalf("negative rate limit should not delay replay, got %s", got)
	}
	if got := replayScheduleDelay(-1, 60); got != 0 {
		t.Fatalf("negative item index should not delay replay, got %s", got)
	}
}
