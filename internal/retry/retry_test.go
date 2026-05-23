package retry

import (
	"math/rand"
	"testing"
	"time"
)

func TestFullJitterDelayWithinCap(t *testing.T) {
	policy := DefaultPolicy()
	delay := policy.NextDelay(3, rand.New(rand.NewSource(1)))

	capDelay := minDuration(policy.MaxDelay, policy.InitialDelay*time.Duration(1<<3))
	if delay < 0 || delay > capDelay {
		t.Fatalf("delay %s outside cap %s", delay, capDelay)
	}
}

func TestDeterministicDelayIsStableForSeedAndAttempt(t *testing.T) {
	policy := DefaultPolicy()
	seed := Seed("ten_1", "del_1", "evt_1", "end_1")
	first := policy.NextDeterministicDelay(3, seed)
	second := policy.NextDeterministicDelay(3, seed)

	if first != second {
		t.Fatalf("expected deterministic delay, got %s and %s", first, second)
	}
	capDelay := minDuration(policy.MaxDelay, policy.InitialDelay*time.Duration(1<<3))
	if first < 0 || first > capDelay {
		t.Fatalf("delay %s outside cap %s", first, capDelay)
	}
}

func TestSeedSeparatesParts(t *testing.T) {
	if Seed("a", "bc") == Seed("ab", "c") {
		t.Fatal("seed generation must distinguish part boundaries")
	}
}

func TestClassifyHTTPStatus(t *testing.T) {
	if !DefaultPolicy().ClassifyStatus(500).Retryable {
		t.Fatal("500 should be retryable")
	}
	if DefaultPolicy().ClassifyStatus(404).Retryable {
		t.Fatal("404 should be permanent by default")
	}
	if !DefaultPolicy().ClassifyStatus(429).Retryable {
		t.Fatal("429 should be retryable")
	}
}
