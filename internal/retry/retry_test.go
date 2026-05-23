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
