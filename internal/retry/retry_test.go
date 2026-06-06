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

func TestFullJitterHandlesNilRNGAndZeroCapPolicies(t *testing.T) {
	policy := DefaultPolicy()
	delay := policy.NextDelay(-1, nil)
	if delay < 0 || delay > policy.InitialDelay {
		t.Fatalf("nil RNG delay %s outside first-attempt cap %s", delay, policy.InitialDelay)
	}
	if got := (Policy{}).NextDelay(1, rand.New(rand.NewSource(1))); got != 0 {
		t.Fatalf("zero-value policy delay=%s want 0", got)
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

func TestDeterministicDelayNormalizesEmptySeedAndNegativeAttempt(t *testing.T) {
	policy := Policy{MaxAttempts: 3, InitialDelay: time.Second, MaxDelay: 4 * time.Second}
	first := policy.NextDeterministicDelay(-10, "")
	second := policy.NextDeterministicDelay(0, Seed("empty"))
	if first != second {
		t.Fatalf("negative attempt and empty seed should normalize, got %s and %s", first, second)
	}
	if first < 0 || first > policy.InitialDelay {
		t.Fatalf("normalized delay %s outside first cap %s", first, policy.InitialDelay)
	}
	if got := (Policy{}).NextDeterministicDelay(1, "seed"); got != 0 {
		t.Fatalf("zero-value deterministic delay=%s want 0", got)
	}
}

func TestDelayCapHonorsMaxDelayAndNegativeAttempts(t *testing.T) {
	policy := Policy{InitialDelay: time.Second, MaxDelay: 3 * time.Second}
	if got := policy.delayCap(-1); got != time.Second {
		t.Fatalf("negative attempt cap=%s want 1s", got)
	}
	if got := policy.delayCap(10); got != 3*time.Second {
		t.Fatalf("large attempt cap=%s want max delay", got)
	}
}

func TestSeedSeparatesParts(t *testing.T) {
	if Seed("a", "bc") == Seed("ab", "c") {
		t.Fatal("seed generation must distinguish part boundaries")
	}
}

func TestClassifyHTTPStatus(t *testing.T) {
	if result := DefaultPolicy().ClassifyStatus(204); result.Retryable || result.Reason != "success" {
		t.Fatalf("204 should be successful, got %+v", result)
	}
	if !DefaultPolicy().ClassifyStatus(500).Retryable {
		t.Fatal("500 should be retryable")
	}
	if !DefaultPolicy().ClassifyStatus(409).Retryable {
		t.Fatal("409 should be retryable")
	}
	if DefaultPolicy().ClassifyStatus(404).Retryable {
		t.Fatal("404 should be permanent by default")
	}
	if !DefaultPolicy().ClassifyStatus(429).Retryable {
		t.Fatal("429 should be retryable")
	}
}
