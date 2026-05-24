package domain

import "testing"

func TestMetricDimensionsHashIsDeterministic(t *testing.T) {
	left := MetricDimensionsHash(map[string]string{"state": "scheduled", "queue": "deliveries"})
	right := MetricDimensionsHash(map[string]string{"queue": "deliveries", "state": "scheduled"})
	if left == "" || left != right {
		t.Fatalf("dimension hash should be stable, got %q and %q", left, right)
	}
	if left == MetricDimensionsHash(map[string]string{"queue": "deliveries", "state": "failed"}) {
		t.Fatal("different dimensions should produce a different hash")
	}
}
