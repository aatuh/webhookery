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

func TestCanonicalHeadersLowercasesNamesAndPreservesDuplicateOrder(t *testing.T) {
	headers := CanonicalHeaders([]HeaderPair{
		{Name: "Stripe-Signature", Value: "v1=first"},
		{Name: "stripe-signature", Value: "v1=second"},
		{Name: "X-Webhookery-Trace", Value: "trace-1"},
	})

	if got := headers["stripe-signature"]; len(got) != 2 || got[0] != "v1=first" || got[1] != "v1=second" {
		t.Fatalf("signature headers were not canonicalized in order: %#v", got)
	}
	if got := headers["x-webhookery-trace"]; len(got) != 1 || got[0] != "trace-1" {
		t.Fatalf("trace header was not canonicalized: %#v", got)
	}
	if _, ok := headers["Stripe-Signature"]; ok {
		t.Fatalf("mixed-case key should not remain in canonical map: %#v", headers)
	}
}
