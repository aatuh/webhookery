package deliveryhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"webhookery/internal/ssrf"
)

func TestBuildSignedRequestAddsHMACHeader(t *testing.T) {
	client := Client{
		Secret:            []byte("secret"),
		SigningKeyID:      "esec_1",
		SigningKeyVersion: 2,
		Now:               func() time.Time { return time.Unix(1_700_000_000, 0) },
		SSRF: ssrf.Validator{Resolver: ssrf.StaticResolver{
			"example.com": {netip.MustParseAddr("93.184.216.34")},
		}},
	}
	req, err := client.BuildRequest(context.Background(), "https://example.com/webhook", []byte(`{"id":"evt_123"}`))
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Webhook-Signature") == "" {
		t.Fatal("missing signature header")
	}
	if req.Header.Get("Webhook-Timestamp") != "1700000000" {
		t.Fatalf("unexpected timestamp: %s", req.Header.Get("Webhook-Timestamp"))
	}
	if req.Header.Get("Webhook-Signature-Key-Id") != "esec_1" || req.Header.Get("Webhook-Signature-Key-Version") != "2" {
		t.Fatalf("missing signing key metadata headers: %+v", req.Header)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/private", http.StatusFound)
	}))
	defer server.Close()

	client := HTTPClient(2 * time.Second)
	err := client.CheckRedirect(nil, []*http.Request{{}})
	if err == nil {
		t.Fatal("redirects must be disabled by default")
	}
}

func TestHTTPClientUsesPinnedEgressTransport(t *testing.T) {
	client := HTTPClient(2*time.Second, ssrf.StaticResolver{
		"customer.example.com": {netip.MustParseAddr("10.0.0.10")},
	})
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected pinned HTTP transport, got %T", client.Transport)
	}
	_, err := transport.DialContext(context.Background(), "tcp", "customer.example.com:443")
	var policyErr ssrf.PolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("expected dial-time SSRF policy error, got %v", err)
	}
}

func TestSafeDoErrorDoesNotLeakCustomerURLTokens(t *testing.T) {
	failureClass, err := safeDoError(errors.New(`Post "https://customer.example/hook?token=secret-token": dial tcp 203.0.113.10:443: connect: refused`))
	if failureClass != "network_error" {
		t.Fatalf("expected network_error, got %q", failureClass)
	}
	if err == nil || strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "customer.example") {
		t.Fatalf("network error leaked customer URL detail: %v", err)
	}
}

func TestSafeDoErrorHandlesTimeoutStormWithoutLeakingReceiver(t *testing.T) {
	timeoutErrors := []error{
		context.DeadlineExceeded,
		errors.New(`Post "https://receiver.example/hook?token=secret-token": context deadline exceeded`),
		errors.New(`Post "https://receiver.example/hook": net/http: request canceled while waiting for connection`),
	}
	for _, timeoutErr := range timeoutErrors {
		failureClass, err := safeDoError(timeoutErr)
		if failureClass != "network_error" {
			t.Fatalf("expected network_error, got %q", failureClass)
		}
		if err == nil || strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "receiver.example") {
			t.Fatalf("timeout storm error leaked receiver detail: %v", err)
		}
	}
}

func TestClientRejectsInvalidMTLSCertificatePair(t *testing.T) {
	client := Client{
		Secret:            []byte("secret"),
		MTLSClientCertPEM: []byte("not a certificate"),
		MTLSClientKeyPEM:  []byte("not a key"),
		SSRF: ssrf.Validator{Resolver: ssrf.StaticResolver{
			"example.com": {netip.MustParseAddr("93.184.216.34")},
		}},
	}
	result, err := client.Deliver(context.Background(), "https://example.com/webhook", []byte("{}"))
	if err == nil {
		t.Fatal("expected invalid mTLS certificate pair to fail closed")
	}
	if result.FailureClass != "client_certificate_error" {
		t.Fatalf("expected client_certificate_error, got %+v", result)
	}
}

func TestTruncateResponseBody(t *testing.T) {
	body, err := readTruncated(io.NopCloser(repeatingReader("x", 20)), 8)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "xxxxxxxx" {
		t.Fatalf("unexpected truncated body: %q", body)
	}
}
