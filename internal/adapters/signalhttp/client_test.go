package signalhttp

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"webhookery/internal/ssrf"
	"webhookery/pkg/verifier"
)

func TestBuildRequestSignsExactSignalBytes(t *testing.T) {
	client := Client{
		SSRF: ssrf.Validator{Resolver: ssrf.StaticResolver{
			"signals.example": {netip.MustParseAddr("93.184.216.34")},
		}},
		Now: func() time.Time { return time.Unix(1710000000, 0).UTC() },
	}
	body := []byte(`{"type":"alert.opened","value":"snowman"}`)
	req, err := client.BuildRequest(context.Background(), "https://signals.example/hook", body, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	expected := "t=1710000000,v1=" + verifier.SignHMACSHA256Hex([]byte("0123456789abcdef"), []byte("1710000000."+string(body)))
	if got := req.Header.Get("Webhookery-Signal-Signature"); got != expected {
		t.Fatalf("unexpected signature: got %q want %q", got, expected)
	}
	if got := req.Header.Get("Webhookery-Signal-Timestamp"); got != "1710000000" {
		t.Fatalf("unexpected timestamp: %q", got)
	}
}

func TestBuildRequestBlocksSSRFUnsafeURLs(t *testing.T) {
	client := Client{}
	if _, err := client.BuildRequest(context.Background(), "http://169.254.169.254/latest", []byte("{}"), []byte("secret")); err == nil {
		t.Fatal("expected unsafe signal URL to be blocked")
	}
}

func TestHTTPClientUsesPinnedEgressTransport(t *testing.T) {
	client := HTTPClient(2*time.Second, ssrf.StaticResolver{
		"signals.example": {netip.MustParseAddr("10.0.0.10")},
	})
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected pinned HTTP transport, got %T", client.Transport)
	}
	_, err := transport.DialContext(context.Background(), "tcp", "signals.example:443")
	var policyErr ssrf.PolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("expected dial-time SSRF policy error, got %v", err)
	}
}

func TestSafeDoErrorDoesNotLeakCustomerURLTokens(t *testing.T) {
	failureClass, err := safeDoError(errors.New(`Post "https://signals.example/hook?token=secret-token": dial tcp 203.0.113.10:443: connect: refused`))
	if failureClass != "network_error" {
		t.Fatalf("expected network_error, got %q", failureClass)
	}
	if err == nil || strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "signals.example") {
		t.Fatalf("network error leaked customer URL detail: %v", err)
	}
}
