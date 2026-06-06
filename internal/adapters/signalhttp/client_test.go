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

func TestSignalClassifyHTTPStatuses(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{status: http.StatusOK, want: "success"},
		{status: http.StatusNoContent, want: "success"},
		{status: http.StatusTemporaryRedirect, want: "redirect_blocked"},
		{status: http.StatusTooManyRequests, want: "temporary_http"},
		{status: http.StatusBadGateway, want: "temporary_http"},
		{status: http.StatusBadRequest, want: "permanent_http"},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			if got := classify(tt.status); got != tt.want {
				t.Fatalf("classify(%d)=%q want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestDeliverRejectsUnsafeCustomHTTPTransport(t *testing.T) {
	client := Client{
		HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsafe custom transport must not be used")
			return nil, nil
		})},
		SSRF: ssrf.Validator{Resolver: ssrf.StaticResolver{
			"signals.example": {netip.MustParseAddr("93.184.216.34")},
		}},
	}
	result, err := client.Deliver(context.Background(), "https://signals.example/hook", []byte("{}"), []byte("secret"))
	if err == nil {
		t.Fatal("expected unsafe custom transport rejection")
	}
	if result.FailureClass != "client_configuration_error" {
		t.Fatalf("expected client_configuration_error, got %+v", result)
	}
}

func TestDeliverBlocksUnsafeSignalURLWithoutLeakingSecret(t *testing.T) {
	client := Client{}
	result, err := client.Deliver(context.Background(), "http://169.254.169.254/latest?token=secret-token", []byte("{}"), []byte("signing-secret"))
	if err == nil {
		t.Fatal("expected unsafe signal URL rejection")
	}
	if result.FailureClass != "policy_blocked" {
		t.Fatalf("expected policy_blocked, got %+v", result)
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "signing-secret") {
		t.Fatalf("blocked signal error leaked secret material: %v", err)
	}
}

func TestDeliverNetworkErrorDoesNotLeakSignalURL(t *testing.T) {
	client := Client{
		HTTP: HTTPClient(time.Millisecond, ssrf.StaticResolver{
			"signals.example": {netip.MustParseAddr("93.184.216.34")},
		}),
		SSRF: ssrf.Validator{Resolver: ssrf.StaticResolver{
			"signals.example": {netip.MustParseAddr("93.184.216.34")},
		}},
	}
	result, err := client.Deliver(context.Background(), "https://signals.example/hook?token=secret-token", []byte("{}"), []byte("signing-secret"))
	if err == nil {
		t.Fatal("expected signal delivery network error")
	}
	if result.FailureClass != "network_error" {
		t.Fatalf("expected network_error, got %+v", result)
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "signals.example") || strings.Contains(err.Error(), "signing-secret") {
		t.Fatalf("signal delivery network error leaked sensitive detail: %v", err)
	}
}

func TestSignalHTTPClientDefaultsAndPinsBaseTransport(t *testing.T) {
	defaultClient, err := (Client{}).httpClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := defaultClient.Transport.(*http.Transport); !ok {
		t.Fatalf("expected default pinned transport, got %T", defaultClient.Transport)
	}
	if err := defaultClient.CheckRedirect(&http.Request{}, []*http.Request{{}}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("default signal client should block redirects, got %v", err)
	}

	base := &http.Client{}
	pinned, err := (Client{
		HTTP: base,
		SSRF: ssrf.Validator{Resolver: ssrf.StaticResolver{
			"signals.example": {netip.MustParseAddr("10.0.0.10")},
		}},
	}).httpClient()
	if err != nil {
		t.Fatal(err)
	}
	if pinned == base {
		t.Fatal("httpClient should copy caller-provided client")
	}
	transport, ok := pinned.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected pinned base transport, got %T", pinned.Transport)
	}
	_, err = transport.DialContext(context.Background(), "tcp", "signals.example:443")
	var policyErr ssrf.PolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("expected pinned transport policy error, got %v", err)
	}
	if err := pinned.CheckRedirect(&http.Request{}, []*http.Request{{}}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("base signal client should block redirects, got %v", err)
	}
}

func TestReadTruncatedSignalResponse(t *testing.T) {
	body, err := readTruncated(strings.NewReader(strings.Repeat("x", 20)), 8)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "xxxxxxxx" {
		t.Fatalf("unexpected truncated body %q", string(body))
	}
}

func TestSafeDoErrorPreservesPolicyErrors(t *testing.T) {
	failureClass, err := safeDoError(ssrf.PolicyError{Reasons: []string{"blocked_ip_range"}})
	if failureClass != "policy_blocked" {
		t.Fatalf("expected policy_blocked, got %q", failureClass)
	}
	var policyErr ssrf.PolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("expected policy error, got %v", err)
	}
}

func TestHTTPClientDisablesRedirects(t *testing.T) {
	client := HTTPClient(2 * time.Second)
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("expected redirects disabled, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
