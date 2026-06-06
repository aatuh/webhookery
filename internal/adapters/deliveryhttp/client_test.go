package deliveryhttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
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

func TestSafeHTTPClientOverridesPermissiveRedirectPolicy(t *testing.T) {
	base := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return nil
		},
	}
	client, err := safeHTTPClient(base, 2*time.Second, ssrf.StaticResolver{})
	if err != nil {
		t.Fatal(err)
	}
	err = client.CheckRedirect(&http.Request{}, []*http.Request{{}})
	if err == nil {
		t.Fatal("copied HTTP clients must not preserve permissive redirect policies")
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

func TestBuildRequestPolicyBlockDoesNotLeakURLToken(t *testing.T) {
	client := Client{
		Secret: []byte("secret"),
		SSRF: ssrf.Validator{Resolver: ssrf.StaticResolver{
			"internal.example.com": {netip.MustParseAddr("10.0.0.10")},
		}},
	}
	_, err := client.BuildRequest(context.Background(), "https://internal.example.com/hook?token=secret-token", []byte("{}"))
	if err == nil {
		t.Fatal("expected blocked endpoint URL")
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "internal.example.com") {
		t.Fatalf("blocked endpoint error leaked URL detail: %v", err)
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

func TestHTTPClientAddsMTLSCertificateToPinnedTransport(t *testing.T) {
	certPEM, keyPEM := testClientCertificatePEM(t)
	baseTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	client := Client{
		HTTP:              &http.Client{Transport: baseTransport},
		Secret:            []byte("secret"),
		MTLSClientCertPEM: certPEM,
		MTLSClientKeyPEM:  keyPEM,
		SSRF: ssrf.Validator{Resolver: ssrf.StaticResolver{
			"example.com": {netip.MustParseAddr("93.184.216.34")},
		}},
	}

	httpClient, err := client.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected HTTP transport, got %T", httpClient.Transport)
	}
	if transport.TLSClientConfig == nil || len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("expected mTLS client certificate in transport, got %+v", transport.TLSClientConfig)
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected existing TLS minimum version to be preserved, got %d", transport.TLSClientConfig.MinVersion)
	}
	if baseTransport.TLSClientConfig == transport.TLSClientConfig {
		t.Fatal("mTLS setup should clone the base TLS config before mutation")
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

func TestClassifyDeliveryHTTPStatuses(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{status: http.StatusOK, want: "success"},
		{status: http.StatusAccepted, want: "success"},
		{status: http.StatusFound, want: "redirect_blocked"},
		{status: http.StatusRequestTimeout, want: "temporary_http"},
		{status: http.StatusTooManyRequests, want: "temporary_http"},
		{status: http.StatusInternalServerError, want: "temporary_http"},
		{status: http.StatusBadRequest, want: "permanent_http"},
		{status: http.StatusUnauthorized, want: "permanent_http"},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			if got := classify(tt.status); got != tt.want {
				t.Fatalf("classify(%d)=%q want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestClientRejectsUnsafeCustomHTTPTransport(t *testing.T) {
	client := Client{
		HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsafe custom transport must not be used")
			return nil, nil
		})},
		Secret: []byte("secret"),
		SSRF: ssrf.Validator{Resolver: ssrf.StaticResolver{
			"example.com": {netip.MustParseAddr("93.184.216.34")},
		}},
	}
	result, err := client.Deliver(context.Background(), "https://example.com/webhook", []byte("{}"))
	if err == nil {
		t.Fatal("expected unsafe custom transport rejection")
	}
	if result.FailureClass != "client_configuration_error" {
		t.Fatalf("expected client_configuration_error, got %+v", result)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testClientCertificatePEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Webhookery Delivery Client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
