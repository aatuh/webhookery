package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRedactCredentialDoesNotExposeToken(t *testing.T) {
	got := RedactCredential("sk_test_1234567890")
	if got == "sk_test_1234567890" || !strings.Contains(got, "...") {
		t.Fatalf("credential was not redacted: %q", got)
	}
	if RedactCredential("") != "" {
		t.Fatal("empty credential should remain empty")
	}
	if RedactCredential("short") != "****" {
		t.Fatal("short credential should be fully redacted")
	}
}

func TestProviderErrorClassifiesAndRedactsProviderFailures(t *testing.T) {
	if got := (ProviderError{Class: ErrorRetryable}).Error(); got != ErrorRetryable {
		t.Fatalf("expected class fallback, got %q", got)
	}
	if got := (ProviderError{Class: ErrorForbidden, Message: "forbidden"}).Error(); got != "forbidden" {
		t.Fatalf("expected message error, got %q", got)
	}

	tests := []struct {
		status int
		body   []byte
		want   string
	}{
		{status: http.StatusTooManyRequests, body: []byte("slow down"), want: ErrorRateLimited},
		{status: http.StatusUnauthorized, body: []byte("nope"), want: ErrorForbidden},
		{status: http.StatusForbidden, body: []byte("nope"), want: ErrorForbidden},
		{status: http.StatusNotFound, body: []byte("missing"), want: ErrorNotFound},
		{status: http.StatusBadRequest, body: []byte("bad input"), want: ErrorInvalidInput},
		{status: http.StatusInternalServerError, body: []byte("server down"), want: ErrorRetryable},
	}
	for _, tt := range tests {
		err := ClassifyHTTPError(tt.status, tt.body)
		if err.Class != tt.want || err.StatusCode != tt.status {
			t.Fatalf("status %d classified as %+v, want %s", tt.status, err, tt.want)
		}
	}
	for _, secretBody := range [][]byte{
		[]byte("sk_test_secret leaked"),
		[]byte("ghp_secret leaked"),
		[]byte("github_pat_secret leaked"),
		[]byte("xoxb-secret leaked"),
		[]byte("shpat_secret leaked"),
	} {
		err := ClassifyHTTPError(http.StatusBadRequest, secretBody)
		if strings.Contains(err.Message, "secret") || err.Message != "provider request failed" {
			t.Fatalf("provider error leaked credential body: %+v", err)
		}
	}
}

func TestProviderBaseURLValidation(t *testing.T) {
	official, err := providerBaseURL(nil, "https://api.stripe.com", map[string]bool{"api.stripe.com": true})
	if err != nil || official != "https://api.stripe.com" {
		t.Fatalf("unexpected official base URL result %q err=%v", official, err)
	}
	testBase, err := providerBaseURL(map[string]string{"base_url": "http://127.0.0.1:8080/", "allow_test_base_url": "true"}, "https://api.stripe.com", map[string]bool{"api.stripe.com": true})
	if err != nil || testBase != "http://127.0.0.1:8080" {
		t.Fatalf("unexpected localhost test base URL %q err=%v", testBase, err)
	}

	rejected := []map[string]string{
		{"base_url": "http://api.stripe.com"},
		{"base_url": "https://evil.example.com"},
		{"base_url": "https://user:pass@api.stripe.com"},
		{"base_url": "https://evil.example.com", "allow_test_base_url": "true"},
	}
	for _, config := range rejected {
		if _, err := providerBaseURL(config, "https://api.stripe.com", map[string]bool{"api.stripe.com": true}); err == nil {
			t.Fatalf("expected base URL rejection for %+v", config)
		}
	}
	if err := requiredConfig(map[string]string{"owner": "o"}, "owner", "repo", "hook_id"); err == nil {
		t.Fatal("expected missing provider config rejection")
	}
}

func TestBuiltInAdaptersExposeCapabilitiesAndUnsupportedBehavior(t *testing.T) {
	registry := BuiltInRegistry(nil)
	stripe, ok := registry.Adapter(" STRIPE ")
	if !ok || stripe.Name() != ProviderStripe {
		t.Fatalf("missing stripe adapter: ok=%t adapter=%T", ok, stripe)
	}
	if caps := stripe.Capabilities(map[string]string{}); !caps.CanScanEvents || caps.Provider != ProviderStripe || len(caps.RequiredConfig) == 0 {
		t.Fatalf("unexpected stripe capabilities: %+v", caps)
	}
	github, ok := registry.Adapter("github")
	if !ok || github.Name() != ProviderGitHub {
		t.Fatalf("missing github adapter: ok=%t adapter=%T", ok, github)
	}
	if caps := github.Capabilities(map[string]string{}); !caps.CanRequestRedelivery || caps.Provider != ProviderGitHub {
		t.Fatalf("unexpected github capabilities: %+v", caps)
	}
	if _, ok := registry.Adapter("unknown"); ok {
		t.Fatal("unknown provider should not resolve")
	}

	unsupported := UnsupportedAdapter{Provider: ProviderSlack, Cap: SlackCapabilities()}
	if err := unsupported.ValidateConnection(context.Background(), Connection{}); err != nil || unsupported.Name() != ProviderSlack {
		t.Fatalf("unexpected unsupported adapter identity")
	}
	if caps := unsupported.Capabilities(nil); caps.Provider != ProviderSlack || len(caps.Limitations) == 0 {
		t.Fatalf("unexpected unsupported capabilities: %+v", caps)
	}
	if _, _, err := unsupported.Lookup(context.Background(), Connection{}, "evt_1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected unsupported lookup error, got %v", err)
	}
	if _, err := unsupported.RequestRedelivery(context.Background(), Connection{}, "evt_1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected unsupported redelivery error, got %v", err)
	}
}

func TestStripeScanParsesEventsAndSendsBearer(t *testing.T) {
	var auth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/v1/events" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "evt_1", "type": "invoice.paid", "created": time.Now().Unix()}},
		})
	}))
	defer server.Close()

	adapter := StripeAdapter{Client: server.Client()}
	res, err := adapter.Scan(context.Background(), ScanRequest{
		Connection:  Connection{Credential: "sk_test_secret", Config: map[string]string{"base_url": server.URL, "allow_test_base_url": "true"}},
		WindowStart: time.Now().Add(-time.Hour),
		WindowEnd:   time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer sk_test_secret" {
		t.Fatalf("authorization header=%q", auth)
	}
	if len(res.Objects) != 1 || res.Objects[0].ID != "evt_1" || !res.Objects[0].Recoverable {
		t.Fatalf("unexpected objects: %+v", res.Objects)
	}
}

func TestStripeRejectsTooOldWindow(t *testing.T) {
	adapter := StripeAdapter{Client: http.DefaultClient}
	_, err := adapter.Scan(context.Background(), ScanRequest{
		Connection:  Connection{Credential: "sk_test_secret"},
		WindowStart: time.Now().AddDate(0, 0, -31),
	})
	if err == nil {
		t.Fatal("expected 30-day window rejection")
	}
	_, err = adapter.Scan(context.Background(), ScanRequest{
		Connection: Connection{Credential: "sk_test_secret"},
		WindowEnd:  time.Now().AddDate(0, 0, -31),
	})
	if err == nil {
		t.Fatal("expected old end-window rejection")
	}
	if _, err := adapter.RequestRedelivery(context.Background(), Connection{}, "evt_1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected unsupported stripe redelivery, got %v", err)
	}
}

func TestStripeScopeObjectIDRetrievesSingleEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events/evt_scoped" {
			t.Fatalf("expected retrieve path, got %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "evt_scoped", "type": "charge.succeeded", "created": time.Now().Unix()})
	}))
	defer server.Close()

	adapter := StripeAdapter{Client: server.Client()}
	res, err := adapter.Scan(context.Background(), ScanRequest{
		Connection:    Connection{Credential: "sk_test_secret", Config: map[string]string{"base_url": server.URL, "allow_test_base_url": "true"}},
		ScopeObjectID: "evt_scoped",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects) != 1 || res.Objects[0].ID != "evt_scoped" {
		t.Fatalf("unexpected scoped result: %+v", res.Objects)
	}
}

func TestGitHubScopeObjectIDRetrievesSingleDelivery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/o/r/hooks/42/deliveries/100" {
			t.Fatalf("expected delivery detail path, got %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 100, "guid": "guid-scoped", "event": "push", "status_code": 200,
			"request": map[string]any{"payload": map[string]any{"zen": "ok"}},
		})
	}))
	defer server.Close()

	conn := Connection{Credential: "ghp_secret", Config: map[string]string{"base_url": server.URL, "allow_test_base_url": "true", "owner": "o", "repo": "r", "hook_id": "42"}}
	adapter := GitHubAdapter{Client: server.Client()}
	res, err := adapter.Scan(context.Background(), ScanRequest{Connection: conn, ScopeObjectID: "100"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects) != 1 || res.Objects[0].ID != "guid-scoped" || len(res.Objects[0].RawBody) == 0 {
		t.Fatalf("unexpected scoped result: %+v", res.Objects)
	}
}

func TestGitHubScanAndRedeliveryUseRepositoryWebhookAPI(t *testing.T) {
	var redelivered bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/hooks/42/deliveries":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 100, "guid": "guid-1", "event": "push", "status_code": 500}})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/hooks/42/deliveries/100/attempts":
			redelivered = true
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	conn := Connection{Credential: "ghp_secret", Config: map[string]string{"base_url": server.URL, "allow_test_base_url": "true", "owner": "o", "repo": "r", "hook_id": "42"}}
	adapter := GitHubAdapter{Client: server.Client()}
	res, err := adapter.Scan(context.Background(), ScanRequest{Connection: conn, RedeliverFailed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects) != 1 || !res.Objects[0].Failed || !res.Objects[0].Redeliverable {
		t.Fatalf("unexpected scan: %+v", res.Objects)
	}
	if _, err := adapter.RequestRedelivery(context.Background(), conn, "100"); err != nil {
		t.Fatal(err)
	}
	if !redelivered {
		t.Fatal("expected redelivery request")
	}
}

func TestGitHubRequiresRepositoryWebhookConfig(t *testing.T) {
	adapter := GitHubAdapter{Client: http.DefaultClient}
	conn := Connection{Credential: "ghp_secret", Config: map[string]string{"owner": "o"}}
	if err := adapter.ValidateConnection(context.Background(), conn); err == nil {
		t.Fatal("expected missing GitHub config rejection")
	}
	if _, err := adapter.RequestRedelivery(context.Background(), conn, "100"); err == nil {
		t.Fatal("expected redelivery missing config rejection")
	}
}

func TestProviderValueHelpersHandleCommonTypes(t *testing.T) {
	if bearerHeader(Connection{}) != "" || bearerHeader(Connection{Credential: " token "}) != "Bearer token" {
		t.Fatal("unexpected bearer header behavior")
	}
	if got := configValue(nil, "missing", "fallback"); got != "fallback" {
		t.Fatalf("unexpected fallback value %q", got)
	}
	if got := configValue(map[string]string{"key": " value "}, "key", "fallback"); got != "value" {
		t.Fatalf("unexpected config value %q", got)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	if !unixTime(json.Number("1700000000")).Equal(now) || !unixTime(float64(1_700_000_000)).Equal(now) || !unixTime(int64(1_700_000_000)).Equal(now) {
		t.Fatal("unixTime failed supported numeric inputs")
	}
	if !unixTime("not-time").IsZero() {
		t.Fatal("unsupported unixTime input should be zero")
	}
	if intFromAny(json.Number("42")) != 42 || intFromAny(float64(42)) != 42 || intFromAny(42) != 42 || intFromAny("42") != 42 || intFromAny("bad") != 0 {
		t.Fatal("intFromAny failed supported inputs")
	}
}

func TestUnsupportedProvidersReportLimitations(t *testing.T) {
	for _, provider := range []string{ProviderShopify, ProviderSlack} {
		adapter, ok := BuiltInRegistry(nil).Adapter(provider)
		if !ok {
			t.Fatalf("missing adapter %s", provider)
		}
		res, err := adapter.Scan(context.Background(), ScanRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Unsupported || len(res.Limitations) == 0 {
			t.Fatalf("expected limitation evidence for %s: %+v", provider, res)
		}
	}
}
