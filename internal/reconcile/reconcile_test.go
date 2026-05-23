package reconcile

import (
	"context"
	"encoding/json"
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
