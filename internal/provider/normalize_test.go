package provider

import (
	"encoding/json"
	"errors"
	"testing"

	"webhookery/internal/domain"
	"webhookery/pkg/verifier"
)

func TestNormalizeBuiltInProviderMetadata(t *testing.T) {
	tests := []struct {
		name     string
		adapter  string
		raw      []byte
		headers  map[string][]string
		wantID   string
		wantType string
	}{
		{
			name:     "stripe",
			adapter:  "stripe",
			raw:      []byte(`{"id":"evt_stripe","type":"invoice.paid","account":"acct_123","api_version":"2026-01-01","data":{"object":{"id":"in_123"}}}`),
			wantID:   "evt_stripe",
			wantType: "invoice.paid",
		},
		{
			name:     "github",
			adapter:  "github",
			raw:      []byte(`{"repository":{"full_name":"acme/repo"},"sender":{"login":"octo"}}`),
			headers:  map[string][]string{"x-github-delivery": {"gh-delivery"}, "x-github-event": {"push"}},
			wantID:   "gh-delivery",
			wantType: "push",
		},
		{
			name:     "shopify",
			adapter:  "shopify",
			raw:      []byte(`{"id":123,"email":"buyer@example.com"}`),
			headers:  map[string][]string{"x-shopify-webhook-id": {"shopify-delivery"}, "x-shopify-topic": {"orders/create"}, "x-shopify-shop-domain": {"example.myshopify.com"}},
			wantID:   "shopify-delivery",
			wantType: "orders/create",
		},
		{
			name:     "slack",
			adapter:  "slack",
			raw:      []byte(`{"type":"event_callback","event_id":"Ev123","team_id":"T123","api_app_id":"A123","event":{"type":"reaction_added","item":{"type":"message"}}}`),
			wantID:   "Ev123",
			wantType: "reaction_added",
		},
		{
			name:     "cloudevents",
			adapter:  "cloudevents",
			raw:      []byte(`{"specversion":"1.0","id":"ce-1","source":"tests","type":"customer.created","subject":"customers/cus_1","data":{"id":"cus_1"}}`),
			headers:  map[string][]string{"content-type": {"application/cloudevents+json"}},
			wantID:   "ce-1",
			wantType: "customer.created",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := Normalize(NormalizeInput{
				Adapter:  tt.adapter,
				Provider: tt.adapter,
				SourceID: "src_1",
				TenantID: "ten_1",
				RawBody:  tt.raw,
				Headers:  tt.headers,
				Verified: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if env.ID != tt.wantID || env.Type != tt.wantType {
				t.Fatalf("unexpected envelope id/type: %+v", env)
			}
			if !json.Valid(env.Data) || !json.Valid(env.Metadata) || !json.Valid(env.Envelope) {
				t.Fatalf("normalized JSON must be valid: %+v", env)
			}
		})
	}
}

func TestNormalizeRejectsUnverifiedProviderPayload(t *testing.T) {
	_, err := Normalize(NormalizeInput{
		Adapter:  "github",
		Provider: "github",
		RawBody:  []byte(`{"zen":"x"}`),
		Verified: false,
	})
	if err == nil {
		t.Fatal("expected unverified normalization rejection")
	}
}

func TestNormalizeAllowsExplicitRecoveryAndUnsafePolicies(t *testing.T) {
	tests := []struct {
		name         string
		input        NormalizeInput
		wantSource   string
		wantProvider string
	}{
		{
			name: "provider API reconciliation",
			input: NormalizeInput{
				Adapter:      "stripe",
				Provider:     "stripe",
				SourceID:     "src_1",
				TenantID:     "ten_1",
				RawBody:      []byte(`{"id":"evt_recovered","type":"invoice.created","account":"acct_1"}`),
				RawHash:      "sha256:raw",
				Verified:     false,
				VerifyReason: domain.VerificationReasonProviderAPIReconcile,
			},
			wantSource:   "stripe:acct_1",
			wantProvider: "stripe",
		},
		{
			name: "generic unsafe",
			input: NormalizeInput{
				Adapter:      "generic-unsafe",
				Provider:     "generic",
				SourceID:     "src_unsafe",
				TenantID:     "ten_1",
				RawBody:      []byte(`{"id":"evt_unsafe","type":"debug"}`),
				RawHash:      "sha256:raw",
				Verified:     false,
				VerifyReason: verifier.ReasonInvalidSignature,
			},
			wantSource:   "generic-unsafe:src_unsafe",
			wantProvider: "generic",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := Normalize(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if env.Source != tt.wantSource || env.Provider != tt.wantProvider || env.ID == "" || env.EnvelopeHash == "" {
				t.Fatalf("unexpected recovery/unsafe normalization: %+v", env)
			}
		})
	}
}

func TestNormalizeUsesProviderAsAdapterAndFallsBackForRawNonJSONPayload(t *testing.T) {
	env, err := Normalize(NormalizeInput{
		Provider:     "cloudevents",
		SourceID:     "src_ce",
		TenantID:     "ten_1",
		RawBody:      []byte(`not-json`),
		RawHash:      "sha256:raw",
		Headers:      map[string][]string{"ce-id": {"evt_header"}, "ce-type": {"com.example.event"}, "ce-source": {"urn:test"}, "ce-subject": {"subject_1"}, "ce-specversion": {"1.0"}},
		Verified:     true,
		VerifyReason: verifier.ReasonOK,
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.ID != "evt_header" || env.Type != "com.example.event" || env.Source != "urn:test" || env.Subject != "subject_1" {
		t.Fatalf("CloudEvents header normalization mismatch: %+v", env)
	}
	if string(env.Data) != `"not-json"` {
		t.Fatalf("non-JSON payload should be preserved as a JSON string, got %s", env.Data)
	}
}

func TestNormalizeUsesDeclarativeDefinitionsAndFailsClosedOnInvalidDefinition(t *testing.T) {
	definition := json.RawMessage(`{"name":"custom","version":"v1","verification":{"type":"hmac_sha256","signature_header":"X-Sig"},"extractors":{"provider_event_id":"$.id","type":"$.kind"},"normalization":{"source":"custom/{{$.account}}","data":"$.payload"}}`)
	env, err := Normalize(NormalizeInput{
		Adapter:           "custom",
		Provider:          "custom",
		SourceID:          "src_1",
		TenantID:          "ten_1",
		RawBody:           []byte(`{"id":"evt_custom","kind":"thing.created","account":"acct_1","payload":{"z":2,"a":1}}`),
		RawHash:           "sha256:raw",
		Verified:          true,
		VerifyReason:      verifier.ReasonOK,
		AdapterDefinition: definition,
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.ID != "evt_custom" || env.Type != "thing.created" || env.Source != "custom/acct_1" || string(env.Data) != `{"a":1,"z":2}` {
		t.Fatalf("declarative normalization through Normalize mismatch: %+v data=%s", env, env.Data)
	}

	_, err = Normalize(NormalizeInput{
		Adapter:           "custom",
		Provider:          "custom",
		TenantID:          "ten_1",
		RawBody:           []byte(`{"id":"evt_custom"}`),
		RawHash:           "sha256:raw",
		Verified:          true,
		AdapterDefinition: json.RawMessage(`{"name":"custom","verification":{"type":"rsa"}}`),
	})
	if err == nil || errors.Is(err, ErrUnverifiedNormalization) {
		t.Fatalf("invalid declarative definition should fail closed before fallback normalization, got %v", err)
	}
}

func TestNormalizeProviderSpecificSubjectsAndFallbacks(t *testing.T) {
	tests := []struct {
		name        string
		adapter     string
		raw         []byte
		headers     map[string][]string
		wantSubject string
		wantSource  string
	}{
		{name: "slack channel subject", adapter: "slack", raw: []byte(`{"event_id":"Ev1","type":"event_callback","team_id":"T1","event":{"channel":"C1"}}`), wantSubject: "C1", wantSource: "slack:T1"},
		{name: "slack user subject", adapter: "slack", raw: []byte(`{"event_id":"Ev2","type":"event_callback","team_id":"T1","event":{"user":"U1"}}`), wantSubject: "U1", wantSource: "slack:T1"},
		{name: "shopify source and subject", adapter: "shopify", raw: []byte(`{"id":"order_1"}`), headers: map[string][]string{"x-shopify-webhook-id": {"wh_1"}, "x-shopify-topic": {"orders/create"}, "x-shopify-shop-domain": {"shop.example"}}, wantSubject: "shop.example", wantSource: "shopify:shop.example"},
		{name: "default fallback source", adapter: "unknown", raw: []byte(`{"event":{"type":"nested.type"}}`), wantSubject: "", wantSource: "unknown:src_1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := Normalize(NormalizeInput{
				Adapter:      tt.adapter,
				Provider:     tt.adapter,
				SourceID:     "src_1",
				TenantID:     "ten_1",
				RawBody:      tt.raw,
				RawHash:      "sha256:raw",
				Headers:      tt.headers,
				Verified:     true,
				VerifyReason: verifier.ReasonOK,
			})
			if err != nil {
				t.Fatal(err)
			}
			if env.Subject != tt.wantSubject || env.Source != tt.wantSource {
				t.Fatalf("unexpected subject/source: %+v", env)
			}
		})
	}
}
