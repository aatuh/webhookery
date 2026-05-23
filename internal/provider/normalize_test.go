package provider

import (
	"encoding/json"
	"testing"
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
