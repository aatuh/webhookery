package provider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestProviderSignatureVectors(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	body := []byte(`{"id":"evt_123","type":"payment_intent.succeeded","event_id":"slack_evt"}`)

	tests := []struct {
		name    string
		adapter string
		headers map[string][]string
	}{
		{
			name:    "stripe",
			adapter: "stripe",
			headers: map[string][]string{
				"stripe-signature": {fmt.Sprintf("t=%d,v1=%s", now.Unix(), hmacHex([]byte("whsec_test"), []byte(fmt.Sprintf("%d.%s", now.Unix(), body))))},
			},
		},
		{
			name:    "github",
			adapter: "github",
			headers: map[string][]string{
				"x-hub-signature-256": {"sha256=" + hmacHex([]byte("whsec_test"), body)},
				"x-github-delivery":   {"delivery-guid"},
				"x-github-event":      {"push"},
			},
		},
		{
			name:    "shopify",
			adapter: "shopify",
			headers: map[string][]string{
				"x-shopify-hmac-sha256": {hmacBase64([]byte("whsec_test"), body)},
				"x-shopify-topic":       {"orders/create"},
				"x-shopify-shop-domain": {"example.myshopify.com"},
				"x-shopify-webhook-id":  {"webhook-id"},
			},
		},
		{
			name:    "slack",
			adapter: "slack",
			headers: map[string][]string{
				"x-slack-request-timestamp": {fmt.Sprint(now.Unix())},
				"x-slack-signature":         {"v0=" + hmacHex([]byte("whsec_test"), []byte(fmt.Sprintf("v0:%d:%s", now.Unix(), body)))},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, ok := BuiltInRegistry().Adapter(tt.adapter)
			if !ok {
				t.Fatalf("missing adapter %s", tt.adapter)
			}
			result := adapter.Verify(VerifyInput{
				RawBody: body,
				Headers: tt.headers,
				Secret:  []byte("whsec_test"),
				Now:     now,
			})
			if !result.Verified {
				t.Fatalf("expected verified signature, got %s", result.Reason)
			}

			bad := adapter.Verify(VerifyInput{
				RawBody: []byte(`{"type":"payment_intent.succeeded","id":"evt_123"}`),
				Headers: tt.headers,
				Secret:  []byte("whsec_test"),
				Now:     now,
			})
			if bad.Verified {
				t.Fatal("mutated body must not verify")
			}
		})
	}
}

func TestCloudEventsAdapterAcceptsStructuredMode(t *testing.T) {
	adapter := CloudEventsAdapter{}
	result := adapter.Verify(VerifyInput{
		Headers: map[string][]string{"content-type": {"application/cloudevents+json"}},
		RawBody: []byte(`{"specversion":"1.0","id":"evt_1","type":"invoice.paid","source":"tests"}`),
	})
	if !result.Verified {
		t.Fatalf("structured CloudEvents request should verify as a trusted envelope, got %+v", result)
	}
}

func TestProviderRejectsMissingSignature(t *testing.T) {
	adapter, ok := BuiltInRegistry().Adapter("github")
	if !ok {
		t.Fatal("missing github adapter")
	}
	result := adapter.Verify(VerifyInput{
		RawBody: []byte(`{"zen":"Keep it logically awesome."}`),
		Headers: map[string][]string{
			"x-github-event": {"ping"},
		},
		Secret: []byte("whsec_test"),
		Now:    time.Unix(1_700_000_000, 0),
	})
	if result.Verified || result.Reason != "missing_signature" {
		t.Fatalf("expected missing signature rejection, got verified=%v reason=%s", result.Verified, result.Reason)
	}
}

func TestInternalTrustedProducerAdapter(t *testing.T) {
	adapter, ok := BuiltInRegistry().Adapter("internal")
	if !ok {
		t.Fatal("missing internal adapter")
	}
	result := adapter.Verify(VerifyInput{RawBody: []byte(`{"source_id":"src_internal"}`)})
	if !result.Verified {
		t.Fatalf("internal trusted producer should verify after API auth, got %s", result.Reason)
	}
}

func hmacHex(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func hmacBase64(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
