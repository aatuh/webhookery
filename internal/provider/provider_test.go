package provider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProviderSignatureVectors(t *testing.T) {
	registry := loadSignatureVectorRegistry(t)
	if registry.SchemaVersion != "webhookery.provider_signature_vectors.v1" {
		t.Fatalf("unexpected provider vector registry schema_version %q", registry.SchemaVersion)
	}
	if len(registry.Vectors) == 0 {
		t.Fatal("provider vector registry must contain at least one vector")
	}

	seen := map[string]bool{}
	for _, vector := range registry.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			if vector.Provider == "" || vector.Source == "" || vector.CheckedDate == "" || vector.Expected.Reason == "" {
				t.Fatalf("vector must include provider, source, checked_date, and expected reason: %+v", vector)
			}
			if _, err := time.Parse("2006-01-02", vector.CheckedDate); err != nil {
				t.Fatalf("vector checked_date must use YYYY-MM-DD: %v", err)
			}
			if seen[vector.Provider] {
				t.Fatalf("duplicate provider vector for %s", vector.Provider)
			}
			seen[vector.Provider] = true
			adapter, ok := BuiltInRegistry().Adapter(vector.Provider)
			if !ok {
				t.Fatalf("missing adapter %s", vector.Provider)
			}
			now, err := time.Parse(time.RFC3339, vector.Now)
			if err != nil {
				t.Fatalf("vector now must use RFC3339: %v", err)
			}
			result := adapter.Verify(VerifyInput{
				RawBody: []byte(vector.RawBody),
				Headers: vector.Headers,
				Secret:  []byte(vector.Secret),
				Now:     now,
			})
			if result.Verified != vector.Expected.Verified || result.Reason != vector.Expected.Reason {
				t.Fatalf("expected verified=%v reason=%s, got verified=%v reason=%s", vector.Expected.Verified, vector.Expected.Reason, result.Verified, result.Reason)
			}

			bad := adapter.Verify(VerifyInput{
				RawBody: []byte(vector.MutatedRawBody),
				Headers: vector.Headers,
				Secret:  []byte(vector.Secret),
				Now:     now,
			})
			if bad.Verified {
				t.Fatal("mutated body must not verify")
			}
		})
	}

	for _, provider := range []string{"stripe", "github", "shopify", "slack"} {
		if !seen[provider] {
			t.Fatalf("provider vector registry missing %s", provider)
		}
	}
}

type signatureVectorRegistry struct {
	SchemaVersion string                    `json:"schema_version"`
	Vectors       []providerSignatureVector `json:"vectors"`
}

type providerSignatureVector struct {
	Name           string              `json:"name"`
	Provider       string              `json:"provider"`
	Source         string              `json:"source"`
	CheckedDate    string              `json:"checked_date"`
	Now            string              `json:"now"`
	Secret         string              `json:"secret"`
	RawBody        string              `json:"raw_body"`
	MutatedRawBody string              `json:"mutated_raw_body"`
	Headers        map[string][]string `json:"headers"`
	Expected       struct {
		Verified bool   `json:"verified"`
		Reason   string `json:"reason"`
	} `json:"expected"`
}

func loadSignatureVectorRegistry(t *testing.T) signatureVectorRegistry {
	t.Helper()
	raw, err := os.ReadFile("testdata/signature_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var registry signatureVectorRegistry
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestFailedVerificationResultDoesNotExposeSensitiveInputs(t *testing.T) {
	result := StripeAdapter{}.Verify(VerifyInput{
		RawBody: []byte(`{"customer":"cus_secret","raw_body":"raw-body-secret"}`),
		Headers: map[string][]string{
			"stripe-signature": {"t=1700000000,v1=signature-secret-marker"},
		},
		Secret: []byte("whsec_secret_marker"),
		Now:    time.Unix(1_700_000_000, 0),
	})
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Fatal("expected failed verification")
	}
	for _, forbidden := range []string{"whsec_secret_marker", "signature-secret-marker", "raw-body-secret", "cus_secret"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("failed verification result leaked sensitive input %q: %s", forbidden, raw)
		}
	}
	if !strings.Contains(string(raw), "invalid_signature") {
		t.Fatalf("failed verification should retain safe reason, got %s", raw)
	}
}

func TestCloudEventsAdapterDoesNotVerifyUnsignedStructuredMode(t *testing.T) {
	adapter := CloudEventsAdapter{}
	result := adapter.Verify(VerifyInput{
		Headers: map[string][]string{"content-type": {"application/cloudevents+json"}},
		RawBody: []byte(`{"specversion":"1.0","id":"evt_1","type":"invoice.paid","source":"tests"}`),
	})
	if result.Verified || result.Reason != "unsigned_cloudevents" {
		t.Fatalf("structured CloudEvents validity must not imply trust, got %+v", result)
	}
}

func TestCloudEventsAdapterDoesNotVerifyUnsignedBinaryMode(t *testing.T) {
	adapter := CloudEventsAdapter{}
	result := adapter.Verify(VerifyInput{
		Headers: map[string][]string{
			"ce-id":          {"evt_1"},
			"ce-type":        {"invoice.paid"},
			"ce-source":      {"tests"},
			"ce-specversion": {"1.0"},
		},
		RawBody: []byte(`{"amount":42}`),
	})
	if result.Verified || result.Reason != "unsigned_cloudevents" {
		t.Fatalf("binary CloudEvents validity must not imply trust, got %+v", result)
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

func TestGenericJWTAdapterVerifiesHS256AndBodyHash(t *testing.T) {
	adapter, ok := BuiltInRegistry().Adapter("generic-jwt")
	if !ok {
		t.Fatal("missing generic-jwt adapter")
	}
	now := time.Unix(1_700_000_000, 0)
	body := []byte(`{"id":"evt_jwt","type":"invoice.paid"}`)
	token := jwtHS256(t, []byte("whsec_test"), map[string]any{
		"iss":         "issuer",
		"jti":         "evt_jwt",
		"iat":         now.Unix(),
		"exp":         now.Add(time.Minute).Unix(),
		"body_sha256": sha256Hex(body),
	})

	result := adapter.Verify(VerifyInput{
		RawBody: body,
		Headers: map[string][]string{
			"authorization": {"Bearer " + token},
		},
		Secret: []byte("whsec_test"),
		Now:    now,
	})
	if !result.Verified {
		t.Fatalf("expected generic JWT to verify, got %s", result.Reason)
	}

	mutated := adapter.Verify(VerifyInput{
		RawBody: []byte(`{"id":"evt_jwt","type":"invoice.failed"}`),
		Headers: map[string][]string{
			"authorization": {"Bearer " + token},
		},
		Secret: []byte("whsec_test"),
		Now:    now,
	})
	if mutated.Verified || mutated.Reason != "invalid_signature" {
		t.Fatalf("mutated raw body must not verify, verified=%v reason=%s", mutated.Verified, mutated.Reason)
	}
}

func TestGenericJWTAdapterRejectsAlgNone(t *testing.T) {
	adapter, ok := BuiltInRegistry().Adapter("generic-jwt")
	if !ok {
		t.Fatal("missing generic-jwt adapter")
	}
	token := base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{"alg": "none"})) + "." +
		base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{"body_sha256": sha256Hex([]byte(`{}`))})) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("ignored"))

	result := adapter.Verify(VerifyInput{
		RawBody: []byte(`{}`),
		Headers: map[string][]string{
			"authorization": {"Bearer " + token},
		},
		Secret: []byte("whsec_test"),
		Now:    time.Unix(1_700_000_000, 0),
	})
	if result.Verified || result.Reason != "unsupported_algorithm" {
		t.Fatalf("alg none must be rejected, verified=%v reason=%s", result.Verified, result.Reason)
	}
}

func jwtHS256(t *testing.T, secret []byte, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{"alg": "HS256", "typ": "JWT"}))
	payload := base64.RawURLEncoding.EncodeToString(mustJSON(t, claims))
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
