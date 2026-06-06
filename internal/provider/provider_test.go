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

func TestBuiltInProviderAdapterNamesAndUnsafeAdapter(t *testing.T) {
	registry := BuiltInRegistry()
	tests := []string{
		"stripe",
		"github",
		"shopify",
		"slack",
		"generic-hmac",
		"generic-jwt",
		"cloudevents",
		"internal",
		"generic-unsafe",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			adapter, ok := registry.Adapter(strings.ToUpper(name))
			if !ok {
				t.Fatalf("missing adapter %s", name)
			}
			if adapter.Name() != name {
				t.Fatalf("adapter name=%q want %q", adapter.Name(), name)
			}
		})
	}
	if _, ok := registry.Adapter("unknown"); ok {
		t.Fatal("unknown adapter should not resolve")
	}

	unsafe, _ := registry.Adapter("generic-unsafe")
	result := unsafe.Verify(VerifyInput{RawBody: []byte(`{"id":"evt_1"}`)})
	if result.Verified || result.Reason != "unsafe_adapter_disabled" {
		t.Fatalf("unsafe adapter should fail closed, got %+v", result)
	}
}

func TestGenericHMACAdapterVerifiesBareAndPrefixedSHA256(t *testing.T) {
	adapter := GenericHMACAdapter{}
	body := []byte(`{"id":"evt_1"}`)
	signature := hmacSHA256Hex([]byte("secret"), body)

	for _, header := range []string{signature, "sha256=" + signature} {
		result := adapter.Verify(VerifyInput{
			RawBody: body,
			Headers: map[string][]string{"webhook-signature": {header}},
			Secret:  []byte("secret"),
		})
		if !result.Verified || result.Reason != "ok" {
			t.Fatalf("expected generic HMAC success for %q, got %+v", header, result)
		}
	}
	missing := adapter.Verify(VerifyInput{RawBody: body, Secret: []byte("secret")})
	if missing.Verified || missing.Reason != "missing_signature" {
		t.Fatalf("expected missing signature rejection, got %+v", missing)
	}
	invalid := adapter.Verify(VerifyInput{
		RawBody: []byte(`{"id":"evt_changed"}`),
		Headers: map[string][]string{"webhook-signature": {signature}},
		Secret:  []byte("secret"),
	})
	if invalid.Verified || invalid.Reason != "invalid_signature" {
		t.Fatalf("expected invalid signature rejection, got %+v", invalid)
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

func TestGenericJWTAdapterRejectsMalformedExpiredAndMismatchedTokens(t *testing.T) {
	adapter := GenericJWTAdapter{}
	now := time.Unix(1_700_000_000, 0)
	body := []byte(`{"id":"evt_jwt"}`)
	validClaims := map[string]any{
		"iat":         now.Unix(),
		"exp":         now.Add(time.Minute).Unix(),
		"body_sha256": sha256Hex(body),
	}

	tests := []struct {
		name    string
		headers map[string][]string
		want    string
	}{
		{name: "missing token", headers: nil, want: "missing_signature"},
		{name: "wrong bearer scheme", headers: map[string][]string{"authorization": {"Basic abc"}}, want: "missing_signature"},
		{name: "malformed segments", headers: map[string][]string{"webhook-jwt": {"a.b"}}, want: "malformed_header"},
		{name: "malformed header json", headers: map[string][]string{"webhook-jwt": {"bm90LWpzb24." + base64.RawURLEncoding.EncodeToString(mustJSON(t, validClaims)) + ".sig"}}, want: "malformed_header"},
		{name: "malformed claims json", headers: map[string][]string{"webhook-jwt": {base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{"alg": "HS256"})) + ".bm90LWpzb24.sig"}}, want: "malformed_header"},
		{name: "malformed signature encoding", headers: map[string][]string{"webhook-jwt": {base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{"alg": "HS256"})) + "." + base64.RawURLEncoding.EncodeToString(mustJSON(t, validClaims)) + ".@@@"}}, want: "malformed_header"},
		{name: "invalid signature", headers: map[string][]string{"webhook-jwt": {jwtHS256(t, []byte("wrong-secret"), validClaims)}}, want: "invalid_signature"},
		{name: "missing exp", headers: map[string][]string{"webhook-jwt": {jwtHS256(t, []byte("secret"), map[string]any{"body_sha256": sha256Hex(body)})}}, want: "malformed_header"},
		{name: "expired exp", headers: map[string][]string{"webhook-jwt": {jwtHS256(t, []byte("secret"), map[string]any{"exp": now.Add(-time.Second).Unix(), "body_sha256": sha256Hex(body)})}}, want: "expired_timestamp"},
		{name: "future nbf", headers: map[string][]string{"webhook-jwt": {jwtHS256(t, []byte("secret"), map[string]any{"exp": now.Add(time.Minute).Unix(), "nbf": now.Add(time.Second).Unix(), "body_sha256": sha256Hex(body)})}}, want: "expired_timestamp"},
		{name: "future iat", headers: map[string][]string{"webhook-jwt": {jwtHS256(t, []byte("secret"), map[string]any{"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Add(6 * time.Minute).Unix(), "body_sha256": sha256Hex(body)})}}, want: "expired_timestamp"},
		{name: "body hash mismatch", headers: map[string][]string{"webhook-jwt": {jwtHS256(t, []byte("secret"), map[string]any{"exp": now.Add(time.Minute).Unix(), "body_sha256": sha256Hex([]byte(`{"other":true}`))})}}, want: "invalid_signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adapter.Verify(VerifyInput{
				RawBody: body,
				Headers: tt.headers,
				Secret:  []byte("secret"),
				Now:     now,
			})
			if result.Verified || result.Reason != tt.want {
				t.Fatalf("expected %s, got %+v", tt.want, result)
			}
		})
	}
}

func TestGenericJWTAdapterAcceptsWebhookJWTHeaderAndPaddedEncoding(t *testing.T) {
	adapter := GenericJWTAdapter{}
	now := time.Unix(1_700_000_000, 0)
	body := []byte(`{"id":"evt_jwt"}`)
	token := jwtHS256Padded(t, []byte("secret"), map[string]any{
		"exp":         now.Add(time.Minute).Unix(),
		"body_sha256": sha256Hex(body),
	})

	result := adapter.Verify(VerifyInput{
		RawBody: body,
		Headers: map[string][]string{"webhook-jwt": {token}},
		Secret:  []byte("secret"),
		Now:     now,
	})
	if !result.Verified || result.Reason != "ok" {
		t.Fatalf("expected padded generic JWT to verify, got %+v", result)
	}
}

func TestCloudEventsAdapterRejectsMalformedAndIncompleteStructuredMode(t *testing.T) {
	adapter := CloudEventsAdapter{}
	malformed := adapter.Verify(VerifyInput{
		Headers: map[string][]string{"content-type": {"application/cloudevents+json"}},
		RawBody: []byte(`{`),
	})
	if malformed.Verified || malformed.Reason != "malformed_header" {
		t.Fatalf("expected malformed CloudEvents JSON rejection, got %+v", malformed)
	}
	missing := adapter.Verify(VerifyInput{
		Headers: map[string][]string{"content-type": {"application/cloudevents+json; charset=utf-8"}},
		RawBody: []byte(`{"specversion":"1.0","id":"evt_1"}`),
	})
	if missing.Verified || missing.Reason != "missing_cloudevents_headers" {
		t.Fatalf("expected incomplete structured CloudEvents rejection, got %+v", missing)
	}
}

func TestProviderInternalHelpers(t *testing.T) {
	if bearerToken("bearer token") != "token" || bearerToken("Basic token") != "" || bearerToken("Bearer ") != "" {
		t.Fatal("unexpected bearer token parsing")
	}
	var decoded map[string]any
	if !decodeJWTPart(base64.URLEncoding.EncodeToString(mustJSON(t, map[string]any{"ok": true})), &decoded) || decoded["ok"] != true {
		t.Fatal("expected padded base64url JWT part to decode")
	}
	if decodeJWTPart("@@@", &decoded) {
		t.Fatal("malformed JWT part should not decode")
	}
	if jwtNumericClaim(map[string]any{"n": json.Number("42")}, "n") != 42 || jwtNumericClaim(map[string]any{"n": "42"}, "n") != 0 {
		t.Fatal("unexpected JWT numeric claim behavior")
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

func jwtHS256Padded(t *testing.T, secret []byte, claims map[string]any) string {
	t.Helper()
	header := base64.URLEncoding.EncodeToString(mustJSON(t, map[string]any{"alg": "HS256", "typ": "JWT"}))
	payload := base64.URLEncoding.EncodeToString(mustJSON(t, claims))
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

func hmacSHA256Hex(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return base64ToHex(mac.Sum(nil))
}

func base64ToHex(raw []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, b := range raw {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
