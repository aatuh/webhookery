package provider

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"webhookery/pkg/verifier"
)

func TestDeclarativeAdapterVerifiesTimestampedHMAC(t *testing.T) {
	definition := json.RawMessage(`{
		"name":"acme-hmac",
		"version":"2026-05-01",
		"verification":{
			"type":"hmac_sha256",
			"signature_header":"X-Acme-Signature",
			"timestamp_header":"X-Acme-Timestamp",
			"signed_payload":"{{timestamp}}.{{raw_body}}",
			"encoding":"hex",
			"replay_window_seconds":300
		},
		"extractors":{"provider_event_id":"$.id","type":"$.event_type","account_id":"$.account.id"},
		"normalization":{"source":"acme/{{account_id}}","subject":"$.resource.id","data":"$"}
	}`)
	adapter, err := NewDeclarativeAdapter(definition)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":"evt_1","event_type":"thing.created","account":{"id":"acct_1"},"resource":{"id":"res_1"}}`)
	ts := "1700000000"
	signature := verifier.SignHMACSHA256Hex([]byte("secret"), []byte(ts+"."+string(body)))
	result := adapter.Verify(VerifyInput{
		RawBody: body,
		Headers: map[string][]string{
			"x-acme-signature": {signature},
			"x-acme-timestamp": {ts},
		},
		Secret: []byte("secret"),
		Now:    time.Unix(1_700_000_100, 0),
	})
	if !result.Verified || result.Reason != verifier.ReasonOK {
		t.Fatalf("expected verified declarative request, got %+v", result)
	}
	id, typ := DeclarativeMetadata(definition, body, nil)
	if id != "evt_1" || typ != "thing.created" {
		t.Fatalf("unexpected declarative metadata id=%q type=%q", id, typ)
	}
}

func TestDeclarativeAdapterRejectsExpiredAndMutatedPayloads(t *testing.T) {
	definition := json.RawMessage(`{"name":"acme","verification":{"type":"hmac_sha256","signature_header":"X-Sig","timestamp_header":"X-Time","signed_payload":"{{timestamp}}.{{raw_body}}","replay_window_seconds":30}}`)
	adapter, err := NewDeclarativeAdapter(definition)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":"evt_1"}`)
	ts := "1700000000"
	signature := verifier.SignHMACSHA256Hex([]byte("secret"), []byte(ts+"."+string(body)))
	expired := adapter.Verify(VerifyInput{RawBody: body, Headers: map[string][]string{"x-sig": {signature}, "x-time": {ts}}, Secret: []byte("secret"), Now: time.Unix(1_700_000_100, 0)})
	if expired.Reason != verifier.ReasonExpiredTimestamp {
		t.Fatalf("expected expired timestamp, got %+v", expired)
	}
	mutated := adapter.Verify(VerifyInput{RawBody: []byte(`{"id":"evt_2"}`), Headers: map[string][]string{"x-sig": {signature}, "x-time": {ts}}, Secret: []byte("secret"), Now: time.Unix(1_700_000_010, 0)})
	if mutated.Reason != verifier.ReasonInvalidSignature {
		t.Fatalf("expected invalid signature for mutated raw body, got %+v", mutated)
	}
}

func TestDeclarativeDefinitionValidationRejectsUnsafeOrAmbiguousRules(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{name: "missing definition", raw: nil, want: "definition is required"},
		{name: "malformed json", raw: json.RawMessage(`{`), want: "unexpected end"},
		{name: "missing name", raw: json.RawMessage(`{"verification":{"type":"hmac_sha256","signature_header":"X-Sig"}}`), want: "name is required"},
		{name: "unsupported verification", raw: json.RawMessage(`{"name":"acme","verification":{"type":"rsa","signature_header":"X-Sig"}}`), want: "only hmac_sha256"},
		{name: "missing signature header", raw: json.RawMessage(`{"name":"acme","verification":{"type":"hmac_sha256"}}`), want: "signature_header is required"},
		{name: "unsupported encoding", raw: json.RawMessage(`{"name":"acme","verification":{"type":"hmac_sha256","signature_header":"X-Sig","encoding":"plain"}}`), want: "unsupported signature encoding"},
		{name: "unsupported signed payload", raw: json.RawMessage(`{"name":"acme","verification":{"type":"hmac_sha256","signature_header":"X-Sig","signed_payload":"{{method}}:{{raw_body}}"}}`), want: "unsupported signed_payload"},
		{name: "timestamp template missing header", raw: json.RawMessage(`{"name":"acme","verification":{"type":"hmac_sha256","signature_header":"X-Sig","signed_payload":"{{timestamp}}:{{raw_body}}"}}`), want: "timestamp_header is required"},
		{name: "negative replay window", raw: json.RawMessage(`{"name":"acme","verification":{"type":"hmac_sha256","signature_header":"X-Sig","replay_window_seconds":-1}}`), want: "replay_window_seconds"},
		{name: "huge replay window", raw: json.RawMessage(`{"name":"acme","verification":{"type":"hmac_sha256","signature_header":"X-Sig","replay_window_seconds":86401}}`), want: "replay_window_seconds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDeclarativeDefinition(tt.raw)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}

func TestDeclarativeAdapterRejectsMalformedHeadersAndSupportsBase64(t *testing.T) {
	prefixed := json.RawMessage(`{"name":"acme","verification":{"type":"hmac_sha256","signature_header":"X-Sig","timestamp_header":"X-Time","signed_payload":"v0:{{timestamp}}:{{raw_body}}","signature_prefix":"v0="}}`)
	adapter, err := NewDeclarativeAdapter(prefixed)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":"evt_1"}`)
	ts := "2026-06-11T12:00:00Z"
	signature := verifier.SignHMACSHA256Hex([]byte("secret"), []byte("v0:"+ts+":"+string(body)))

	tests := []struct {
		name    string
		headers map[string][]string
		want    string
	}{
		{name: "missing signature", headers: map[string][]string{"x-time": {ts}}, want: verifier.ReasonMissingSignature},
		{name: "wrong prefix", headers: map[string][]string{"x-sig": {"sha256=" + signature}, "x-time": {ts}}, want: verifier.ReasonMalformedHeader},
		{name: "missing timestamp", headers: map[string][]string{"x-sig": {"v0=" + signature}}, want: verifier.ReasonMissingSignature},
		{name: "bad timestamp", headers: map[string][]string{"x-sig": {"v0=" + signature}, "x-time": {"not-a-time"}}, want: verifier.ReasonMalformedHeader},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adapter.Verify(VerifyInput{RawBody: body, Headers: tt.headers, Secret: []byte("secret"), Now: time.Date(2026, 6, 11, 12, 0, 1, 0, time.UTC)})
			if result.Verified || result.Reason != tt.want {
				t.Fatalf("expected %s, got %+v", tt.want, result)
			}
		})
	}

	base64Def := json.RawMessage(`{"name":"acme64","verification":{"type":"hmac_sha256","signature_header":"X-Sig","encoding":"base64"}}`)
	base64Adapter, err := NewDeclarativeAdapter(base64Def)
	if err != nil {
		t.Fatal(err)
	}
	base64Sig := verifier.SignHMACSHA256Base64([]byte("secret"), body)
	result := base64Adapter.Verify(VerifyInput{RawBody: body, Headers: map[string][]string{"x-sig": {base64Sig}}, Secret: []byte("secret")})
	if !result.Verified || result.Reason != verifier.ReasonOK {
		t.Fatalf("expected base64 signature to verify, got %+v", result)
	}
}

func TestNormalizeDeclarativeUsesExtractorsTemplatesAndHashes(t *testing.T) {
	definition := json.RawMessage(`{
		"name":"acme-hmac",
		"version":"2026-05-01",
		"verification":{"type":"hmac_sha256","signature_header":"X-Sig"},
		"extractors":{
			"provider_event_id":"$.id",
			"type":"$.event_type",
			"account_id":"header:X-Acme-Account"
		},
		"normalization":{
			"source":"acme/{{account_id}}/{{$.resource.id}}",
			"subject":"$.resource.id",
			"data":"$.data"
		}
	}`)
	raw := []byte(`{"id":"evt_1","event_type":"thing.created","resource":{"id":"res_1"},"data":{"z":2,"a":1}}`)
	env, ok, err := NormalizeDeclarative(NormalizeInput{
		Adapter:      "acme",
		Provider:     "acme",
		SourceID:     "src_1",
		TenantID:     "ten_1",
		RawBody:      raw,
		RawHash:      "sha256:raw",
		Headers:      map[string][]string{"x-acme-account": {"acct_1"}},
		Verified:     true,
		VerifyReason: verifier.ReasonOK,
	}, definition)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected declarative normalization to produce an envelope")
	}
	if env.ID != "evt_1" || env.ProviderEventID != "evt_1" || env.Type != "thing.created" || env.Source != "acme/acct_1/res_1" || env.Subject != "res_1" {
		t.Fatalf("unexpected declarative envelope fields: %+v", env)
	}
	if string(env.Data) != `{"a":1,"z":2}` {
		t.Fatalf("data was not canonicalized: %s", env.Data)
	}
	var envelope map[string]any
	if err := json.Unmarshal(env.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["tenant_id"] != "ten_1" || envelope["signature_verified"] != true || envelope["verification_reason"] != verifier.ReasonOK {
		t.Fatalf("envelope missing tenant or verification evidence: %s", env.Envelope)
	}
	var metadata map[string]any
	if err := json.Unmarshal(env.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["declarative_adapter"] != "acme-hmac" || metadata["declarative_version"] != "2026-05-01" || metadata["account_id"] != "acct_1" {
		t.Fatalf("metadata missing declarative adapter evidence: %s", env.Metadata)
	}
	if env.EnvelopeHash == "" || env.DataHash == "" || env.MetadataHash == "" {
		t.Fatalf("expected hashes to be populated: %+v", env)
	}
}

func TestNormalizeDeclarativeFallsBackWhenExtractorsAreMissing(t *testing.T) {
	definition := json.RawMessage(`{"name":"fallback","version":"v1","verification":{"type":"hmac_sha256","signature_header":"X-Sig"},"normalization":{"source":"provider/{{account_id}}","subject":"header:X-Subject"}}`)
	raw := []byte(`{"nested":"not-used"}`)
	env, ok, err := NormalizeDeclarative(NormalizeInput{
		Adapter:      "fallback",
		Provider:     "generic",
		SourceID:     "src_1",
		TenantID:     "ten_1",
		RawBody:      raw,
		RawHash:      "sha256:raw",
		Headers:      map[string][]string{"x-subject": {"sub_1"}},
		Verified:     false,
		VerifyReason: verifier.ReasonInvalidSignature,
	}, definition)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || env.ID != "sha256:raw" || env.Type != "unknown" || env.Source != "provider/" || env.Subject != "sub_1" {
		t.Fatalf("unexpected fallback declarative envelope: ok=%v env=%+v", ok, env)
	}

	id, typ := DeclarativeMetadata(json.RawMessage(`{"bad":true}`), raw, nil)
	if id != "" || typ != "" {
		t.Fatalf("invalid definition should not expose metadata, got id=%q type=%q", id, typ)
	}
	if _, ok, err := NormalizeDeclarative(NormalizeInput{}, json.RawMessage(`{"bad":true}`)); err == nil || ok {
		t.Fatalf("invalid declarative normalization should fail closed, ok=%v err=%v", ok, err)
	}
}

func TestDeclarativePathHelpersHandleNumbersHeadersLiteralsAndInvalidPaths(t *testing.T) {
	raw := parseJSONMap([]byte(`{"id":123,"nested":{"value":true},"flat":"value"}`))
	headers := map[string][]string{"x-id": {"hdr_1"}}
	if got := declarativeValue("$.id", raw, headers); got != "123" {
		t.Fatalf("numeric path should render without decimals, got %q", got)
	}
	if got := declarativeValue("header:X-ID", raw, headers); got != "hdr_1" {
		t.Fatalf("header path should be case-insensitive, got %q", got)
	}
	if got := declarativeValue("$.nested.value", raw, headers); got != "true" {
		t.Fatalf("boolean path should stringify, got %q", got)
	}
	if got := declarativeAny("$.flat.missing", raw, headers); got != nil {
		t.Fatalf("non-object traversal should return nil, got %#v", got)
	}
	if got := declarativeValue("literal-type", raw, headers); got != "literal-type" {
		t.Fatalf("literal path should round trip, got %q", got)
	}
	if got := renderDeclarativeTemplate("acct/{{account_id}}/{{$.flat}}/{{$.missing", raw, headers, map[string]string{"account_id": "acct_1"}); got != "acct/acct_1/value/{{$.missing" {
		t.Fatalf("unexpected template render %q", got)
	}
}
