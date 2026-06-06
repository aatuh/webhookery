package provider

import (
	"encoding/json"
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
