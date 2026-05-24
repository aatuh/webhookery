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
