package verifier

import (
	"testing"
	"time"
)

func TestHMACSignatureUsesExactRawBytes(t *testing.T) {
	secret := []byte("test-secret")
	raw := []byte("{\"id\":\"evt_123\",\"amount\":100}")
	sig := SignHMACSHA256Hex(secret, raw)

	if !VerifyHMACSHA256Hex(secret, raw, sig) {
		t.Fatal("expected raw body signature to verify")
	}
	if VerifyHMACSHA256Hex(secret, []byte("{\"amount\":100,\"id\":\"evt_123\"}"), sig) {
		t.Fatal("expected mutated JSON body to fail verification")
	}
}

func TestTimestampedSignatureWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := []byte(`{"type":"event"}`)
	header := TimestampedHeader("v1", now, []byte("secret"), raw)

	result := VerifyTimestampedHMAC(VerifyTimestampedHMACInput{
		Secret:          []byte("secret"),
		RawBody:         raw,
		Header:          header,
		Now:             now.Add(2 * time.Minute),
		Tolerance:       5 * time.Minute,
		ExpectedVersion: "v1",
		Encoding:        EncodingHex,
	})
	if !result.Valid {
		t.Fatalf("expected valid signature, got %s", result.Reason)
	}

	result = VerifyTimestampedHMAC(VerifyTimestampedHMACInput{
		Secret:          []byte("secret"),
		RawBody:         raw,
		Header:          header,
		Now:             now.Add(6 * time.Minute),
		Tolerance:       5 * time.Minute,
		ExpectedVersion: "v1",
		Encoding:        EncodingHex,
	})
	if result.Valid || result.Reason != ReasonExpiredTimestamp {
		t.Fatalf("expected expired timestamp, got valid=%v reason=%s", result.Valid, result.Reason)
	}
}

func TestCompareRejectsMalformedHex(t *testing.T) {
	if VerifyHMACSHA256Hex([]byte("secret"), []byte("body"), "not-hex") {
		t.Fatal("malformed signature must not verify")
	}
}

func TestBase64HMACSignatureUsesExactRawBytes(t *testing.T) {
	secret := []byte("test-secret")
	raw := []byte("{\"id\":\"evt_123\",\"amount\":100}")
	sig := SignHMACSHA256Base64(secret, raw)

	if !VerifyHMACSHA256Base64(secret, raw, sig) {
		t.Fatal("expected base64 raw body signature to verify")
	}
	if VerifyHMACSHA256Base64(secret, []byte("{\"amount\":100,\"id\":\"evt_123\"}"), sig) {
		t.Fatal("expected mutated JSON body to fail base64 verification")
	}
	if VerifyHMACSHA256Base64(secret, raw, "not-base64") {
		t.Fatal("malformed base64 signature must not verify")
	}
}

func TestVerifyTimestampedHMACSupportsBase64Encoding(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := []byte(`{"type":"event"}`)
	payload := []byte("1700000000." + string(raw))
	header := "t=1700000000,v1=" + SignHMACSHA256Base64([]byte("secret"), payload)

	result := VerifyTimestampedHMAC(VerifyTimestampedHMACInput{
		Secret:          []byte("secret"),
		RawBody:         raw,
		Header:          header,
		Now:             now,
		Tolerance:       5 * time.Minute,
		ExpectedVersion: "v1",
		Encoding:        EncodingBase64,
	})
	if !result.Valid || result.Reason != ReasonOK {
		t.Fatalf("expected valid base64 timestamped signature, got %+v", result)
	}
}

func TestVerifyTimestampedHMACRejectsMalformedAndUnsupportedHeaders(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := []byte(`{"type":"event"}`)
	validHeader := TimestampedHeader("v1", now, []byte("secret"), raw)

	tests := []struct {
		name   string
		header string
		input  VerifyTimestampedHMACInput
		want   string
	}{
		{
			name:   "missing timestamp",
			header: "v1=signature",
			want:   ReasonMalformedHeader,
		},
		{
			name:   "malformed timestamp",
			header: "t=not-unix,v1=signature",
			want:   ReasonMalformedHeader,
		},
		{
			name:   "missing expected version",
			header: validHeader,
			input:  VerifyTimestampedHMACInput{ExpectedVersion: "v2"},
			want:   ReasonMissingSignature,
		},
		{
			name:   "unsupported encoding",
			header: validHeader,
			input:  VerifyTimestampedHMACInput{Encoding: "sha1"},
			want:   ReasonUnsupportedAlg,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input
			input.Secret = []byte("secret")
			input.RawBody = raw
			input.Header = tt.header
			input.Now = now
			input.Tolerance = 5 * time.Minute
			if input.ExpectedVersion == "" {
				input.ExpectedVersion = "v1"
			}
			result := VerifyTimestampedHMAC(input)
			if result.Valid || result.Reason != tt.want {
				t.Fatalf("expected reason %s, got %+v", tt.want, result)
			}
		})
	}
}

func TestVerifyWebhookerySignatureReturnsKeyMetadata(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := []byte(`{"id":"evt_123"}`)
	header := TimestampedHeader("v1", now, []byte("secret"), raw)

	result := VerifyWebhookerySignature(VerifyWebhookerySignatureInput{
		Secret:           []byte("secret"),
		RawBody:          raw,
		SignatureHeader:  header,
		KeyIDHeader:      "esec_123",
		KeyVersionHeader: "7",
		Now:              now,
		Tolerance:        5 * time.Minute,
	})
	if !result.Valid {
		t.Fatalf("expected valid signature, got %s", result.Reason)
	}
	if result.KeyID != "esec_123" || result.KeyVersion != 7 {
		t.Fatalf("unexpected key metadata: %+v", result)
	}
}

func TestVerifyWebhookerySignatureRejectsMalformedKeyVersion(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := []byte(`{"id":"evt_123"}`)
	header := TimestampedHeader("v1", now, []byte("secret"), raw)

	result := VerifyWebhookerySignature(VerifyWebhookerySignatureInput{
		Secret:           []byte("secret"),
		RawBody:          raw,
		SignatureHeader:  header,
		KeyVersionHeader: "not-an-int",
		Now:              now,
		Tolerance:        5 * time.Minute,
	})
	if result.Valid || result.Reason != ReasonMalformedHeader {
		t.Fatalf("expected malformed key version rejection, got %+v", result)
	}
}
