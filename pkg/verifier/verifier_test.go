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
