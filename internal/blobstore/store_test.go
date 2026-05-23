package blobstore

import "testing"

func TestRawPayloadKeySanitizesTenantRawAndHash(t *testing.T) {
	key := RawPayloadKey("ten/../a", "raw:1", "sha256:abcdef1234567890deadbeef")

	want := "raw-payloads/ten_.._a/raw_1-abcdef1234567890.bin"
	if key != want {
		t.Fatalf("key=%q want %q", key, want)
	}
}

func TestExportKeySanitizesSegments(t *testing.T) {
	key := ExportKey("ten a", "../exp/1")

	want := "evidence-exports/ten_a/exp_1.tar.gz"
	if key != want {
		t.Fatalf("key=%q want %q", key, want)
	}
}
