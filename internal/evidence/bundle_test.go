package evidence

import (
	"testing"
	"time"

	"webhookery/internal/auditchain"
	"webhookery/internal/domain"
)

func chainProofJSONL(t *testing.T) []byte {
	t.Helper()
	event := domain.AuditEvent{
		ID:         "aud_1",
		TenantID:   "ten_1",
		ActorID:    "usr_1",
		Action:     "audit_export.created",
		Resource:   "audit_export",
		ResourceID: "exp_1",
		OccurredAt: time.Unix(10, 0).UTC(),
	}
	entry, err := auditchain.ComputeEntry("ace_1", event, 1, "", domain.AuditChainEntrySourceLive, time.Unix(11, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	body, err := JSONLines([]any{entry})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestBuildTarGzipBundleIsDeterministicAndHashesFiles(t *testing.T) {
	manifest := Manifest{
		ExportID:  "exp_1",
		TenantID:  "ten_1",
		CreatedAt: time.Unix(123, 0).UTC(),
	}
	files := map[string][]byte{
		"audit_events.jsonl": []byte("{\"id\":\"aud_1\"}\n"),
		"timelines.jsonl":    []byte("{\"event_id\":\"evt_1\"}\n"),
	}

	first, err := BuildTarGzipBundle(manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildTarGzipBundle(manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	if first.BundleSHA256 != second.BundleSHA256 {
		t.Fatalf("bundle hash changed: %s != %s", first.BundleSHA256, second.BundleSHA256)
	}
	if first.ManifestSHA256 != second.ManifestSHA256 {
		t.Fatalf("manifest hash changed: %s != %s", first.ManifestSHA256, second.ManifestSHA256)
	}
	if len(first.Files) != 2 {
		t.Fatalf("expected two file hashes, got %d", len(first.Files))
	}
	if first.Files[0].Name != "audit_events.jsonl" {
		t.Fatalf("files not sorted deterministically: %+v", first.Files)
	}
}

func TestJSONLinesAddsOneLinePerItem(t *testing.T) {
	lines, err := JSONLines([]any{
		map[string]string{"id": "one"},
		map[string]string{"id": "two"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(lines) != "{\"id\":\"one\"}\n{\"id\":\"two\"}\n" {
		t.Fatalf("unexpected jsonl %q", string(lines))
	}
}

func TestVerifyTarGzipBundleChecksManifestFiles(t *testing.T) {
	bundle, err := BuildTarGzipBundle(Manifest{ExportID: "exp_1", TenantID: "ten_1", CreatedAt: time.Unix(123, 0).UTC()}, map[string][]byte{
		"audit_events.jsonl": []byte("{\"id\":\"aud_1\"}\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyTarGzipBundle(bundle.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.CheckedFiles != 1 || result.ManifestSHA256 != bundle.ManifestSHA256 {
		t.Fatalf("unexpected verification result: %+v", result)
	}
}

func TestVerifyTarGzipBundleChecksAuditChainProof(t *testing.T) {
	bundle, err := BuildTarGzipBundle(Manifest{ExportID: "exp_1", TenantID: "ten_1", CreatedAt: time.Unix(123, 0).UTC()}, map[string][]byte{
		"audit_events.jsonl":      []byte("{\"id\":\"aud_1\"}\n"),
		"audit_chain_proof.jsonl": chainProofJSONL(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyTarGzipBundle(bundle.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.CheckedChainEntries != 1 {
		t.Fatalf("unexpected chain verification result: %+v", result)
	}
}
