package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"sort"
	"strings"
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

func TestBuildTarGzipBundleWritesVersionedSanitizedManifest(t *testing.T) {
	bundle, err := BuildTarGzipBundle(Manifest{
		ExportID:          "exp_1",
		TenantID:          "ten_1",
		CreatedAt:         time.Unix(123, 0).UTC(),
		IncludedEvents:    []string{"evt_2", "evt_1", "evt_1"},
		IncludedIncidents: []string{"inc_1"},
	}, map[string][]byte{
		"audit_events.jsonl": []byte("{\"id\":\"aud_1\"}\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	files, err := readTarGzipFiles(bundle.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes := files["manifest.json"]
	if bytes.Contains(manifestBytes, []byte(`"tenant_id":`)) {
		t.Fatalf("manifest leaked raw tenant id: %s", string(manifestBytes))
	}
	if bytes.Contains(manifestBytes, []byte(`"from":`)) || bytes.Contains(manifestBytes, []byte(`"to":`)) {
		t.Fatalf("manifest serialized empty time window: %s", string(manifestBytes))
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != ManifestSchemaV1 {
		t.Fatalf("unexpected schema version %q", manifest.SchemaVersion)
	}
	if manifest.BundleID != "exp_1" || manifest.TenantIDHash == "" || manifest.GeneratedAt.IsZero() {
		t.Fatalf("manifest missing bundle id, tenant hash, or generated time: %+v", manifest)
	}
	if got := strings.Join(manifest.IncludedEvents, ","); got != "evt_1,evt_2" {
		t.Fatalf("included events not normalized: %s", got)
	}
	if manifest.Hashes["audit_events.jsonl"] == "" || len(manifest.NonClaims) == 0 || manifest.RedactionPolicy.Secrets == "" {
		t.Fatalf("manifest missing hashes, non-claims, or redaction policy: %+v", manifest)
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

func TestVerifyTarGzipBundleRejectsMissingSchemaVersion(t *testing.T) {
	bundle, err := BuildTarGzipBundle(Manifest{ExportID: "exp_1", TenantID: "ten_1", CreatedAt: time.Unix(123, 0).UTC()}, map[string][]byte{
		"audit_events.jsonl": []byte("{\"id\":\"aud_1\"}\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	files, err := readTarGzipFiles(bundle.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	delete(manifest, "schema_version")
	files["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = append(files["manifest.json"], '\n')

	result, err := VerifyTarGzipBundle(tarGzipTestFiles(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatalf("expected missing schema version to be invalid: %+v", result)
	}
	if !hasFailure(result.Failures, "unsupported manifest schema_version") {
		t.Fatalf("expected schema version failure, got %+v", result.Failures)
	}
}

func TestVerifyTarGzipBundleRejectsTamperedFile(t *testing.T) {
	bundle, err := BuildTarGzipBundle(Manifest{ExportID: "exp_1", TenantID: "ten_1", CreatedAt: time.Unix(123, 0).UTC()}, map[string][]byte{
		"audit_events.jsonl": []byte("{\"id\":\"aud_1\"}\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	files, err := readTarGzipFiles(bundle.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	files["audit_events.jsonl"] = []byte("{\"id\":\"aud_tampered\"}\n")

	result, err := VerifyTarGzipBundle(tarGzipTestFiles(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatalf("expected tampered bundle to be invalid: %+v", result)
	}
	if !hasFailure(result.Failures, "hash mismatch: audit_events.jsonl") {
		t.Fatalf("expected audit_events hash mismatch, got %+v", result.Failures)
	}
}

func tarGzipTestFiles(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var out bytes.Buffer
	gz, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	gz.Name = "webhookery-evidence-export.tar"
	gz.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	for _, name := range names {
		if err := writeTarFile(tw, name, files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func hasFailure(failures []string, want string) bool {
	for _, failure := range failures {
		if strings.Contains(failure, want) {
			return true
		}
	}
	return false
}
