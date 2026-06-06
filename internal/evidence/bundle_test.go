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
		TenantID:          "ten_whsec_secret_marker",
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
	if bytes.Contains(manifestBytes, []byte("ten_whsec_secret_marker")) || bytes.Contains(manifestBytes, []byte("whsec_secret_marker")) {
		t.Fatalf("manifest leaked secret-shaped tenant id: %s", string(manifestBytes))
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

func TestVerifyTarGzipBundleRejectsMissingManifestHash(t *testing.T) {
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
	manifest["hashes"] = map[string]string{}
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
		t.Fatalf("expected missing manifest hash to be invalid: %+v", result)
	}
	if !hasFailure(result.Failures, "manifest hash missing: audit_events.jsonl") {
		t.Fatalf("expected manifest hash missing failure, got %+v", result.Failures)
	}
}

func TestVerifyTarGzipBundleToleratesUnknownOptionalManifestField(t *testing.T) {
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
	manifest["future_optional_field"] = map[string]any{"ignored": true}
	files["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = append(files["manifest.json"], '\n')

	result, err := VerifyTarGzipBundle(tarGzipTestFiles(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatalf("expected unknown optional field to be tolerated: %+v", result)
	}
}

func TestInspectTarGzipBundleSummarizesEvidenceAndWarnings(t *testing.T) {
	bundle, err := BuildTarGzipBundle(Manifest{
		ExportID:             "exp_1",
		TenantID:             "ten_1",
		CreatedAt:            time.Unix(123, 0).UTC(),
		IncludedEvents:       []string{"evt_1"},
		IncludedIncidents:    []string{"inc_1"},
		IncludeRawPayloads:   true,
		IncludePayloadBodies: true,
	}, map[string][]byte{
		"incident_report.json":    []byte(`{"id":"inc_1"}`),
		"incident_report.md":      []byte("# Incident\n"),
		"timelines.jsonl":         []byte("{\"kind\":\"delivery\"}\n{\"kind\":\"replay\"}\n{\"kind\":\"delivery\"}\n"),
		"audit_events.jsonl":      []byte("{\"id\":\"aud_1\"}\n{\"id\":\"aud_2\"}\n"),
		"audit_chain_proof.jsonl": chainProofJSONL(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	view, err := InspectTarGzipBundle(bundle.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Verification.Valid || view.Verification.CheckedChainEntries != 1 {
		t.Fatalf("expected valid inspected bundle with checked chain proof, got %+v", view.Verification)
	}
	if view.SchemaVersion != BundleViewSchemaV1 || view.Manifest.SchemaVersion != ManifestSchemaV1 {
		t.Fatalf("unexpected view/manifest schema versions: %+v", view)
	}
	if view.Summary.FileCount != 5 || view.Summary.IncludedEventCount != 1 || view.Summary.IncludedIncidentCount != 1 {
		t.Fatalf("unexpected summary counts: %+v", view.Summary)
	}
	if view.Summary.TimelineEntryCount != 3 || view.Summary.TimelineKinds["delivery"] != 2 || view.Summary.TimelineKinds["replay"] != 1 {
		t.Fatalf("timeline summary was not populated: %+v", view.Summary)
	}
	if view.Summary.AuditEventCount != 2 || !view.Summary.HasIncidentReportJSON || !view.Summary.HasIncidentReportMarkdown || !view.Summary.HasAuditChainProof || view.Summary.AuditChainStatus != "verified" {
		t.Fatalf("incident/audit summary was not populated: %+v", view.Summary)
	}
	if !hasWarning(view.Warnings, "raw payload bodies may be included") || !hasWarning(view.Warnings, "payload bodies may be included") {
		t.Fatalf("expected sensitive payload warnings, got %+v", view.Warnings)
	}
}

func TestInspectTarGzipBundleReportsInvalidSummariesAndMissingManifest(t *testing.T) {
	bundle, err := BuildTarGzipBundle(Manifest{
		ExportID:  "exp_1",
		TenantID:  "ten_1",
		CreatedAt: time.Unix(123, 0).UTC(),
	}, map[string][]byte{
		"timelines.jsonl":    []byte("{bad-json}\n"),
		"audit_events.jsonl": []byte("{bad-json}\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectTarGzipBundle(bundle.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(view.Warnings, "timelines.jsonl could not be summarized") || !hasWarning(view.Warnings, "audit_events.jsonl could not be summarized") {
		t.Fatalf("expected invalid jsonl warnings, got %+v", view.Warnings)
	}
	if !hasWarning(view.Warnings, "raw payload bodies and payload bodies are omitted") {
		t.Fatalf("expected omitted payload warning, got %+v", view.Warnings)
	}

	files, err := readTarGzipFiles(bundle.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	delete(files, "manifest.json")
	missingManifest, err := InspectTarGzipBundle(tarGzipTestFiles(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if missingManifest.Verification.Valid || !hasWarning(missingManifest.Warnings, "manifest.json is missing") {
		t.Fatalf("expected missing manifest warning and invalid verification, got %+v", missingManifest)
	}
}

func TestInspectTarGzipBundleCleansZeroTimeWindowAndReportsManifestFailures(t *testing.T) {
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
	manifest["from"] = "0001-01-01T00:00:00Z"
	manifest["to"] = "0001-01-01T00:00:00Z"
	files["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = append(files["manifest.json"], '\n')

	view, err := InspectTarGzipBundle(tarGzipTestFiles(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if view.Manifest.From != nil || view.Manifest.To != nil {
		t.Fatalf("zero time window should be omitted after inspection: from=%v to=%v", view.Manifest.From, view.Manifest.To)
	}

	delete(manifest, "bundle_id")
	delete(manifest, "tenant_id_hash")
	delete(manifest, "non_claims")
	delete(manifest, "redaction_policy")
	delete(manifest, "hashes")
	files["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = append(files["manifest.json"], '\n')
	result, err := VerifyTarGzipBundle(tarGzipTestFiles(t, files))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bundle_id is missing", "tenant_id_hash is missing", "non_claims are missing", "redaction_policy is missing", "hashes are missing"} {
		if !hasFailure(result.Failures, want) {
			t.Fatalf("expected manifest failure %q, got %+v", want, result.Failures)
		}
	}
}

func TestReadTarGzipFilesRejectsUnsafeEntryNames(t *testing.T) {
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "../secret.txt", Typeflag: tar.TypeReg, Size: int64(len("secret"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readTarGzipFiles(out.Bytes()); err == nil || !strings.Contains(err.Error(), "unsafe tar entry name") {
		t.Fatalf("expected unsafe tar entry rejection, got %v", err)
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

func hasWarning(warnings []string, want string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, want) {
			return true
		}
	}
	return false
}
