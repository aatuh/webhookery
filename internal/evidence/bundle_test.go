package evidence

import (
	"testing"
	"time"
)

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
