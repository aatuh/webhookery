package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webhookery/internal/config"
	"webhookery/internal/evidence"
)

func TestWritePrivateFileUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "export.tar.gz")

	if err := writePrivateFile(path, []byte("bundle")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions=%o want 0600", got)
	}
}

func TestWritePrivateFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	if err := writePrivateFile(link, []byte("new")); err == nil {
		t.Fatal("expected symlink write rejection")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "old" {
		t.Fatalf("target was modified through symlink: %q", string(body))
	}
}

func TestVerifyEvidenceBundleFileRequiresExplicitFile(t *testing.T) {
	if err := verifyEvidenceBundleFile(""); err == nil {
		t.Fatal("expected missing file path error")
	}
}

func TestVerifyEvidenceBundleFileAcceptsValidBundle(t *testing.T) {
	bundle, err := evidence.BuildTarGzipBundle(evidence.Manifest{ExportID: "exp_1", TenantID: "ten_1", CreatedAt: time.Unix(1, 0).UTC()}, map[string][]byte{
		"audit_events.jsonl": []byte("{}\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := os.WriteFile(path, bundle.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidenceBundleFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestReadMTLSFilesRequiresBothFiles(t *testing.T) {
	if _, _, err := readMTLSFiles("client.crt", ""); err == nil {
		t.Fatal("expected mTLS file pair validation")
	}
}

func TestReadSmallFileRejectsDirectoryAndLargeFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := readSmallFile(dir, 64); err == nil {
		t.Fatal("expected directory rejection")
	}
	path := filepath.Join(dir, "large.pem")
	if err := os.WriteFile(path, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSmallFile(path, 3); err == nil {
		t.Fatal("expected oversized file rejection")
	}
}

func TestReadSmallFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "client.key")
	link := filepath.Join(dir, "client-link.key")
	if err := os.WriteFile(target, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if _, err := readSmallFile(link, 64); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestSecretBoxFromConfigAcceptsVaultTransit(t *testing.T) {
	box, err := secretBoxFromConfig(context.Background(), config.Config{
		SecretBoxMode:   "vault-transit",
		VaultAddr:       "https://vault.example",
		VaultToken:      "vault-token",
		VaultTransitKey: "webhookery",
	})
	if err != nil {
		t.Fatal(err)
	}
	if box == nil {
		t.Fatal("expected vault transit secret box")
	}
}

func TestKeyCustodyKeyRefRedactsAWSKMSKeyID(t *testing.T) {
	cfg := config.Config{SecretBoxMode: "aws-kms", AWSKMSKeyID: "arn:aws:kms:us-east-1:123456789012:key/secret-key-id"}

	ref := keyCustodyKeyRef(cfg)
	if ref == "" {
		t.Fatal("expected redacted key reference")
	}
	if bytes.Contains([]byte(ref), []byte("secret-key-id")) || bytes.Contains([]byte(ref), []byte("123456789012")) {
		t.Fatalf("key reference leaked key id material: %q", ref)
	}
}

func TestRunKeyCustodyTestDoesNotPrintCiphertextOrKeyIDInLocalMode(t *testing.T) {
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://example")
	t.Setenv("WEBHOOKERY_SECRET_BOX_MODE", "local")
	t.Setenv("WEBHOOKERY_MASTER_KEY_BASE64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	err = runKeyCustody([]string{"test"})
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("invalid json output %q: %v", string(body), err)
	}
	if out["ok"] != true || out["mode"] != "local" {
		t.Fatalf("unexpected output: %s", body)
	}
	if bytes.Contains(body, []byte("webhookery-key-custody-test")) {
		t.Fatalf("key custody output leaked test plaintext: %s", body)
	}
}

func TestProductionDoctorBlocksUnsafeDefaultsAndRedactsValues(t *testing.T) {
	env := map[string]string{
		"WEBHOOKERY_ENVIRONMENT":               "production",
		"WEBHOOKERY_DATABASE_URL":              "postgres://webhookery:secret-db-password@db/webhookery?sslmode=disable",
		"WEBHOOKERY_SECRET_BOX_MODE":           "local",
		"WEBHOOKERY_MASTER_KEY_BASE64":         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"WEBHOOKERY_RAW_STORAGE_MODE":          "s3",
		"WEBHOOKERY_OBJECT_STORAGE_ENDPOINT":   "storage.internal:9000",
		"WEBHOOKERY_OBJECT_STORAGE_BUCKET":     "webhookery-raw",
		"WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY": "prod-access-key",
		"WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY": "object-secret-password",
		"WEBHOOKERY_OBJECT_STORAGE_USE_SSL":    "false",
		"WEBHOOKERY_AWS_KMS_KEY_ID":            "arn:aws:kms:us-east-1:123456789012:key/secret-key-id",
	}

	findings := productionDoctorFindings(func(name string) string { return env[name] })
	if countDoctorBlockers(findings) == 0 {
		t.Fatalf("expected production doctor blockers, got %+v", findings)
	}
	var out bytes.Buffer
	writeDoctorFindings(&out, findings)
	for _, forbidden := range []string{"secret-db-password", "object-secret-password", "secret-key-id", "123456789012", env["WEBHOOKERY_DATABASE_URL"]} {
		if bytes.Contains(out.Bytes(), []byte(forbidden)) {
			t.Fatalf("doctor output leaked sensitive value %q in %s", forbidden, out.String())
		}
	}
}

func TestProductionDoctorAcceptsHardenedVaultS3Config(t *testing.T) {
	env := map[string]string{
		"WEBHOOKERY_ENVIRONMENT":               "production",
		"WEBHOOKERY_DATABASE_URL":              "postgres://webhookery@db.internal/webhookery?sslmode=require",
		"WEBHOOKERY_TLS_CERT_FILE":             "/etc/webhookery/tls.crt",
		"WEBHOOKERY_TLS_KEY_FILE":              "/etc/webhookery/tls.key",
		"WEBHOOKERY_SECRET_BOX_MODE":           "vault-transit",
		"WEBHOOKERY_VAULT_ADDR":                "https://vault.internal",
		"WEBHOOKERY_VAULT_TOKEN":               "vault-token",
		"WEBHOOKERY_VAULT_TRANSIT_KEY":         "webhookery",
		"WEBHOOKERY_RAW_STORAGE_MODE":          "s3",
		"WEBHOOKERY_OBJECT_STORAGE_ENDPOINT":   "s3.internal",
		"WEBHOOKERY_OBJECT_STORAGE_BUCKET":     "webhookery-raw",
		"WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY": "prod-access-key",
		"WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY": "prod-object-secret",
		"WEBHOOKERY_OBJECT_STORAGE_USE_SSL":    "true",
	}

	findings := productionDoctorFindings(func(name string) string { return env[name] })
	if blockers := countDoctorBlockers(findings); blockers != 0 {
		t.Fatalf("expected no blockers, got %d: %+v", blockers, findings)
	}
}

func TestRunDoctorProductionReturnsNonZeroOnBlockers(t *testing.T) {
	t.Setenv("WEBHOOKERY_ENVIRONMENT", "production")
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://webhookery:secret@db/webhookery?sslmode=require")
	t.Setenv("WEBHOOKERY_SECRET_BOX_MODE", "local")
	t.Setenv("WEBHOOKERY_MASTER_KEY_BASE64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	err = runDoctor([]string{"production"})
	_ = writer.Close()
	if err == nil {
		t.Fatal("expected production doctor to fail on blockers")
	}
	body, readErr := io.ReadAll(reader)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if bytes.Contains(body, []byte("webhookery:secret")) || bytes.Contains(body, []byte("secret@db")) {
		t.Fatalf("doctor output leaked database password: %s", body)
	}
}
