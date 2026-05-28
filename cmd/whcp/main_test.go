package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestRunDispatchesSubcommandUsage(t *testing.T) {
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "usage: whcp") {
		t.Fatalf("expected top-level usage, got %v", err)
	}
	if err := run([]string{"unknown"}); err == nil || !strings.Contains(err.Error(), "usage: whcp") {
		t.Fatalf("expected unknown command usage, got %v", err)
	}

	for _, command := range []string{
		"admin",
		"api-keys",
		"producer-clients",
		"producer-mtls-identities",
		"key-custody",
		"identity-providers",
		"scim-tokens",
		"role-bindings",
		"access-policies",
		"authz",
		"events",
		"sources",
		"provider-connections",
		"adapters",
		"endpoints",
		"subscriptions",
		"retry-policies",
		"routes",
		"transformations",
		"deliveries",
		"replay-jobs",
		"reconciliation-jobs",
		"ops",
		"alerts",
		"notification-channels",
		"notification-deliveries",
		"siem-sinks",
		"siem-deliveries",
		"audit",
		"retention",
		"schemas",
		"dead-letter",
		"quarantine",
		"signatures",
	} {
		t.Run(command, func(t *testing.T) {
			err := run([]string{command})
			if err == nil || !strings.Contains(err.Error(), "usage: whcp "+command) {
				t.Fatalf("expected %s usage, got %v", command, err)
			}
		})
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

func TestAPIEndpointRejectsUnsafeBaseURLs(t *testing.T) {
	tests := []string{
		"ftp://api.example",
		"https://user:pass@api.example",
		"https:///missing-host",
	}
	for _, baseURL := range tests {
		t.Run(baseURL, func(t *testing.T) {
			if _, err := apiEndpoint(baseURL, "/v1/events"); err == nil {
				t.Fatal("expected unsafe base URL rejection")
			}
		})
	}

	endpoint, err := apiEndpoint("https://api.example/", "/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://api.example/v1/events" {
		t.Fatalf("unexpected endpoint %q", endpoint)
	}
}

func TestCLIParsersTrimAndIgnoreInvalidEntries(t *testing.T) {
	if got := splitCSV(" events:read, ,events:write "); strings.Join(got, "|") != "events:read|events:write" {
		t.Fatalf("unexpected csv split: %#v", got)
	}
	values := parseKeyValueCSV("provider=stripe,broken, empty = , =ignored,region=eu")
	if values["provider"] != "stripe" || values["region"] != "eu" || values["empty"] != "" {
		t.Fatalf("unexpected key value parse: %#v", values)
	}
	if _, ok := values[""]; ok {
		t.Fatalf("empty key must be ignored: %#v", values)
	}
}

func TestParseOptionalTimeRequiresRFC3339AndNormalizesUTC(t *testing.T) {
	if zero, err := parseOptionalTime(""); err != nil || !zero.IsZero() {
		t.Fatalf("empty time should be nil value, got %v err=%v", zero, err)
	}
	parsed, err := parseOptionalTime("2026-05-28T12:30:00+03:00")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Format(time.RFC3339) != "2026-05-28T09:30:00Z" {
		t.Fatalf("time was not normalized to UTC: %s", parsed.Format(time.RFC3339))
	}
	if _, err := parseOptionalTime("2026-05-28"); err == nil {
		t.Fatal("expected non-RFC3339 time rejection")
	}
}

func TestPostJSONSendsBearerAndJSONBody(t *testing.T) {
	var gotAuth, gotContentType, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	if err := postJSON(server.URL, "whkey_test", "/v1/replay-jobs", map[string]string{"event_id": "evt_1"}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer whkey_test" {
		t.Fatalf("unexpected auth header %q", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Fatalf("unexpected content type %q", gotContentType)
	}
	if gotBody != `{"event_id":"evt_1"}` {
		t.Fatalf("unexpected JSON body %q", gotBody)
	}
}

func TestJSONRequestHelpersUseExpectedMethodsAndPaths(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(body))
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	if err := getJSON(server.URL, "whkey_test", "/v1/events"); err != nil {
		t.Fatal(err)
	}
	if err := patchJSON(server.URL, "whkey_test", "/v1/sources/src_1", map[string]string{"reason": "rename"}); err != nil {
		t.Fatal(err)
	}
	if err := deleteJSON(server.URL, "whkey_test", "/v1/sources/src_1", map[string]string{"reason": "delete"}); err != nil {
		t.Fatal(err)
	}

	want := []string{
		`GET /v1/events Bearer whkey_test `,
		`PATCH /v1/sources/src_1 Bearer whkey_test {"reason":"rename"}`,
		`DELETE /v1/sources/src_1 Bearer whkey_test {"reason":"delete"}`,
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected requests:\ngot:\n%s\nwant:\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
}

func TestDownloadAuditExportWritesPrivateFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audit-exports/exp_1:download" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer whkey_test" {
			t.Fatalf("unexpected auth header %q", got)
		}
		_, _ = w.Write([]byte("bundle"))
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "exp.tar.gz")
	if err := downloadAuditExport(server.URL, "whkey_test", "exp_1", output); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "bundle" {
		t.Fatalf("unexpected bundle body %q", string(body))
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions=%o want 0600", got)
	}
}

func TestExportRawPayloadDecodesBase64ToPrivateFile(t *testing.T) {
	rawBody := []byte("raw evidence bytes")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events/evt_1/raw" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"body_base64": base64.StdEncoding.EncodeToString(rawBody)})
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "raw.bin")
	if err := exportRawPayload(server.URL, "whkey_test", "evt_1", output); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, rawBody) {
		t.Fatalf("unexpected raw body %q", string(body))
	}
}

func TestOperatorFileHelpers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readRequiredOperatorFile(path, "secret-file")
	if err != nil {
		t.Fatal(err)
	}
	if got != "secret\n" {
		t.Fatalf("unexpected file body %q", got)
	}
	if _, err := readRequiredOperatorFile("", "secret-file"); err == nil {
		t.Fatal("expected required file validation")
	}
	if got, err := readOptionalOperatorFile(""); err != nil || got != "" {
		t.Fatalf("empty optional file got %q err=%v", got, err)
	}
	if got, err := readOptionalOperatorFile(path); err != nil || got != "secret\n" {
		t.Fatalf("optional file got %q err=%v", got, err)
	}
}

func TestSmallCLIValueHelpers(t *testing.T) {
	if valueOrDefault(-1, 10) != 10 || valueOrDefault(0, 10) != 0 {
		t.Fatal("unexpected integer default behavior")
	}
	if valueOrDefaultString("  ", "fallback") != "fallback" || valueOrDefaultString("value", "fallback") != "value" {
		t.Fatal("unexpected string default behavior")
	}
	if nullableCLITime(time.Time{}) != nil {
		t.Fatal("zero CLI time should encode as null")
	}
	now := time.Unix(1, 0).UTC()
	if nullableCLITime(now) != now {
		t.Fatal("non-zero CLI time should be preserved")
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
