package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apppkg "webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/config"
	"webhookery/internal/evidence"
	"webhookery/internal/ssrf"
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
		"replay-approval-policies",
		"reconciliation-jobs",
		"ops",
		"alerts",
		"notification-channels",
		"notification-deliveries",
		"siem-sinks",
		"siem-deliveries",
		"audit",
		"evidence",
		"retention",
		"schemas",
		"dead-letter",
		"quarantine",
		"incidents",
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

func TestRuntimeDeliveryAdaptersBlockUnsafeURLsWithoutLeakingSecrets(t *testing.T) {
	deliveryResult, err := (deliveryAdapter{}).Deliver(context.Background(), "http://169.254.169.254/latest?token=secret-token", []byte(`{"ok":true}`), []byte("delivery-secret"), "key_1", 1, nil, nil)
	if err == nil || deliveryResult.FailureClass != "policy_blocked" {
		t.Fatalf("expected blocked delivery adapter result, got result=%+v err=%v", deliveryResult, err)
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "delivery-secret") {
		t.Fatalf("delivery adapter error leaked secret material: %v", err)
	}

	signalResult, err := (signalAdapter{}).Deliver(context.Background(), "http://169.254.169.254/latest?token=secret-token", []byte(`{"ok":true}`), []byte("signal-secret"))
	if err == nil || signalResult.FailureClass != "policy_blocked" {
		t.Fatalf("expected blocked signal adapter result, got result=%+v err=%v", signalResult, err)
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "signal-secret") {
		t.Fatalf("signal adapter error leaked secret material: %v", err)
	}
}

func TestRuntimeCommandsValidateUsageBeforeOpeningStore(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"up", "extra"},
	} {
		if err := runMigrate(args); err == nil || !strings.Contains(err.Error(), "usage: whcp migrate") {
			t.Fatalf("expected migrate usage for args %+v, got %v", args, err)
		}
	}
	if err := runMigrate([]string{"--not-a-real-flag"}); err == nil {
		t.Fatal("expected migrate flag parse error")
	}
	if err := runWorker([]string{"--not-a-real-flag"}); err == nil {
		t.Fatal("expected worker flag parse error")
	}
}

func TestRunSignaturesVerifyGenericHMAC(t *testing.T) {
	body := []byte(`{"id":"evt_cli_signature"}`)
	bodyFile := filepath.Join(t.TempDir(), "body.json")
	if err := os.WriteFile(bodyFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	err = run([]string{"signatures", "verify", "--provider", "generic-hmac", "--secret", "secret", "--body", bodyFile, "--header", "Webhook-Signature: " + signature})
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Verified bool
		Reason   string
		Provider string
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid signature verification JSON %q: %v", out, err)
	}
	if !result.Verified || result.Provider != "generic-hmac" || result.Reason != "ok" {
		t.Fatalf("unexpected signature verification result: %+v", result)
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

func TestViewEvidenceBundleFileRequiresExplicitFile(t *testing.T) {
	if err := viewEvidenceBundleFile(""); err == nil {
		t.Fatal("expected missing file path error")
	}
}

func TestViewEvidenceBundleFileSummarizesWithoutPrintingBodies(t *testing.T) {
	bundle, err := evidence.BuildTarGzipBundle(evidence.Manifest{
		ExportID:             "exp_1",
		TenantID:             "ten_1",
		CreatedAt:            time.Unix(1, 0).UTC(),
		IncludedEvents:       []string{"evt_1"},
		IncludedIncidents:    []string{"inc_1"},
		IncludeRawPayloads:   true,
		IncludePayloadBodies: true,
		IncludeTimelines:     true,
	}, map[string][]byte{
		"audit_events.jsonl":   []byte(`{"action":"incident_report.generated"}` + "\n"),
		"incident_report.json": []byte(`{"body":"do-not-print-incident-json"}` + "\n"),
		"incident_report.md":   []byte("do-not-print-incident-markdown\n"),
		"raw_payload.bin":      []byte("do-not-print-raw-payload\n"),
		"timelines.jsonl": []byte(
			`{"kind":"delivery","state":"failed"}` + "\n" +
				`{"kind":"replay","state":"succeeded"}` + "\n",
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := os.WriteFile(path, bundle.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	err = viewEvidenceBundleFile(path)
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"do-not-print-incident-json", "do-not-print-incident-markdown", "do-not-print-raw-payload"} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("evidence view printed bundled file body %q in %s", forbidden, body)
		}
	}
	var view evidence.BundleView
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("invalid view JSON %q: %v", body, err)
	}
	if view.SchemaVersion != evidence.BundleViewSchemaV1 || !view.Verification.Valid {
		t.Fatalf("unexpected view status: %+v", view)
	}
	if view.Summary.IncludedEventCount != 1 || view.Summary.IncludedIncidentCount != 1 || view.Summary.TimelineEntryCount != 2 || view.Summary.AuditEventCount != 1 {
		t.Fatalf("unexpected summary counts: %+v", view.Summary)
	}
	if !view.Summary.HasIncidentReportJSON || !view.Summary.HasIncidentReportMarkdown || view.Summary.TimelineKinds["delivery"] != 1 || view.Summary.TimelineKinds["replay"] != 1 {
		t.Fatalf("unexpected summary details: %+v", view.Summary)
	}
	if !strings.Contains(strings.Join(view.Warnings, "\n"), "raw payload bodies may be included") {
		t.Fatalf("expected raw-payload handling warning, got %+v", view.Warnings)
	}
}

func TestRunEvidenceViewReadsExplicitBundleFile(t *testing.T) {
	bundle, err := evidence.BuildTarGzipBundle(evidence.Manifest{
		ExportID:  "exp_1",
		TenantID:  "ten_1",
		CreatedAt: time.Unix(1, 0).UTC(),
	}, map[string][]byte{
		"audit_events.jsonl": []byte(`{"action":"event.captured"}` + "\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := os.WriteFile(path, bundle.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	err = runEvidence([]string{"view", "--file", path})
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var view evidence.BundleView
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("invalid evidence view JSON %q: %v", body, err)
	}
	if view.Manifest.ExportID != "exp_1" || view.Manifest.TenantIDHash == "" || !view.Verification.Valid {
		t.Fatalf("unexpected evidence view: %+v", view)
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

func TestFormatEventTimelineSupportsTableMarkdownAndJSON(t *testing.T) {
	entries := []apppkg.EventTimelineEntry{{
		SchemaVersion: apppkg.EventTimelineSchemaV1,
		Sequence:      1,
		Kind:          "replay",
		RefID:         "rpl_1",
		State:         "completed",
		Detail:        "reason_code=incident_recovery reason=receiver fixed",
		OccurredAt:    time.Unix(123, 0).UTC(),
	}}

	table, err := formatEventTimeline(entries, "table")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(table), "SEQ\tOCCURRED_AT\tKIND\tREF_ID\tSTATE\tDETAIL") || !strings.Contains(string(table), "1\t1970-01-01T00:02:03Z\treplay\trpl_1\tcompleted\treason_code=incident_recovery") {
		t.Fatalf("unexpected table timeline:\n%s", table)
	}

	markdown, err := formatEventTimeline(entries, "markdown")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "## Event Timeline") || !strings.Contains(string(markdown), "`webhookery.event_timeline.v1`") || !strings.Contains(string(markdown), "| 1 | `1970-01-01T00:02:03Z` | `replay` | `rpl_1` | `completed` |") {
		t.Fatalf("unexpected markdown timeline:\n%s", markdown)
	}

	jsonBody, err := formatEventTimeline(entries, "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(jsonBody), `"schema_version":"webhookery.event_timeline.v1"`) {
		t.Fatalf("unexpected json timeline:\n%s", jsonBody)
	}

	if _, err := formatEventTimeline(entries, "xml"); err == nil {
		t.Fatal("expected unknown timeline format rejection")
	}
}

func TestGetEventTimelineFetchesAndWritesMarkdown(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/events/evt_1/timeline" {
			t.Fatalf("unexpected timeline request %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(eventTimelinePage{Data: []apppkg.EventTimelineEntry{{
			SchemaVersion: apppkg.EventTimelineSchemaV1,
			Sequence:      1,
			Kind:          "delivery",
			RefID:         "del_1",
			State:         "failed",
			Detail:        "receiver timeout",
			OccurredAt:    time.Unix(123, 0).UTC(),
		}}})
	}))
	defer server.Close()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	err = getEventTimeline(server.URL, "whkey_timeline", "evt_1", "markdown")
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer whkey_timeline" {
		t.Fatalf("authorization header=%q", gotAuth)
	}
	if !strings.Contains(string(body), "## Event Timeline") || !strings.Contains(string(body), "`delivery`") || !strings.Contains(string(body), "receiver timeout") {
		t.Fatalf("unexpected timeline output:\n%s", body)
	}
}

func TestReplayCreateRequiresReasonCodeBeforeRequest(t *testing.T) {
	err := runReplayJobs([]string{"create", "--event-id", "evt_1", "--reason", "debug", "--base-url", "https://api.example", "--api-key", "whkey_test"})
	if err == nil || !strings.Contains(err.Error(), "reason-code is required") {
		t.Fatalf("expected missing reason-code validation, got %v", err)
	}
}

func TestReplayCreateApprovalExpiryRequiresApproval(t *testing.T) {
	err := runReplayJobs([]string{"create", "--event-id", "evt_1", "--reason-code", "support_investigation", "--reason", "debug", "--approval-expires-at", "2026-06-05T12:00:00Z", "--base-url", "https://api.example", "--api-key", "whkey_test"})
	if err == nil || !strings.Contains(err.Error(), "approval-expires-at requires require-approval") {
		t.Fatalf("expected approval expiry validation, got %v", err)
	}
}

func TestCLICommandValidationRejectsMissingRequiredArgsBeforeRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))
	defer server.Close()
	common := []string{"--base-url", server.URL, "--api-key", "whkey_validation"}
	tests := []struct {
		name    string
		run     func() error
		wantErr string
	}{
		{
			name:    "incident get missing id",
			run:     func() error { return runIncidents(append([]string{"get"}, common...)) },
			wantErr: "incident-id is required",
		},
		{
			name: "incident add-event missing event id",
			run: func() error {
				return runIncidents(append([]string{"add-event", "--incident-id", "inc_1", "--reason", "attach"}, common...))
			},
			wantErr: "incident-id and event-id are required",
		},
		{
			name: "incident remove-event missing event id",
			run: func() error {
				return runIncidents(append([]string{"remove-event", "--incident-id", "inc_1", "--reason", "detach"}, common...))
			},
			wantErr: "incident-id and event-id are required",
		},
		{
			name: "dead-letter release missing entry id",
			run: func() error {
				return runDeadLetter(append([]string{"release", "--reason-code", "incident_recovery", "--reason", "receiver fixed"}, common...))
			},
			wantErr: "entry-id is required",
		},
		{
			name: "dead-letter release missing reason code",
			run: func() error {
				return runDeadLetter(append([]string{"release", "--entry-id", "dlq_1", "--reason", "receiver fixed"}, common...))
			},
			wantErr: "reason-code is required",
		},
		{
			name: "dead-letter bulk missing entry ids",
			run: func() error {
				return runDeadLetter(append([]string{"bulk-release", "--reason-code", "incident_recovery", "--reason", "receiver fixed"}, common...))
			},
			wantErr: "entry-ids is required",
		},
		{
			name: "transformation version missing id",
			run: func() error {
				return runTransformations(append([]string{"version", "--operations-file", "ops.json"}, common...))
			},
			wantErr: "transformation-id is required",
		},
		{
			name: "transformation activate missing version",
			run: func() error {
				return runTransformations(append([]string{"activate", "--transformation-id", "trn_1", "--reason", "publish"}, common...))
			},
			wantErr: "transformation-id and version-id are required",
		},
		{
			name: "transformation dry run missing payload file",
			run: func() error {
				return runTransformations(append([]string{"dry-run", "--operations-file", "ops.json"}, common...))
			},
			wantErr: "payload-file is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			err := tt.run()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q error, got %v", tt.wantErr, err)
			}
			if called {
				t.Fatal("request should not be sent when local validation fails")
			}
		})
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

func TestGetJSONDecodeSendsBearerAndDecodesResponse(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s want GET", r.Method)
		}
		if r.URL.Path != "/v1/events/evt_1" {
			t.Fatalf("path=%s want /v1/events/evt_1", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "evt_1"})
	}))
	defer server.Close()

	var decoded struct {
		ID string `json:"id"`
	}
	if err := getJSONDecode(server.URL, "whkey_decode", "/v1/events/evt_1", &decoded); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer whkey_decode" {
		t.Fatalf("authorization header %q did not use the provided API key", gotAuth)
	}
	if decoded.ID != "evt_1" {
		t.Fatalf("decoded id=%q want evt_1", decoded.ID)
	}
}

func TestGetJSONDecodeProblemErrorRedactsBodyDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"stable_code":"WEBHOOKERY_TENANT_ACCESS_DENIED","request_id":"req_get","detail":"tenant secret detail"}`))
	}))
	defer server.Close()

	var decoded map[string]any
	err := getJSONDecode(server.URL, "whkey_should_not_leak", "/v1/events/evt_1", &decoded)
	if err == nil {
		t.Fatal("expected problem response")
	}
	got := err.Error()
	for _, want := range []string{"request failed", "403", "WEBHOOKERY_TENANT_ACCESS_DENIED", "req_get"} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q did not contain %q", got, want)
		}
	}
	for _, forbidden := range []string{"whkey_should_not_leak", "tenant secret detail"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("error %q leaked %q", got, forbidden)
		}
	}
}

func TestPostJSONDecodeSendsJSONAndDecodesResponse(t *testing.T) {
	var gotAuth, gotContentType, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s want POST", r.Method)
		}
		if r.URL.Path != "/v1/incidents/inc_1/evidence-export" {
			t.Fatalf("path=%s want evidence-export path", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"exp_1"}`))
	}))
	defer server.Close()

	var decoded struct {
		ID string `json:"id"`
	}
	err := postJSONDecode(server.URL, "whkey_post_decode", "/v1/incidents/inc_1/evidence-export", map[string]string{"reason": "customer handoff"}, &decoded)
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer whkey_post_decode" {
		t.Fatalf("authorization header %q did not use the provided API key", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Fatalf("content-type=%q want application/json", gotContentType)
	}
	if gotBody != `{"reason":"customer handoff"}` {
		t.Fatalf("body=%s", gotBody)
	}
	if decoded.ID != "exp_1" {
		t.Fatalf("decoded export id=%q want exp_1", decoded.ID)
	}
}

func TestCLIResourceCommandsSendExpectedRequests(t *testing.T) {
	type request struct {
		method string
		path   string
		body   string
	}
	var seen []request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		path := r.URL.Path
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
		seen = append(seen, request{method: r.Method, path: path, body: string(body)})
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "client.pem")
	if err := os.WriteFile(certFile, []byte("test-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	operationsFile := filepath.Join(tempDir, "operations.json")
	if err := os.WriteFile(operationsFile, []byte(`[{"op":"redact","path":"/data/email"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	schemaFile := filepath.Join(tempDir, "schema.json")
	if err := os.WriteFile(schemaFile, []byte(`{"type":"object","required":["id"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	payloadFile := filepath.Join(tempDir, "payload.json")
	if err := os.WriteFile(payloadFile, []byte(`{"id":"evt_1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	newSchemaFile := filepath.Join(tempDir, "new-schema.json")
	if err := os.WriteFile(newSchemaFile, []byte(`{"type":"object","required":["id","type"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	adapterDefinitionFile := filepath.Join(tempDir, "adapter-definition.json")
	if err := os.WriteFile(adapterDefinitionFile, []byte(`{"name":"acme","provider":"generic-hmac"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vectorRequestFile := filepath.Join(tempDir, "vector-request.json")
	if err := os.WriteFile(vectorRequestFile, []byte(`{"headers":{"webhook-signature":"sha256:test"},"body":"{}"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vectorExpectedFile := filepath.Join(tempDir, "vector-expected.json")
	if err := os.WriteFile(vectorExpectedFile, []byte(`{"verified":false,"reason":"invalid_signature"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	common := []string{"--base-url", server.URL, "--api-key", "whkey_cli"}
	cases := []struct {
		name         string
		args         []string
		wantMethod   string
		wantPath     string
		bodyContains []string
	}{
		{
			name:         "sources create",
			args:         append([]string{"sources", "create", "--name", "Stripe", "--provider", "stripe", "--secret", "whsec_test"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/sources",
			bodyContains: []string{`"name":"Stripe"`, `"provider":"stripe"`, `"verification_secret":"whsec_test"`},
		},
		{
			name:       "sources list",
			args:       append([]string{"sources", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/sources",
		},
		{
			name:       "sources get",
			args:       append([]string{"sources", "get", "--source-id", "src_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/sources/src_1",
		},
		{
			name:         "sources update",
			args:         append([]string{"sources", "update", "--source-id", "src_1", "--name", "Stripe prod", "--state", "active", "--reason", "rename"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/sources/src_1",
			bodyContains: []string{`"name":"Stripe prod"`, `"state":"active"`, `"reason":"rename"`},
		},
		{
			name:         "sources delete",
			args:         append([]string{"sources", "delete", "--source-id", "src_1", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/sources/src_1",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "sources rotate secret",
			args:         append([]string{"sources", "rotate-secret", "--source-id", "src_1", "--secret", "whsec_next", "--grace-hours", "48", "--reason", "scheduled rotation"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/sources/src_1/secrets:rotate",
			bodyContains: []string{`"new_secret":"whsec_next"`, `"grace_period_hours":48`, `"reason":"scheduled rotation"`},
		},
		{
			name:       "events list",
			args:       append([]string{"events", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/events",
		},
		{
			name:       "events search",
			args:       append([]string{"events", "search", "--provider", "stripe", "--external-id", "evt_external", "--verification", "invalid", "--status", "dlq", "--received-after", "2026-06-04T10:00:00Z", "--route-id", "rte_1", "--delivery-id", "del_1", "--limit", "25"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/events?delivery_id=del_1&external_id=evt_external&limit=25&provider=stripe&received_after=2026-06-04T10%3A00%3A00Z&route_id=rte_1&status=dlq&verification=invalid",
		},
		{
			name:       "events get",
			args:       append([]string{"events", "get", "--event-id", "evt_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/events/evt_1",
		},
		{
			name:       "events normalized",
			args:       append([]string{"events", "normalized", "--event-id", "evt_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/events/evt_1/normalized",
		},
		{
			name:         "endpoints validate url",
			args:         append([]string{"endpoints", "validate-url", "--url", "https://receiver.example.com/hook"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/endpoints:validate-url",
			bodyContains: []string{`"url":"https://receiver.example.com/hook"`},
		},
		{
			name:       "endpoints list",
			args:       append([]string{"endpoints", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/endpoints",
		},
		{
			name:       "endpoints get",
			args:       append([]string{"endpoints", "get", "--endpoint-id", "end_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/endpoints/end_1",
		},
		{
			name:         "endpoints create",
			args:         append([]string{"endpoints", "create", "--name", "receiver", "--url", "https://receiver.example.com/hook", "--retry-policy-id", "rtp_1"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/endpoints",
			bodyContains: []string{`"name":"receiver"`, `"url":"https://receiver.example.com/hook"`, `"retry_policy_id":"rtp_1"`},
		},
		{
			name:         "endpoints update",
			args:         append([]string{"endpoints", "update", "--endpoint-id", "end_1", "--name", "receiver", "--url", "https://receiver.example.com/next", "--state", "active", "--retry-policy-id", "rtp_1", "--reason", "move"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/endpoints/end_1",
			bodyContains: []string{`"name":"receiver"`, `"url":"https://receiver.example.com/next"`, `"state":"active"`, `"retry_policy_id":"rtp_1"`, `"reason":"move"`},
		},
		{
			name:         "endpoints delete",
			args:         append([]string{"endpoints", "delete", "--endpoint-id", "end_1", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/endpoints/end_1",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "endpoints test",
			args:         append([]string{"endpoints", "test", "--endpoint-id", "end_1", "--reason", "probe"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/endpoints/end_1:test",
			bodyContains: []string{`"reason":"probe"`},
		},
		{
			name:         "endpoints rotate secret",
			args:         append([]string{"endpoints", "rotate-secret", "--endpoint-id", "end_1", "--grace-hours", "24", "--reason", "rotate"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/endpoints/end_1/secrets:rotate",
			bodyContains: []string{`"grace_period_hours":24`, `"reason":"rotate"`},
		},
		{
			name:         "subscriptions create",
			args:         append([]string{"subscriptions", "create", "--endpoint-id", "end_1", "--event-types", "invoice.created,customer.created", "--payload-format", "canonical_json"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/subscriptions",
			bodyContains: []string{`"endpoint_id":"end_1"`, `"event_types":["invoice.created","customer.created"]`, `"payload_format":"canonical_json"`},
		},
		{
			name:       "subscriptions list",
			args:       append([]string{"subscriptions", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/subscriptions",
		},
		{
			name:       "subscriptions get",
			args:       append([]string{"subscriptions", "get", "--subscription-id", "sub_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/subscriptions/sub_1",
		},
		{
			name:         "subscriptions update",
			args:         append([]string{"subscriptions", "update", "--subscription-id", "sub_1", "--endpoint-id", "end_2", "--event-types", "invoice.paid", "--payload-format", "raw", "--transformation-id", "trn_1", "--state", "disabled", "--reason", "pause"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/subscriptions/sub_1",
			bodyContains: []string{`"endpoint_id":"end_2"`, `"event_types":["invoice.paid"]`, `"payload_format":"raw"`, `"transformation_id":"trn_1"`, `"state":"disabled"`, `"reason":"pause"`},
		},
		{
			name:         "subscriptions delete",
			args:         append([]string{"subscriptions", "delete", "--subscription-id", "sub_1", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/subscriptions/sub_1",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "retry policy create",
			args:         append([]string{"retry-policies", "create", "--name", "standard", "--max-attempts", "4", "--initial-delay-seconds", "2", "--max-delay-seconds", "30"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/retry-policies",
			bodyContains: []string{`"name":"standard"`, `"max_attempts":4`, `"initial_delay_seconds":2`, `"max_delay_seconds":30`},
		},
		{
			name:       "retry policy list",
			args:       append([]string{"retry-policies", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/retry-policies",
		},
		{
			name:       "retry policy get",
			args:       append([]string{"retry-policies", "get", "--retry-policy-id", "rtp_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/retry-policies/rtp_1",
		},
		{
			name:         "retry policy update",
			args:         append([]string{"retry-policies", "update", "--retry-policy-id", "rtp_1", "--name", "fast", "--max-attempts", "2", "--max-duration-seconds", "600", "--initial-delay-seconds", "1", "--max-delay-seconds", "60", "--rate-limit-per-minute", "20", "--state", "active", "--reason", "tune"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/retry-policies/rtp_1",
			bodyContains: []string{`"name":"fast"`, `"max_attempts":2`, `"max_duration_seconds":600`, `"initial_delay_seconds":1`, `"max_delay_seconds":60`, `"rate_limit_per_minute":20`, `"state":"active"`, `"reason":"tune"`},
		},
		{
			name:         "retry policy delete",
			args:         append([]string{"retry-policies", "delete", "--retry-policy-id", "rtp_1", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/retry-policies/rtp_1",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "routes activate",
			args:         append([]string{"routes", "activate", "--route-id", "rte_1", "--reason", "ship"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/routes/rte_1:activate",
			bodyContains: []string{`"reason":"ship"`},
		},
		{
			name:       "routes list",
			args:       append([]string{"routes", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/routes",
		},
		{
			name:       "routes get",
			args:       append([]string{"routes", "get", "--route-id", "rte_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/routes/rte_1",
		},
		{
			name:         "routes create",
			args:         append([]string{"routes", "create", "--name", "paid", "--source-id", "src_1", "--endpoint-id", "end_1", "--event-types", "invoice.paid", "--priority", "10", "--retry-policy-id", "rtp_1", "--transformation-id", "trn_1", "--state", "draft"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/routes",
			bodyContains: []string{`"name":"paid"`, `"source_id":"src_1"`, `"endpoint_id":"end_1"`, `"event_types":["invoice.paid"]`, `"priority":10`, `"retry_policy_id":"rtp_1"`, `"transformation_id":"trn_1"`, `"state":"draft"`},
		},
		{
			name:         "routes update",
			args:         append([]string{"routes", "update", "--route-id", "rte_1", "--name", "paid prod", "--source-id", "src_1", "--endpoint-id", "end_2", "--event-types", "invoice.paid", "--priority", "20", "--retry-policy-id", "rtp_2", "--transformation-id", "trn_2", "--state", "active", "--reason", "promote"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/routes/rte_1",
			bodyContains: []string{`"name":"paid prod"`, `"source_id":"src_1"`, `"endpoint_id":"end_2"`, `"event_types":["invoice.paid"]`, `"priority":20`, `"retry_policy_id":"rtp_2"`, `"transformation_id":"trn_2"`, `"state":"active"`, `"reason":"promote"`},
		},
		{
			name:         "routes delete",
			args:         append([]string{"routes", "delete", "--route-id", "rte_1", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/routes/rte_1",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "routes dry run",
			args:         append([]string{"routes", "dry-run", "--route-id", "rte_1", "--event-id", "evt_1"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/routes/rte_1:dry-run",
			bodyContains: []string{`"event_id":"evt_1"`},
		},
		{
			name:       "routes versions",
			args:       append([]string{"routes", "versions", "--route-id", "rte_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/routes/rte_1/versions",
		},
		{
			name:         "replay create",
			args:         append([]string{"replay-jobs", "create", "--event-id", "evt_1", "--endpoint-id", "end_1", "--reason-code", "support_investigation", "--reason", "debug", "--require-approval", "--approval-expires-at", "2026-06-05T12:00:00Z"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/replay-jobs",
			bodyContains: []string{`"event_id":"evt_1"`, `"endpoint_id":"end_1"`, `"reason_code":"support_investigation"`, `"reason":"debug"`, `"require_approval":true`, `"approval_expires_at":"2026-06-05T12:00:00Z"`},
		},
		{
			name:       "replay list",
			args:       append([]string{"replay-jobs", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/replay-jobs",
		},
		{
			name:         "replay dry run",
			args:         append([]string{"replay-jobs", "dry-run", "--event-id", "evt_1", "--delivery-id", "del_1", "--endpoint-id", "end_1", "--reason-code", "support_investigation", "--reason", "inspect", "--config-mode", "original", "--rate-limit-per-minute", "30"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/replay-jobs:dry-run",
			bodyContains: []string{`"event_id":"evt_1"`, `"delivery_id":"del_1"`, `"endpoint_id":"end_1"`, `"reason_code":"support_investigation"`, `"reason":"inspect"`, `"config_mode":"original"`, `"rate_limit_per_minute":30`},
		},
		{
			name:         "replay preview",
			args:         append([]string{"replay-jobs", "preview", "--event-id", "evt_1", "--reason-code", "operator_requested", "--reason", "inspect"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/replay-jobs/preview",
			bodyContains: []string{`"event_id":"evt_1"`, `"reason_code":"operator_requested"`, `"reason":"inspect"`},
		},
		{
			name:         "replay approve",
			args:         append([]string{"replay-jobs", "approve", "--replay-job-id", "rpl_1", "--reason", "approved by security"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/replay-jobs/rpl_1:approve",
			bodyContains: []string{`"reason":"approved by security"`},
		},
		{
			name:         "replay pause",
			args:         append([]string{"replay-jobs", "pause", "--replay-job-id", "rpl_1", "--reason", "rate limiting"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/replay-jobs/rpl_1:pause",
			bodyContains: []string{`"reason":"rate limiting"`},
		},
		{
			name:         "replay resume",
			args:         append([]string{"replay-jobs", "resume", "--replay-job-id", "rpl_1", "--reason", "capacity restored"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/replay-jobs/rpl_1:resume",
			bodyContains: []string{`"reason":"capacity restored"`},
		},
		{
			name:         "replay cancel",
			args:         append([]string{"replay-jobs", "cancel", "--replay-job-id", "rpl_1", "--reason", "operator cancelled"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/replay-jobs/rpl_1:cancel",
			bodyContains: []string{`"reason":"operator cancelled"`},
		},
		{
			name:       "replay approval policy list",
			args:       append([]string{"replay-approval-policies", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/replay-approval-policies",
		},
		{
			name:         "replay approval policy create",
			args:         append([]string{"replay-approval-policies", "create", "--scope-type", "source", "--scope-id", "src_1", "--default-expiry-seconds", "3600", "--reason", "sensitive source"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/replay-approval-policies",
			bodyContains: []string{`"scope_type":"source"`, `"scope_id":"src_1"`, `"require_approval":true`, `"default_expiry_seconds":3600`, `"reason":"sensitive source"`},
		},
		{
			name:         "replay approval policy disable",
			args:         append([]string{"replay-approval-policies", "disable", "--policy-id", "rap_1", "--reason", "retire policy"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/replay-approval-policies/rap_1",
			bodyContains: []string{`"reason":"retire policy"`},
		},
		{
			name:       "alert firings filter",
			args:       append([]string{"alerts", "firings", "--state", "open"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/alert-firings?state=open",
		},
		{
			name:       "alert list",
			args:       append([]string{"alerts", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/alerts",
		},
		{
			name:         "alert create",
			args:         append([]string{"alerts", "create", "--name", "DLQ backlog", "--rule-type", "dead_letter_open", "--metric-name", "dead_letter.open", "--threshold", "5", "--comparator", ">=", "--window-seconds", "600", "--state", "active", "--channel-ids", "nch_1,nch_2"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/alerts",
			bodyContains: []string{`"name":"DLQ backlog"`, `"rule_type":"dead_letter_open"`, `"metric_name":"dead_letter.open"`, `"threshold":5`, `"comparator":"\u003e="`, `"window_seconds":600`, `"channel_ids":["nch_1","nch_2"]`},
		},
		{
			name:         "alert update",
			args:         append([]string{"alerts", "update", "--alert-id", "alr_1", "--name", "DLQ urgent", "--threshold", "10", "--comparator", ">", "--window-seconds", "300", "--state", "active", "--channel-ids", "nch_1", "--reason", "tune alert"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/alerts/alr_1",
			bodyContains: []string{`"name":"DLQ urgent"`, `"threshold":10`, `"comparator":"\u003e"`, `"window_seconds":300`, `"state":"active"`, `"channel_ids":["nch_1"]`, `"reason":"tune alert"`},
		},
		{
			name:         "alert disable",
			args:         append([]string{"alerts", "disable", "--alert-id", "alr_1", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/alerts/alr_1",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "alert acknowledge",
			args:         append([]string{"alerts", "ack", "--firing-id", "alf_1", "--reason", "investigating"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/alert-firings/alf_1:acknowledge",
			bodyContains: []string{`"reason":"investigating"`},
		},
		{
			name:       "ops metrics",
			args:       append([]string{"ops", "metrics"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/ops/metrics",
		},
		{
			name:       "ops rollups",
			args:       append([]string{"ops", "rollups"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/ops/metrics/rollups",
		},
		{
			name:       "ops storage",
			args:       append([]string{"ops", "storage"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/ops/storage",
		},
		{
			name:       "ops worker",
			args:       append([]string{"ops", "worker", "--worker-id", "wrk_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/ops/workers/wrk_1",
		},
		{
			name:       "ops queues",
			args:       append([]string{"ops", "queues"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/ops/queues",
		},
		{
			name:       "ops config",
			args:       append([]string{"ops", "config"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/ops/config",
		},
		{
			name:       "ops endpoint health",
			args:       append([]string{"ops", "endpoint-health"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/endpoint-health",
		},
		{
			name:       "ops workers",
			args:       append([]string{"ops", "workers"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/ops/workers",
		},
		{
			name:         "notification channel create",
			args:         append([]string{"notification-channels", "create", "--name", "PagerDuty", "--url", "https://signals.example.com/notify", "--signing-secret", "notify-secret"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/notification-channels",
			bodyContains: []string{`"name":"PagerDuty"`, `"channel_type":"webhook"`, `"url":"https://signals.example.com/notify"`, `"signing_secret":"notify-secret"`},
		},
		{
			name:       "notification channel list",
			args:       append([]string{"notification-channels", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/notification-channels",
		},
		{
			name:         "notification channel update",
			args:         append([]string{"notification-channels", "update", "--channel-id", "nch_1", "--name", "Ops", "--url", "https://signals.example.com/ops", "--signing-secret", "next-secret", "--state", "active", "--reason", "rotate"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/notification-channels/nch_1",
			bodyContains: []string{`"name":"Ops"`, `"url":"https://signals.example.com/ops"`, `"signing_secret":"next-secret"`, `"state":"active"`, `"reason":"rotate"`},
		},
		{
			name:         "notification channel disable",
			args:         append([]string{"notification-channels", "disable", "--channel-id", "nch_1", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/notification-channels/nch_1",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "notification channel test",
			args:         append([]string{"notification-channels", "test", "--channel-id", "nch_1", "--reason", "probe"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/notification-channels/nch_1:test",
			bodyContains: []string{`"reason":"probe"`},
		},
		{
			name:       "notification deliveries list",
			args:       append([]string{"notification-deliveries", "list", "--state", "scheduled"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/notification-deliveries?state=scheduled",
		},
		{
			name:       "notification delivery attempts",
			args:       append([]string{"notification-deliveries", "attempts", "--delivery-id", "ndl_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/notification-deliveries/ndl_1/attempts",
		},
		{
			name:         "notification delivery retry",
			args:         append([]string{"notification-deliveries", "retry", "--delivery-id", "ndl_1", "--reason", "receiver fixed"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/notification-deliveries/ndl_1:retry",
			bodyContains: []string{`"reason":"receiver fixed"`},
		},
		{
			name:         "schema event type update",
			args:         append([]string{"schemas", "event-type-update", "--name", "invoice.created", "--description", "updated", "--state", "active", "--reason", "docs"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/event-types/invoice.created",
			bodyContains: []string{`"description":"updated"`, `"state":"active"`, `"reason":"docs"`},
		},
		{
			name:         "schema event type create",
			args:         append([]string{"schemas", "event-type-create", "--name", "invoice.created", "--description", "Invoice created"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/event-types",
			bodyContains: []string{`"name":"invoice.created"`, `"description":"Invoice created"`},
		},
		{
			name:       "schema event type list",
			args:       append([]string{"schemas", "event-type-list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/event-types",
		},
		{
			name:       "schema event type get",
			args:       append([]string{"schemas", "event-type-get", "--name", "invoice.created"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/event-types/invoice.created",
		},
		{
			name:         "schema event type delete",
			args:         append([]string{"schemas", "event-type-delete", "--name", "invoice.created", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/event-types/invoice.created",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "schema create",
			args:         append([]string{"schemas", "schema-create", "--name", "invoice.created", "--version", "2026-06-01", "--schema-file", schemaFile}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/event-types/invoice.created/schemas",
			bodyContains: []string{`"version":"2026-06-01"`, `"schema":"{\"type\":\"object\",\"required\":[\"id\"]}"`},
		},
		{
			name:       "schema list",
			args:       append([]string{"schemas", "schema-list", "--name", "invoice.created"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/event-types/invoice.created/schemas",
		},
		{
			name:       "schema get",
			args:       append([]string{"schemas", "schema-get", "--name", "invoice.created", "--version", "2026-06-01"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/event-types/invoice.created/schemas/2026-06-01",
		},
		{
			name:         "schema update",
			args:         append([]string{"schemas", "schema-update", "--name", "invoice.created", "--version", "2026-06-01", "--state", "deprecated", "--reason", "superseded"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/event-types/invoice.created/schemas/2026-06-01",
			bodyContains: []string{`"state":"deprecated"`, `"reason":"superseded"`},
		},
		{
			name:         "schema delete",
			args:         append([]string{"schemas", "schema-delete", "--name", "invoice.created", "--version", "2026-06-01", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/event-types/invoice.created/schemas/2026-06-01",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "schema validate payload",
			args:         append([]string{"schemas", "validate", "--name", "invoice.created", "--version", "2026-06-01", "--payload-file", payloadFile}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/event-types/invoice.created/schemas/2026-06-01:validate",
			bodyContains: []string{`"payload":"{\"id\":\"evt_1\"}"`},
		},
		{
			name:         "schema compatibility check",
			args:         append([]string{"schemas", "check-compat", "--name", "invoice.created", "--version", "2026-06-01", "--new-schema-file", newSchemaFile}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/event-types/invoice.created/schemas/2026-06-01:check-compatibility",
			bodyContains: []string{`"new_schema":"{\"type\":\"object\",\"required\":[\"id\",\"type\"]}"`},
		},
		{
			name:       "adapter list",
			args:       append([]string{"adapters", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/adapters",
		},
		{
			name:       "adapter get",
			args:       append([]string{"adapters", "get", "--adapter-id", "adp_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/adapters/adp_1",
		},
		{
			name:         "adapter create",
			args:         append([]string{"adapters", "create", "--name", "acme", "--kind", "declarative", "--description", "ACME adapter", "--risk-level", "medium", "--provenance-url", "https://example.com/provenance"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/adapters",
			bodyContains: []string{`"name":"acme"`, `"kind":"declarative"`, `"description":"ACME adapter"`, `"risk_level":"medium"`, `"provenance_url":"https://example.com/provenance"`},
		},
		{
			name:       "adapter versions",
			args:       append([]string{"adapters", "versions", "--adapter-id", "adp_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/adapters/adp_1/versions",
		},
		{
			name:         "adapter version create",
			args:         append([]string{"adapters", "version-create", "--adapter-id", "adp_1", "--version", "2026-06-01", "--definition-file", adapterDefinitionFile, "--package-sha256", "sha256:pkg", "--package-signature", "sig", "--sbom-sha256", "sha256:sbom", "--provenance-url", "https://example.com/prov", "--risk-level", "high", "--reason", "upload"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/adapters/adp_1/versions",
			bodyContains: []string{`"version":"2026-06-01"`, `"definition":{"name":"acme","provider":"generic-hmac"}`, `"package_sha256":"sha256:pkg"`, `"package_signature":"sig"`, `"sbom_sha256":"sha256:sbom"`, `"risk_level":"high"`, `"reason":"upload"`},
		},
		{
			name:         "adapter vector create",
			args:         append([]string{"adapters", "vector-create", "--adapter-id", "adp_1", "--version-id", "adv_1", "--name", "invalid signature", "--request-file", vectorRequestFile, "--expected-file", vectorExpectedFile}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/adapters/adp_1/versions/adv_1/test-vectors",
			bodyContains: []string{`"name":"invalid signature"`, `"request":{"headers":{"webhook-signature":"sha256:test"},"body":"{}"}`, `"expected":{"verified":false,"reason":"invalid_signature"}`},
		},
		{
			name:         "adapter transition",
			args:         append([]string{"adapters", "transition", "--adapter-id", "adp_1", "--version-id", "adv_1", "--action", "approve", "--reason", "reviewed"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/adapters/adp_1/versions/adv_1:transition",
			bodyContains: []string{`"action":"approve"`, `"reason":"reviewed"`},
		},
		{
			name:         "transformation create",
			args:         append([]string{"transformations", "create", "--name", "redact-email", "--operations-file", operationsFile}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/transformations",
			bodyContains: []string{`"name":"redact-email"`, `"operations":[{"op":"redact","path":"/data/email"}]`},
		},
		{
			name:         "transformation version",
			args:         append([]string{"transformations", "version", "--transformation-id", "trn_1", "--operations-file", operationsFile}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/transformations/trn_1/versions",
			bodyContains: []string{`"operations":[{"op":"redact","path":"/data/email"}]`},
		},
		{
			name:         "transformation activate",
			args:         append([]string{"transformations", "activate", "--transformation-id", "trn_1", "--version-id", "trv_1", "--reason", "publish"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/transformations/trn_1/versions/trv_1:activate",
			bodyContains: []string{`"reason":"publish"`},
		},
		{
			name:       "transformation list",
			args:       append([]string{"transformations", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/transformations",
		},
		{
			name:         "api key create",
			args:         append([]string{"api-keys", "create", "--name", "operator", "--user-id", "usr_1", "--email", "ops@example.com", "--role", "operator", "--scopes", "events:read,deliveries:read"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/api-keys",
			bodyContains: []string{`"email":"ops@example.com"`, `"role":"operator"`, `"scopes":["events:read","deliveries:read"]`},
		},
		{
			name:       "api key list",
			args:       append([]string{"api-keys", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/api-keys",
		},
		{
			name:         "api key revoke",
			args:         append([]string{"api-keys", "revoke", "--key-id", "key_1", "--reason", "compromised"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/api-keys/key_1:revoke",
			bodyContains: []string{`"reason":"compromised"`},
		},
		{
			name:       "producer client list",
			args:       append([]string{"producer-clients", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/producer-clients",
		},
		{
			name:       "producer client get",
			args:       append([]string{"producer-clients", "get", "--client-id", "pcl_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/producer-clients/pcl_1",
		},
		{
			name:         "producer client create",
			args:         append([]string{"producer-clients", "create", "--name", "producer", "--source-id", "src_1", "--scopes", "events:write", "--token-ttl-seconds", "600"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/producer-clients",
			bodyContains: []string{`"name":"producer"`, `"source_id":"src_1"`, `"scopes":["events:write"]`, `"token_ttl_seconds":600`},
		},
		{
			name:         "producer client update",
			args:         append([]string{"producer-clients", "update", "--client-id", "pcl_1", "--name", "producer", "--source-id", "src_1", "--scopes", "events:write", "--token-ttl-seconds", "120", "--state", "active", "--reason", "rotate"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/producer-clients/pcl_1",
			bodyContains: []string{`"name":"producer"`, `"source_id":"src_1"`, `"token_ttl_seconds":120`, `"reason":"rotate"`},
		},
		{
			name:         "producer client disable",
			args:         append([]string{"producer-clients", "disable", "--client-id", "pcl_1", "--reason", "offboard"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/producer-clients/pcl_1",
			bodyContains: []string{`"reason":"offboard"`},
		},
		{
			name:         "producer client rotate secret",
			args:         append([]string{"producer-clients", "rotate-secret", "--client-id", "pcl_1", "--reason", "scheduled rotation"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/producer-clients/pcl_1/secrets:rotate",
			bodyContains: []string{`"reason":"scheduled rotation"`},
		},
		{
			name:       "producer mtls list",
			args:       append([]string{"producer-mtls-identities", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/producer-mtls-identities",
		},
		{
			name:       "producer mtls get",
			args:       append([]string{"producer-mtls-identities", "get", "--identity-id", "pmi_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/producer-mtls-identities/pmi_1",
		},
		{
			name:         "producer mtls create",
			args:         append([]string{"producer-mtls-identities", "create", "--name", "producer cert", "--source-id", "src_1", "--cert-file", certFile}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/producer-mtls-identities",
			bodyContains: []string{`"name":"producer cert"`, `"source_id":"src_1"`, `"certificate_pem":"test-cert"`},
		},
		{
			name:         "producer mtls update",
			args:         append([]string{"producer-mtls-identities", "update", "--identity-id", "pmi_1", "--name", "producer cert next", "--source-id", "src_2", "--state", "active", "--reason", "rename"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/producer-mtls-identities/pmi_1",
			bodyContains: []string{`"name":"producer cert next"`, `"source_id":"src_2"`, `"state":"active"`, `"reason":"rename"`},
		},
		{
			name:         "producer mtls disable",
			args:         append([]string{"producer-mtls-identities", "disable", "--identity-id", "pmi_1", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/producer-mtls-identities/pmi_1",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "producer mtls verify",
			args:         append([]string{"producer-mtls-identities", "verify", "--identity-id", "pmi_1", "--cert-file", certFile}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/producer-mtls-identities/pmi_1:verify",
			bodyContains: []string{`"certificate_pem":"test-cert"`},
		},
		{
			name:         "provider connection create",
			args:         append([]string{"provider-connections", "create", "--name", "Stripe prod", "--provider", "stripe", "--credential", "sk_test_secret", "--credential-type", "api_key", "--config", "source_id=src_1,region=eu"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/provider-connections",
			bodyContains: []string{`"name":"Stripe prod"`, `"provider":"stripe"`, `"credential":"sk_test_secret"`, `"credential_type":"api_key"`, `"source_id":"src_1"`, `"region":"eu"`},
		},
		{
			name:       "provider connection list",
			args:       append([]string{"provider-connections", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/provider-connections",
		},
		{
			name:       "provider connection get",
			args:       append([]string{"provider-connections", "get", "--connection-id", "pcn_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/provider-connections/pcn_1",
		},
		{
			name:         "provider connection verify",
			args:         append([]string{"provider-connections", "verify", "--connection-id", "pcn_1", "--reason", "validated"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/provider-connections/pcn_1:verify",
			bodyContains: []string{`"reason":"validated"`},
		},
		{
			name:         "provider connection revoke",
			args:         append([]string{"provider-connections", "revoke", "--connection-id", "pcn_1", "--reason", "offboard"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/provider-connections/pcn_1:revoke",
			bodyContains: []string{`"reason":"offboard"`},
		},
		{
			name:         "identity provider create",
			args:         append([]string{"identity-providers", "create", "--name", "OIDC", "--issuer-url", "https://issuer.example.com", "--client-id", "client", "--client-secret", "secret", "--allowed-email-domains", "example.com,ops.example.com"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/identity-providers",
			bodyContains: []string{`"name":"OIDC"`, `"issuer_url":"https://issuer.example.com"`, `"client_secret":"secret"`, `"allowed_email_domains":["example.com","ops.example.com"]`},
		},
		{
			name:       "identity provider list",
			args:       append([]string{"identity-providers", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/identity-providers",
		},
		{
			name:       "identity provider get",
			args:       append([]string{"identity-providers", "get", "--provider-id", "idp_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/identity-providers/idp_1",
		},
		{
			name:         "identity provider update",
			args:         append([]string{"identity-providers", "update", "--provider-id", "idp_1", "--name", "OIDC prod", "--issuer-url", "https://issuer.example.com", "--authorization-url", "https://issuer.example.com/auth", "--token-url", "https://issuer.example.com/token", "--jwks-url", "https://issuer.example.com/jwks", "--client-id", "client", "--client-secret", "secret", "--redirect-uri", "https://webhookery.example/callback", "--allowed-email-domains", "example.com", "--state", "active", "--reason", "refresh metadata"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/identity-providers/idp_1",
			bodyContains: []string{`"name":"OIDC prod"`, `"authorization_endpoint":"https://issuer.example.com/auth"`, `"token_endpoint":"https://issuer.example.com/token"`, `"jwks_uri":"https://issuer.example.com/jwks"`, `"redirect_uri":"https://webhookery.example/callback"`, `"state":"active"`, `"reason":"refresh metadata"`},
		},
		{
			name:         "identity provider disable",
			args:         append([]string{"identity-providers", "disable", "--provider-id", "idp_1", "--reason", "offboard"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/identity-providers/idp_1",
			bodyContains: []string{`"reason":"offboard"`},
		},
		{
			name:         "identity provider test",
			args:         append([]string{"identity-providers", "test", "--provider-id", "idp_1", "--reason", "preflight"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/identity-providers/idp_1:test",
			bodyContains: []string{`"reason":"preflight"`},
		},
		{
			name:       "scim token list",
			args:       append([]string{"scim-tokens", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/scim-tokens",
		},
		{
			name:         "scim token create",
			args:         append([]string{"scim-tokens", "create", "--name", "Okta SCIM"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/scim-tokens",
			bodyContains: []string{`"name":"Okta SCIM"`},
		},
		{
			name:         "scim token revoke",
			args:         append([]string{"scim-tokens", "revoke", "--token-id", "sct_1", "--reason", "compromised"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/scim-tokens/sct_1",
			bodyContains: []string{`"reason":"compromised"`},
		},
		{
			name:         "role binding create",
			args:         append([]string{"role-bindings", "create", "--principal-type", "group", "--principal-id", "scg_1", "--role", "security", "--resource-family", "events", "--resource-id", "*", "--environment", "prod", "--reason", "least privilege"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/role-bindings",
			bodyContains: []string{`"principal_type":"group"`, `"principal_id":"scg_1"`, `"role":"security"`, `"resource_family":"events"`, `"environment":"prod"`},
		},
		{
			name:       "role binding list",
			args:       append([]string{"role-bindings", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/role-bindings",
		},
		{
			name:         "role binding update",
			args:         append([]string{"role-bindings", "update", "--binding-id", "rb_1", "--role", "operator", "--resource-family", "deliveries", "--resource-id", "del_*", "--environment", "prod", "--state", "active", "--reason", "tighten scope"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/role-bindings/rb_1",
			bodyContains: []string{`"role":"operator"`, `"resource_family":"deliveries"`, `"resource_id":"del_*"`, `"environment":"prod"`, `"state":"active"`, `"reason":"tighten scope"`},
		},
		{
			name:         "role binding disable",
			args:         append([]string{"role-bindings", "disable", "--binding-id", "rb_1", "--reason", "offboard"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/role-bindings/rb_1",
			bodyContains: []string{`"reason":"offboard"`},
		},
		{
			name:         "access policy create",
			args:         append([]string{"access-policies", "create", "--name", "deny raw", "--action", "events:raw", "--effect", "deny", "--resource-family", "events", "--environment", "prod", "--conditions", `{"ip":"outside"}`, "--reason", "policy"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/access-policies",
			bodyContains: []string{`"name":"deny raw"`, `"action":"events:raw"`, `"effect":"deny"`, `"conditions":{"ip":"outside"}`},
		},
		{
			name:       "access policy list",
			args:       append([]string{"access-policies", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/access-policies",
		},
		{
			name:         "access policy update",
			args:         append([]string{"access-policies", "update", "--policy-id", "pol_1", "--name", "deny prod raw", "--action", "events:raw", "--effect", "deny", "--resource-family", "events", "--environment", "prod", "--conditions", `{"ip":"outside"}`, "--state", "active", "--reason", "tighten policy"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/access-policies/pol_1",
			bodyContains: []string{`"name":"deny prod raw"`, `"effect":"deny"`, `"state":"active"`, `"reason":"tighten policy"`},
		},
		{
			name:         "access policy disable",
			args:         append([]string{"access-policies", "disable", "--policy-id", "pol_1", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/access-policies/pol_1",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:         "authz explain",
			args:         append([]string{"authz", "explain", "--actor-id", "usr_1", "--action", "events:raw", "--resource-family", "events", "--resource-id", "evt_1", "--environment", "prod"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/authz:explain",
			bodyContains: []string{`"actor_id":"usr_1"`, `"action":"events:raw"`, `"resource_id":"evt_1"`, `"environment":"prod"`},
		},
		{
			name:         "siem sink test",
			args:         append([]string{"siem-sinks", "test", "--sink-id", "snk_1", "--reason", "probe"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/siem-sinks/snk_1:test",
			bodyContains: []string{`"reason":"probe"`},
		},
		{
			name:       "siem sink list",
			args:       append([]string{"siem-sinks", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/siem-sinks",
		},
		{
			name:         "siem sink create",
			args:         append([]string{"siem-sinks", "create", "--name", "Splunk", "--url", "https://signals.example.com/siem", "--signing-secret", "siem-secret"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/siem-sinks",
			bodyContains: []string{`"name":"Splunk"`, `"sink_type":"webhook"`, `"url":"https://signals.example.com/siem"`, `"signing_secret":"siem-secret"`},
		},
		{
			name:         "siem sink update",
			args:         append([]string{"siem-sinks", "update", "--sink-id", "snk_1", "--name", "Splunk prod", "--url", "https://signals.example.com/siem-prod", "--signing-secret", "next-siem-secret", "--state", "active", "--reason", "rotate"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/siem-sinks/snk_1",
			bodyContains: []string{`"name":"Splunk prod"`, `"url":"https://signals.example.com/siem-prod"`, `"signing_secret":"next-siem-secret"`, `"state":"active"`, `"reason":"rotate"`},
		},
		{
			name:         "siem sink disable",
			args:         append([]string{"siem-sinks", "disable", "--sink-id", "snk_1", "--reason", "retired"}, common...),
			wantMethod:   http.MethodDelete,
			wantPath:     "/v1/siem-sinks/snk_1",
			bodyContains: []string{`"reason":"retired"`},
		},
		{
			name:       "siem deliveries list",
			args:       append([]string{"siem-deliveries", "list", "--state", "scheduled"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/siem-deliveries?state=scheduled",
		},
		{
			name:       "siem delivery attempts",
			args:       append([]string{"siem-deliveries", "attempts", "--delivery-id", "sdl_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/siem-deliveries/sdl_1/attempts",
		},
		{
			name:         "siem delivery retry",
			args:         append([]string{"siem-deliveries", "retry", "--delivery-id", "sdl_1", "--reason", "receiver fixed"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/siem-deliveries/sdl_1:retry",
			bodyContains: []string{`"reason":"receiver fixed"`},
		},
		{
			name:         "audit export",
			args:         append([]string{"audit", "export", "--from", "2026-05-28T09:00:00Z", "--to", "2026-05-28T10:00:00Z", "--include-raw", "--include-payloads", "--include-timelines", "--reason", "evidence"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/audit-events:export",
			bodyContains: []string{`"from":"2026-05-28T09:00:00Z"`, `"to":"2026-05-28T10:00:00Z"`, `"include_raw_payloads":true`, `"include_payload_bodies":true`, `"include_timelines":true`},
		},
		{
			name:       "audit export status",
			args:       append([]string{"audit", "export-status", "--export-id", "exp_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/audit-exports/exp_1",
		},
		{
			name:       "audit chain head",
			args:       append([]string{"audit", "chain-head"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/audit-chain/head",
		},
		{
			name:         "audit verify chain",
			args:         append([]string{"audit", "verify-chain", "--from-sequence", "10", "--to-sequence", "20"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/audit-chain:verify",
			bodyContains: []string{`"from_sequence":10`, `"to_sequence":20`},
		},
		{
			name:         "audit anchor",
			args:         append([]string{"audit", "anchor", "--from-sequence", "10", "--to-sequence", "20", "--reason", "daily evidence"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/audit-chain:anchor",
			bodyContains: []string{`"from_sequence":10`, `"to_sequence":20`, `"reason":"daily evidence"`},
		},
		{
			name:       "audit anchors list",
			args:       append([]string{"audit", "anchors"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/audit-chain/anchors",
		},
		{
			name:       "audit anchor get",
			args:       append([]string{"audit", "anchors", "--anchor-id", "anc_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/audit-chain/anchors/anc_1",
		},
		{
			name:         "retention update clears legal hold",
			args:         append([]string{"retention", "update", "--policy-id", "ret_1", "--retention-days", "30", "--clear-legal-hold"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/admin/retention-policies/ret_1",
			bodyContains: []string{`"retention_days":30`, `"legal_hold":false`, `"hold_reason":""`},
		},
		{
			name:         "dead letter bulk release",
			args:         append([]string{"dead-letter", "bulk-release", "--entry-ids", "dlq_1,dlq_2", "--reason-code", "incident_recovery", "--reason", "recovered"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/dead-letter:bulk-release",
			bodyContains: []string{`"entry_ids":["dlq_1","dlq_2"]`, `"reason_code":"incident_recovery"`, `"reason":"recovered"`},
		},
		{
			name:       "delivery list",
			args:       append([]string{"deliveries", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/deliveries",
		},
		{
			name:       "delivery attempts",
			args:       append([]string{"deliveries", "attempts", "--delivery-id", "del_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/deliveries/del_1/attempts",
		},
		{
			name:         "delivery retry",
			args:         append([]string{"deliveries", "retry", "--delivery-id", "del_1", "--reason", "receiver fixed"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/deliveries/del_1:retry",
			bodyContains: []string{`"reason":"receiver fixed"`},
		},
		{
			name:         "delivery cancel",
			args:         append([]string{"deliveries", "cancel", "--delivery-id", "del_1", "--reason", "stop"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/deliveries/del_1:cancel",
			bodyContains: []string{`"reason":"stop"`},
		},
		{
			name:         "reconciliation dry run",
			args:         append([]string{"reconciliation-jobs", "dry-run", "--connection-id", "pcn_1", "--scope-object-id", "evt_external", "--from", "2026-05-28T09:00:00Z", "--to", "2026-05-28T10:00:00Z", "--redeliver-failed", "--reason", "compare provider"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/reconciliation-jobs:dry-run",
			bodyContains: []string{`"connection_id":"pcn_1"`, `"scope_object_id":"evt_external"`, `"window_start":"2026-05-28T09:00:00Z"`, `"window_end":"2026-05-28T10:00:00Z"`, `"redeliver_failed":true`, `"reason":"compare provider"`},
		},
		{
			name:       "reconciliation list",
			args:       append([]string{"reconciliation-jobs", "list"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/reconciliation-jobs",
		},
		{
			name:       "reconciliation get",
			args:       append([]string{"reconciliation-jobs", "get", "--job-id", "rec_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/reconciliation-jobs/rec_1",
		},
		{
			name:       "reconciliation items",
			args:       append([]string{"reconciliation-jobs", "items", "--job-id", "rec_1"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/reconciliation-jobs/rec_1/items",
		},
		{
			name:         "reconciliation create",
			args:         append([]string{"reconciliation-jobs", "create", "--connection-id", "pcn_1", "--capture-missing", "--route-recovered", "--reason", "recover missing"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/reconciliation-jobs",
			bodyContains: []string{`"connection_id":"pcn_1"`, `"capture_missing":true`, `"route_recovered":true`, `"reason":"recover missing"`},
		},
		{
			name:         "reconciliation cancel",
			args:         append([]string{"reconciliation-jobs", "cancel", "--job-id", "rec_1", "--reason", "stop"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/reconciliation-jobs/rec_1:cancel",
			bodyContains: []string{`"reason":"stop"`},
		},
		{
			name:         "quarantine approve",
			args:         append([]string{"quarantine", "approve", "--entry-id", "qua_1", "--route-after-release", "--reason", "verified"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/quarantine/qua_1:approve",
			bodyContains: []string{`"reason":"verified"`, `"route_after_release":true`},
		},
		{
			name:         "incident create",
			args:         append([]string{"incidents", "create", "--title", "Stripe payment webhook failed", "--reason", "support investigation"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/incidents",
			bodyContains: []string{`"title":"Stripe payment webhook failed"`, `"reason":"support investigation"`},
		},
		{
			name:         "incident add event",
			args:         append([]string{"incidents", "add-event", "--incident-id", "inc_1", "--event-id", "evt_1", "--reason", "attach failed payment"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/incidents/inc_1/events",
			bodyContains: []string{`"event_id":"evt_1"`, `"reason":"attach failed payment"`},
		},
		{
			name:         "incident generate report",
			args:         append([]string{"incidents", "generate-report", "--incident-id", "inc_1", "--reason", "handoff"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/incidents/inc_1/generate-report",
			bodyContains: []string{`"reason":"handoff"`},
		},
		{
			name:         "incident evidence export",
			args:         append([]string{"incidents", "export", "--incident-id", "inc_1", "--reason", "customer evidence"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/incidents/inc_1/evidence-export",
			bodyContains: []string{`"reason":"customer evidence"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen = nil
			if err := run(tc.args); err != nil {
				t.Fatal(err)
			}
			if len(seen) != 1 {
				t.Fatalf("expected one request, got %+v", seen)
			}
			got := seen[0]
			if got.method != tc.wantMethod || got.path != tc.wantPath {
				t.Fatalf("unexpected request: %+v", got)
			}
			if got.method != http.MethodGet && got.body == "" {
				t.Fatal("expected JSON body")
			}
			for _, needle := range tc.bodyContains {
				if !strings.Contains(got.body, needle) {
					t.Fatalf("request body %s did not contain %s", got.body, needle)
				}
			}
		})
	}
}

func TestDownloadIncidentReportRequiresValidInputsBeforeRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := downloadIncidentReport(server.URL, "whkey_test", " ", "markdown", "-"); err == nil || !strings.Contains(err.Error(), "incident-id is required") {
		t.Fatalf("expected missing incident id error, got %v", err)
	}
	if err := downloadIncidentReport(server.URL, "whkey_test", "inc_1", "html", "-"); err == nil || !strings.Contains(err.Error(), "format must be markdown or json") {
		t.Fatalf("expected invalid format error, got %v", err)
	}
	if called {
		t.Fatal("download request should not be sent when local validation fails")
	}
}

func TestDownloadIncidentReportWritesPrivateFileAndEscapesQuery(t *testing.T) {
	var gotAuth, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s want GET", r.Method)
		}
		if r.URL.Path != "/v1/incidents/inc_1/report" {
			t.Fatalf("path=%s want incident report path", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("# Incident Report\n"))
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "incident.md")
	if err := downloadIncidentReport(server.URL, "whkey_report", "inc_1", "MARKDOWN", output); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer whkey_report" {
		t.Fatalf("authorization header %q did not use the provided API key", gotAuth)
	}
	if gotQuery != "format=markdown" {
		t.Fatalf("query=%q want format=markdown", gotQuery)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "# Incident Report\n" {
		t.Fatalf("unexpected report body %q", string(body))
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions=%o want 0600", got)
	}
}

func TestDownloadIncidentReportCanWriteToStdout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("format") != "json" {
			t.Fatalf("format=%q want json", r.URL.Query().Get("format"))
		}
		_, _ = w.Write([]byte(`{"incident_id":"inc_1"}`))
	}))
	defer server.Close()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	err = downloadIncidentReport(server.URL, "whkey_report", "inc_1", "json", "-")
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"incident_id":"inc_1"}` {
		t.Fatalf("unexpected stdout body %q", string(body))
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

func TestDownloadAuditExportUsesDefaultPrivateOutputPath(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audit-exports/exp_default:download" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("default bundle"))
	}))
	defer server.Close()

	t.Chdir(t.TempDir())
	if err := downloadAuditExport(server.URL, "whkey_default", "exp_default", ""); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer whkey_default" {
		t.Fatalf("authorization header %q did not use the provided API key", gotAuth)
	}
	body, err := os.ReadFile("exp_default.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "default bundle" {
		t.Fatalf("unexpected default export body %q", string(body))
	}
	info, err := os.Stat("exp_default.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions=%o want 0600", got)
	}
}

func TestDownloadAuditExportProblemErrorRedactsDetailsAndDoesNotWriteFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"stable_code":"WEBHOOKERY_TENANT_ACCESS_DENIED","request_id":"req_export","detail":"tenant secret detail"}`))
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "blocked.tar.gz")
	err := downloadAuditExport(server.URL, "whkey_export_secret", "exp_1", output)
	if err == nil {
		t.Fatal("expected problem response")
	}
	got := err.Error()
	for _, want := range []string{"audit export download failed", "403", "WEBHOOKERY_TENANT_ACCESS_DENIED", "req_export"} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q did not contain %q", got, want)
		}
	}
	for _, forbidden := range []string{"whkey_export_secret", "tenant secret detail"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("error %q leaked %q", got, forbidden)
		}
	}
	if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("blocked export output should not exist, stat err=%v", statErr)
	}
}

func TestCreateAndDownloadIncidentExportCreatesThenDownloadsPrivateFile(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(body))
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/incidents/inc_1/evidence-export":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"exp_created"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/audit-exports/exp_created:download":
			_, _ = w.Write([]byte("evidence bundle"))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "incident-export.tar.gz")
	if err := createAndDownloadIncidentExport(server.URL, "whkey_incident_export", "inc_1", "customer evidence", output); err != nil {
		t.Fatal(err)
	}
	wantSeen := []string{
		`POST /v1/incidents/inc_1/evidence-export Bearer whkey_incident_export {"reason":"customer evidence"}`,
		`GET /v1/audit-exports/exp_created:download Bearer whkey_incident_export `,
	}
	if strings.Join(seen, "\n") != strings.Join(wantSeen, "\n") {
		t.Fatalf("unexpected request sequence:\ngot:\n%s\nwant:\n%s", strings.Join(seen, "\n"), strings.Join(wantSeen, "\n"))
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "evidence bundle" {
		t.Fatalf("unexpected export body %q", string(body))
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions=%o want 0600", got)
	}
}

func TestCreateAndDownloadIncidentExportRequiresReturnedID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/incidents/inc_1/evidence-export" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":" "}`))
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "incident-export.tar.gz")
	err := createAndDownloadIncidentExport(server.URL, "whkey_incident_export", "inc_1", "customer evidence", output)
	if err == nil || !strings.Contains(err.Error(), "did not include id") {
		t.Fatalf("expected missing export id error, got %v", err)
	}
	if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("output should not exist when export id is missing, stat err=%v", statErr)
	}
}

func TestProblemResponseErrorIncludesStableCodeAndRequestID(t *testing.T) {
	body := []byte(`{"code":"authorization_error","stable_code":"WEBHOOKERY_TENANT_ACCESS_DENIED","request_id":"req_cli","detail":"redacted detail"}`)
	err := problemResponseError("request failed", http.StatusForbidden, body)
	if err == nil {
		t.Fatal("expected problem response error")
	}
	got := err.Error()
	for _, want := range []string{"403", "WEBHOOKERY_TENANT_ACCESS_DENIED", "req_cli"} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q did not contain %q", got, want)
		}
	}
	for _, forbidden := range []string{"whkey_test", "redacted detail"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("error %q leaked %q", got, forbidden)
		}
	}
}

func TestProblemResponseErrorFallsBackWithoutLeakingBody(t *testing.T) {
	err := problemResponseError("request failed", http.StatusBadGateway, []byte(`{"code":"temporary_http","detail":"backend secret detail"}`))
	if err == nil {
		t.Fatal("expected problem response error")
	}
	got := err.Error()
	for _, want := range []string{"request failed", "502", "temporary_http"} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q did not contain %q", got, want)
		}
	}
	if strings.Contains(got, "backend secret detail") || strings.Contains(got, "request_id=") {
		t.Fatalf("fallback problem error leaked body detail or phantom request id: %q", got)
	}

	unknown := problemResponseError("request failed", http.StatusTeapot, []byte(`not-json-secret`))
	if unknown == nil || !strings.Contains(unknown.Error(), "unknown_error") || strings.Contains(unknown.Error(), "not-json-secret") {
		t.Fatalf("unexpected unknown problem error: %v", unknown)
	}
}

func TestExportRawPayloadDecodesBase64ToPrivateFile(t *testing.T) {
	rawBody := []byte("raw evidence bytes")
	var gotAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events/evt_1/raw" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("reason"); got != "support case" {
			t.Fatalf("unexpected raw export reason %q", got)
		}
		gotAuthorization = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{"body_base64": base64.StdEncoding.EncodeToString(rawBody)})
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "raw.bin")
	if err := exportRawPayload(server.URL, "whkey_tenant_scoped", "evt_1", "support case", output); err != nil {
		t.Fatal(err)
	}
	if gotAuthorization != "Bearer whkey_tenant_scoped" {
		t.Fatalf("authorization header %q did not use the scoped key", gotAuthorization)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, rawBody) {
		t.Fatalf("unexpected raw body %q", string(body))
	}
}

func TestExportRawPayloadRequiresReasonBeforeRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "raw.bin")
	err := exportRawPayload(server.URL, "whkey_test", "evt_1", " ", output)
	if err == nil || !strings.Contains(err.Error(), "reason is required") {
		t.Fatalf("expected missing reason error, got %v", err)
	}
	if called {
		t.Fatal("raw payload export request was sent without a reason")
	}
	if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("raw output should not be created without a reason, stat err=%v", statErr)
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

func TestServerTLSConfigLoadsProducerMTLSClientCA(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, testCertificatePEM(t, "Webhookery Producer CA"), 0o600); err != nil {
		t.Fatal(err)
	}

	tlsConfig, err := serverTLSConfig(config.Config{
		TLSCertFile:              "server.crt",
		ProducerMTLSClientCAFile: caPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig == nil || tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2+ config, got %+v", tlsConfig)
	}
	if tlsConfig.ClientAuth != tls.VerifyClientCertIfGiven || tlsConfig.ClientCAs == nil {
		t.Fatalf("expected producer mTLS client CA verification config, got %+v", tlsConfig)
	}
}

func TestServerTLSConfigRejectsInvalidProducerMTLSClientCA(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := serverTLSConfig(config.Config{ProducerMTLSClientCAFile: caPath}); err == nil || !strings.Contains(err.Error(), "did not contain certificates") {
		t.Fatalf("expected invalid producer mTLS CA error, got %v", err)
	}
}

func TestServerTLSConfigReturnsNilWhenTLSAndProducerMTLSDisabled(t *testing.T) {
	tlsConfig, err := serverTLSConfig(config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig != nil {
		t.Fatalf("expected nil TLS config when TLS is disabled, got %+v", tlsConfig)
	}
}

func TestOpsRuntimeConfigReflectsRedactedSecurityState(t *testing.T) {
	cfg := config.Config{
		Environment:    "production",
		EnableUI:       true,
		RawStorageMode: "s3",
		SecretBoxMode:  "aws-kms",
		AWSKMSKeyID:    "arn:aws:kms:us-east-1:123456789012:key/secret-key-id",
	}

	ops := opsRuntimeConfig(cfg)
	if ops.Environment != "production" || !ops.UIEnabled || ops.RawStorageMode != "s3" || !ops.ObjectStorageConfigured {
		t.Fatalf("unexpected ops runtime config: %+v", ops)
	}
	if !ops.KeyCustodyConfigured || ops.SecretBoxMode != "aws-kms" || !strings.HasPrefix(ops.KeyCustodyKeyRef, "sha256:") {
		t.Fatalf("expected redacted key custody metadata, got %+v", ops)
	}
	for _, forbidden := range []string{"secret-key-id", "123456789012"} {
		if strings.Contains(ops.KeyCustodyKeyRef, forbidden) {
			t.Fatalf("key custody ref leaked key material %q in %q", forbidden, ops.KeyCustodyKeyRef)
		}
	}
}

func TestRuntimeAuthFallsBackToBootstrapAfterDatabaseAuthFails(t *testing.T) {
	lookup := runtimeAPIKeyLookup{err: apppkg.ErrUnauthorized}
	authn := runtimeAuth(config.Config{
		BootstrapTenantID:   "ten_bootstrap",
		BootstrapAPIKeyHash: apppkg.HashToken("bootstrap-secret"),
	}, &lookup)

	actor, err := authn.Authenticate(context.Background(), "bootstrap-secret")
	if err != nil {
		t.Fatal(err)
	}
	if actor.ID != "bootstrap" || actor.TenantID != "ten_bootstrap" || actor.Role != authz.RoleOwner {
		t.Fatalf("unexpected bootstrap actor: %+v", actor)
	}
}

func TestRuntimeAuthPrefersDatabaseAPIKey(t *testing.T) {
	lookup := runtimeAPIKeyLookup{actor: authz.Actor{ID: "usr_db", TenantID: "ten_db", Role: authz.RoleOperator}}
	authn := runtimeAuth(config.Config{
		BootstrapTenantID:   "ten_bootstrap",
		BootstrapAPIKeyHash: apppkg.HashToken("bootstrap-secret"),
	}, &lookup)

	actor, err := authn.Authenticate(context.Background(), "database-token")
	if err != nil {
		t.Fatal(err)
	}
	if actor.ID != "usr_db" || lookup.hash == "" {
		t.Fatalf("expected database actor and hashed lookup token, actor=%+v hash=%q", actor, lookup.hash)
	}
}

func TestReadMTLSFilesRequiresBothFiles(t *testing.T) {
	if _, _, err := readMTLSFiles("client.crt", ""); err == nil {
		t.Fatal("expected mTLS file pair validation")
	}
}

func TestReadMTLSFilesReadsBothFilesAndReportsKeyFailure(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, []byte("cert-pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("key-pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, key, err := readMTLSFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if cert != "cert-pem" || key != "key-pem" {
		t.Fatalf("unexpected mTLS file contents cert=%q key=%q", cert, key)
	}
	if _, _, err := readMTLSFiles(certPath, filepath.Join(dir, "missing.key")); err == nil || !strings.Contains(err.Error(), "read mTLS client key") {
		t.Fatalf("expected key read context, got %v", err)
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

func TestReadSmallFileRejectsInvalidPath(t *testing.T) {
	if _, err := readSmallFile(" ", 64); err == nil {
		t.Fatal("expected blank path rejection")
	}
	if _, err := readSmallFile("bad\x00path", 64); err == nil {
		t.Fatal("expected NUL path rejection")
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

func TestSecretBoxFromConfigAcceptsLocalEnvelope(t *testing.T) {
	box, err := secretBoxFromConfig(context.Background(), config.Config{
		SecretBoxMode:   "local",
		MasterKeyBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if box == nil {
		t.Fatal("expected local envelope secret box")
	}
}

func TestSecretBoxFromConfigAcceptsAWSKMSWithoutPrintingKeyMaterial(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	box, err := secretBoxFromConfig(context.Background(), config.Config{
		SecretBoxMode:   "aws-kms",
		AWSRegion:       "us-east-1",
		AWSKMSKeyID:     "arn:aws:kms:us-east-1:123456789012:key/secret-key-id",
		AWSKMSEndpoint:  "http://localhost:4566",
		MasterKeyBase64: "ignored",
	})
	if err != nil {
		t.Fatal(err)
	}
	if box == nil {
		t.Fatal("expected aws kms envelope secret box")
	}
}

func TestSecretBoxFromConfigRejectsInvalidLocalEnvelopeKey(t *testing.T) {
	_, err := secretBoxFromConfig(context.Background(), config.Config{SecretBoxMode: "local", MasterKeyBase64: "not-base64"})
	if err == nil {
		t.Fatal("expected invalid local envelope key")
	}
}

func TestSecretBoxFromConfigRejectsUnsupportedMode(t *testing.T) {
	_, err := secretBoxFromConfig(context.Background(), config.Config{SecretBoxMode: "plaintext"})
	if err == nil || !strings.Contains(err.Error(), "unsupported secret box mode") {
		t.Fatalf("expected unsupported secret box mode error, got %v", err)
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

type runtimeAPIKeyLookup struct {
	actor authz.Actor
	err   error
	hash  string
}

func (f *runtimeAPIKeyLookup) AuthenticateAPIKey(_ context.Context, hash string) (authz.Actor, error) {
	f.hash = hash
	if f.err != nil {
		return authz.Actor{}, f.err
	}
	return f.actor, nil
}

func testCertificatePEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
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

func TestDoctorSecretBoxFindingsCoverCustodyModes(t *testing.T) {
	validLocalKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	tests := []struct {
		name       string
		env        map[string]string
		production bool
		want       doctorFinding
	}{
		{
			name: "local missing key",
			env:  map[string]string{"WEBHOOKERY_SECRET_BOX_MODE": "local"},
			want: doctorFinding{Severity: "blocker", Check: "secret-box", Message: "requires WEBHOOKERY_MASTER_KEY_BASE64"},
		},
		{
			name: "local production warning",
			env: map[string]string{
				"WEBHOOKERY_SECRET_BOX_MODE":   "local",
				"WEBHOOKERY_MASTER_KEY_BASE64": validLocalKey,
			},
			production: true,
			want:       doctorFinding{Severity: "warning", Check: "secret-box", Message: "prefer Vault Transit"},
		},
		{
			name: "vault missing config",
			env:  map[string]string{"WEBHOOKERY_SECRET_BOX_MODE": "vault-transit", "WEBHOOKERY_VAULT_ADDR": "https://vault.internal"},
			want: doctorFinding{Severity: "blocker", Check: "secret-box", Message: "Vault Transit mode requires"},
		},
		{
			name: "aws missing config",
			env:  map[string]string{"WEBHOOKERY_SECRET_BOX_MODE": "aws-kms", "WEBHOOKERY_AWS_REGION": "us-east-1"},
			want: doctorFinding{Severity: "blocker", Check: "secret-box", Message: "AWS KMS mode requires"},
		},
		{
			name: "aws local endpoint warning plus ok",
			env: map[string]string{
				"WEBHOOKERY_SECRET_BOX_MODE":    "aws-kms",
				"WEBHOOKERY_AWS_REGION":         "us-east-1",
				"WEBHOOKERY_AWS_KMS_KEY_ID":     "arn:aws:kms:us-east-1:123456789012:key/secret-key-id",
				"WEBHOOKERY_AWS_KMS_ENDPOINT":   "http://localhost:4566",
				"WEBHOOKERY_MASTER_KEY_BASE64":  "ignored",
				"WEBHOOKERY_DATABASE_URL":       "postgres://ignored",
				"WEBHOOKERY_OBJECT_STORAGE_KEY": "ignored",
			},
			want: doctorFinding{Severity: "ok", Check: "secret-box", Message: "AWS KMS secret box"},
		},
		{
			name: "unsupported mode",
			env:  map[string]string{"WEBHOOKERY_SECRET_BOX_MODE": "plaintext"},
			want: doctorFinding{Severity: "blocker", Check: "secret-box", Message: "must be local, vault-transit, or aws-kms"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var findings []doctorFinding
			addSecretBoxFindings(func(severity, check, message string) {
				findings = append(findings, doctorFinding{Severity: severity, Check: check, Message: message})
			}, func(name string) string {
				return tt.env[name]
			}, tt.production)
			finding := requireDoctorFinding(t, findings, tt.want.Check)
			if finding.Severity != tt.want.Severity || !strings.Contains(finding.Message, tt.want.Message) {
				t.Fatalf("unexpected secret box finding: %+v want %+v all=%+v", finding, tt.want, findings)
			}
			var out bytes.Buffer
			writeDoctorFindings(&out, findings)
			for _, forbidden := range []string{"secret-key-id", "123456789012", validLocalKey} {
				if strings.Contains(out.String(), forbidden) {
					t.Fatalf("secret box finding leaked sensitive value %q in %s", forbidden, out.String())
				}
			}
		})
	}
}

func TestDoctorRawStorageFindingsCoverObjectStorageModes(t *testing.T) {
	tests := []struct {
		name       string
		env        map[string]string
		production bool
		want       doctorFinding
	}{
		{
			name: "postgres default",
			env:  map[string]string{},
			want: doctorFinding{Severity: "ok", Check: "raw-storage", Message: "PostgreSQL raw payload storage"},
		},
		{
			name: "s3 missing config",
			env:  map[string]string{"WEBHOOKERY_RAW_STORAGE_MODE": "s3", "WEBHOOKERY_OBJECT_STORAGE_ENDPOINT": "s3.internal"},
			want: doctorFinding{Severity: "blocker", Check: "raw-storage", Message: "S3 raw storage requires"},
		},
		{
			name: "s3 placeholder credentials",
			env: map[string]string{
				"WEBHOOKERY_RAW_STORAGE_MODE":          "s3",
				"WEBHOOKERY_OBJECT_STORAGE_ENDPOINT":   "s3.internal",
				"WEBHOOKERY_OBJECT_STORAGE_BUCKET":     "webhookery",
				"WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY": "change-me",
				"WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY": "secret",
			},
			want: doctorFinding{Severity: "blocker", Check: "raw-storage", Message: "placeholder"},
		},
		{
			name: "s3 production tls disabled",
			env: map[string]string{
				"WEBHOOKERY_RAW_STORAGE_MODE":          "s3",
				"WEBHOOKERY_OBJECT_STORAGE_ENDPOINT":   "s3.internal",
				"WEBHOOKERY_OBJECT_STORAGE_BUCKET":     "webhookery",
				"WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY": "access",
				"WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY": "secret",
				"WEBHOOKERY_OBJECT_STORAGE_USE_SSL":    "false",
			},
			production: true,
			want:       doctorFinding{Severity: "blocker", Check: "raw-storage", Message: "must use TLS"},
		},
		{
			name: "s3 pilot tls disabled warning",
			env: map[string]string{
				"WEBHOOKERY_RAW_STORAGE_MODE":          "s3",
				"WEBHOOKERY_OBJECT_STORAGE_ENDPOINT":   "s3.internal",
				"WEBHOOKERY_OBJECT_STORAGE_BUCKET":     "webhookery",
				"WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY": "access",
				"WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY": "secret",
				"WEBHOOKERY_OBJECT_STORAGE_USE_SSL":    "false",
			},
			want: doctorFinding{Severity: "warning", Check: "raw-storage", Message: "TLS disabled"},
		},
		{
			name: "unsupported mode",
			env:  map[string]string{"WEBHOOKERY_RAW_STORAGE_MODE": "filesystem"},
			want: doctorFinding{Severity: "blocker", Check: "raw-storage", Message: "must be postgres or s3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var findings []doctorFinding
			addRawStorageFindings(func(severity, check, message string) {
				findings = append(findings, doctorFinding{Severity: severity, Check: check, Message: message})
			}, func(name string) string {
				return tt.env[name]
			}, tt.production)
			finding := requireDoctorFinding(t, findings, tt.want.Check)
			if finding.Severity != tt.want.Severity || !strings.Contains(finding.Message, tt.want.Message) {
				t.Fatalf("unexpected raw storage finding: %+v want %+v all=%+v", finding, tt.want, findings)
			}
			var out bytes.Buffer
			writeDoctorFindings(&out, findings)
			for _, forbidden := range []string{
				tt.env["WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY"],
				tt.env["WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY"],
			} {
				if forbidden != "" && strings.Contains(out.String(), forbidden) {
					t.Fatalf("raw storage finding leaked object storage credential value %q in %s", forbidden, out.String())
				}
			}
		})
	}
}

func TestProviderProofFindingCoversManifestStates(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")
	invalid := filepath.Join(dir, "invalid.json")
	empty := filepath.Join(dir, "empty.json")
	valid := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(invalid, []byte(`{"schema_version":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(empty, []byte(`{"schema_version":"provider-proof-v1","no_live_provider_calls":true,"proofs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valid, []byte(`{"schema_version":"provider-proof-v1","no_live_provider_calls":true,"proofs":[{"provider":"stripe"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		path     string
		severity string
		message  string
	}{
		{name: "missing", path: missing, severity: "warning", message: "not found"},
		{name: "invalid", path: invalid, severity: "warning", message: "not valid"},
		{name: "empty", path: empty, severity: "warning", message: "no provider proof entries"},
		{name: "valid", path: valid, severity: "ok", message: "metadata is present"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var findings []doctorFinding
			addProviderProofFinding(func(severity, check, message string) {
				findings = append(findings, doctorFinding{Severity: severity, Check: check, Message: message})
			}, func(name string) string {
				if name == "WEBHOOKERY_PROVIDER_PROOF_MANIFEST_PATH" {
					return tt.path
				}
				return ""
			})
			finding := requireDoctorFinding(t, findings, "provider-proof")
			if finding.Severity != tt.severity || !strings.Contains(finding.Message, tt.message) {
				t.Fatalf("unexpected finding for %s: %+v", tt.name, finding)
			}
		})
	}
}

func TestPilotDatabaseFindingsCoverReadinessBranches(t *testing.T) {
	tests := []struct {
		name   string
		status pilotDatabaseStatus
		want   []string
	}{
		{
			name: "empty repository metadata and work warnings",
			status: pilotDatabaseStatus{
				ExpectedMigrations: 0,
				PendingOutbox:      2,
				InProgressOutbox:   1,
			},
			want: []string{
				"ok:database-connectivity",
				"warning:migrations",
				"warning:queue",
				"warning:retention",
				"warning:audit-chain",
			},
		},
		{
			name: "database behind repository",
			status: pilotDatabaseStatus{
				AppliedMigrations:  2,
				ExpectedMigrations: 3,
				RetentionPolicies:  1,
				AuditChainEntries:  1,
			},
			want: []string{"blocker:migrations", "ok:queue", "ok:retention", "ok:audit-chain"},
		},
		{
			name: "database ahead of repository",
			status: pilotDatabaseStatus{
				AppliedMigrations:  4,
				ExpectedMigrations: 3,
				RetentionPolicies:  1,
				AuditChainEntries:  1,
			},
			want: []string{"blocker:migrations", "ok:queue", "ok:retention", "ok:audit-chain"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var findings []doctorFinding
			addPilotDatabaseFindings(func(severity, check, message string) {
				findings = append(findings, doctorFinding{Severity: severity, Check: check, Message: message})
			}, tt.status)
			for _, want := range tt.want {
				parts := strings.SplitN(want, ":", 2)
				finding := requireDoctorFinding(t, findings, parts[1])
				if finding.Severity != parts[0] {
					t.Fatalf("finding %s severity=%s want %s in %+v", parts[1], finding.Severity, parts[0], findings)
				}
			}
		})
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

func TestRunDoctorUsageAndProductionSuccess(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"production", "extra"},
		{"unknown"},
	} {
		if err := runDoctor(args); err == nil || !strings.Contains(err.Error(), "usage: whcp doctor") {
			t.Fatalf("expected doctor usage for args %+v, got %v", args, err)
		}
	}
	if err := runPilotDoctor([]string{"extra"}); err == nil || !strings.Contains(err.Error(), "usage: whcp doctor pilot") {
		t.Fatalf("expected pilot usage, got %v", err)
	}

	t.Setenv("WEBHOOKERY_ENVIRONMENT", "production")
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://webhookery@db.internal/webhookery?sslmode=require")
	t.Setenv("WEBHOOKERY_TLS_CERT_FILE", "/etc/webhookery/tls.crt")
	t.Setenv("WEBHOOKERY_TLS_KEY_FILE", "/etc/webhookery/tls.key")
	t.Setenv("WEBHOOKERY_SECRET_BOX_MODE", "local")
	t.Setenv("WEBHOOKERY_MASTER_KEY_BASE64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	t.Setenv("WEBHOOKERY_RAW_STORAGE_MODE", "postgres")

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	err = runDoctor([]string{"production"})
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	output := string(body)
	for _, want := range []string{"ok: environment", "ok: database", "ok: tls", "ok: raw-storage"} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected %q in production doctor output:\n%s", want, output)
		}
	}
	if strings.Contains(output, os.Getenv("WEBHOOKERY_DATABASE_URL")) || strings.Contains(output, os.Getenv("WEBHOOKERY_MASTER_KEY_BASE64")) {
		t.Fatalf("production doctor success leaked configured secret material: %s", output)
	}
}

func TestPilotDoctorNoNetworkSkipsConnectivityAndRedactsValues(t *testing.T) {
	env := map[string]string{
		"WEBHOOKERY_ENVIRONMENT":                   "production",
		"WEBHOOKERY_DATABASE_URL":                  "postgres://webhookery:secret-db-password@db/webhookery?sslmode=require",
		"WEBHOOKERY_SECRET_BOX_MODE":               "local",
		"WEBHOOKERY_MASTER_KEY_BASE64":             "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
		"WEBHOOKERY_RAW_STORAGE_MODE":              "postgres",
		"WEBHOOKERY_PILOT_RECEIVER_CHECK_URL":      "https://receiver.example.test/webhook?token=secret",
		"WEBHOOKERY_PILOT_ALLOW_RECEIVER_CHECK":    "true",
		"WEBHOOKERY_STRIPE_WEBHOOK_SECRET":         "stripe-secret-marker",
		"WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY":     "object-secret-password",
		"WEBHOOKERY_BOOTSTRAP_API_KEY_HASH":        "sha256:bootstrap-secret-hash",
		"WEBHOOKERY_BOOTSTRAP_API_KEY_PREFIX":      "live",
		"WEBHOOKERY_PROVIDER_PROOF_MANIFEST_PATH":  "docs/provider-proof-manifest.json",
		"WEBHOOKERY_PROVIDER_CONFORMANCE_MANIFEST": "docs/provider-conformance.manifest.json",
	}
	calledDB := false
	calledReceiver := false
	findings := pilotDoctorFindings(func(name string) string { return env[name] }, pilotDoctorOptions{
		Network: false,
		DBCheck: func(_ context.Context, _ string, _ time.Duration) (pilotDatabaseStatus, error) {
			calledDB = true
			return pilotDatabaseStatus{}, nil
		},
		ReceiverCheck: func(_ context.Context, _ string, _ time.Duration) error {
			calledReceiver = true
			return nil
		},
	})
	if calledDB || calledReceiver {
		t.Fatalf("no-network pilot doctor called network checks: db=%t receiver=%t", calledDB, calledReceiver)
	}
	var out bytes.Buffer
	writeDoctorFindings(&out, findings)
	body := out.String()
	for _, want := range []string{"warning: database-connectivity", "warning: receiver-connectivity"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected %q in pilot doctor output:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"secret-db-password", "token=secret", "stripe-secret-marker", "object-secret-password", env["WEBHOOKERY_DATABASE_URL"]} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("pilot doctor output leaked sensitive value %q in %s", forbidden, body)
		}
	}
}

func TestPilotDoctorReportsDatabaseReadiness(t *testing.T) {
	env := map[string]string{
		"WEBHOOKERY_ENVIRONMENT":                  "production",
		"WEBHOOKERY_DATABASE_URL":                 "postgres://webhookery@db/webhookery?sslmode=require",
		"WEBHOOKERY_SECRET_BOX_MODE":              "vault-transit",
		"WEBHOOKERY_VAULT_ADDR":                   "https://vault.internal",
		"WEBHOOKERY_VAULT_TOKEN":                  "vault-token",
		"WEBHOOKERY_VAULT_TRANSIT_KEY":            "webhookery",
		"WEBHOOKERY_RAW_STORAGE_MODE":             "postgres",
		"WEBHOOKERY_BOOTSTRAP_API_KEY_HASH":       "",
		"WEBHOOKERY_PROVIDER_PROOF_MANIFEST_PATH": "docs/provider-proof-manifest.json",
	}
	findings := pilotDoctorFindings(func(name string) string { return env[name] }, pilotDoctorOptions{
		Network: true,
		DBCheck: func(_ context.Context, databaseURL string, _ time.Duration) (pilotDatabaseStatus, error) {
			if databaseURL != env["WEBHOOKERY_DATABASE_URL"] {
				t.Fatalf("unexpected database url %q", databaseURL)
			}
			return pilotDatabaseStatus{
				AppliedMigrations:  3,
				ExpectedMigrations: 3,
				PendingOutbox:      0,
				InProgressOutbox:   0,
				RetentionPolicies:  1,
				AuditChainEntries:  4,
			}, nil
		},
	})
	if blockers := countDoctorBlockers(findings); blockers != 0 {
		t.Fatalf("expected no pilot doctor blockers, got %d: %+v", blockers, findings)
	}
	var out bytes.Buffer
	writeDoctorFindings(&out, findings)
	body := out.String()
	for _, want := range []string{"ok: database-connectivity", "ok: migrations", "ok: queue", "ok: retention", "ok: audit-chain"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected %q in pilot doctor output:\n%s", want, body)
		}
	}
}

func TestReceiverConnectivityFindingCoversNetworkOutcomesAndRedactsErrors(t *testing.T) {
	baseEnv := map[string]string{
		"WEBHOOKERY_PILOT_RECEIVER_CHECK_URL":   "https://receiver.example.test/webhook?token=secret-token",
		"WEBHOOKERY_PILOT_ALLOW_RECEIVER_CHECK": "true",
	}
	tests := []struct {
		name     string
		env      map[string]string
		network  bool
		checkErr error
		want     doctorFinding
	}{
		{
			name:    "missing url",
			env:     map[string]string{},
			network: true,
			want:    doctorFinding{Severity: "warning", Check: "receiver-connectivity", Message: "not configured"},
		},
		{
			name:    "allow flag missing",
			env:     map[string]string{"WEBHOOKERY_PILOT_RECEIVER_CHECK_URL": baseEnv["WEBHOOKERY_PILOT_RECEIVER_CHECK_URL"]},
			network: true,
			want:    doctorFinding{Severity: "warning", Check: "receiver-connectivity", Message: "WEBHOOKERY_PILOT_ALLOW_RECEIVER_CHECK=true is required"},
		},
		{
			name:    "network skipped",
			env:     baseEnv,
			network: false,
			want:    doctorFinding{Severity: "warning", Check: "receiver-connectivity", Message: "skipped"},
		},
		{
			name:     "ssrf policy failure",
			env:      baseEnv,
			network:  true,
			checkErr: ssrf.PolicyError{Reasons: []string{"loopback address blocked"}},
			want:     doctorFinding{Severity: "blocker", Check: "receiver-connectivity", Message: "SSRF policy"},
		},
		{
			name:     "generic receiver failure",
			env:      baseEnv,
			network:  true,
			checkErr: errors.New("dial failed with secret-token"),
			want:     doctorFinding{Severity: "warning", Check: "receiver-connectivity", Message: "connectivity check failed"},
		},
		{
			name:    "success",
			env:     baseEnv,
			network: true,
			want:    doctorFinding{Severity: "ok", Check: "receiver-connectivity", Message: "succeeded"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var findings []doctorFinding
			called := false
			addReceiverConnectivityFinding(func(severity, check, message string) {
				findings = append(findings, doctorFinding{Severity: severity, Check: check, Message: message})
			}, func(name string) string {
				return tt.env[name]
			}, pilotDoctorOptions{
				Network: tt.network,
				Timeout: time.Millisecond,
				ReceiverCheck: func(_ context.Context, rawURL string, _ time.Duration) error {
					called = true
					if rawURL != baseEnv["WEBHOOKERY_PILOT_RECEIVER_CHECK_URL"] {
						t.Fatalf("unexpected receiver url %q", rawURL)
					}
					return tt.checkErr
				},
			})
			finding := requireDoctorFinding(t, findings, tt.want.Check)
			if finding.Severity != tt.want.Severity || !strings.Contains(finding.Message, tt.want.Message) {
				t.Fatalf("unexpected receiver finding: %+v want %+v", finding, tt.want)
			}
			if strings.Contains(finding.Message, "secret-token") {
				t.Fatalf("receiver finding leaked URL secret: %+v", finding)
			}
			if tt.network && tt.env["WEBHOOKERY_PILOT_ALLOW_RECEIVER_CHECK"] == "true" && tt.env["WEBHOOKERY_PILOT_RECEIVER_CHECK_URL"] != "" {
				if !called {
					t.Fatal("expected receiver check call")
				}
			} else if called {
				t.Fatal("receiver check should not have been called")
			}
		})
	}
}

func TestCheckPilotReceiverRejectsUnsafeURLBeforeNetwork(t *testing.T) {
	err := checkPilotReceiver(context.Background(), "http://127.0.0.1:1/health", time.Millisecond)
	var policyErr ssrf.PolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("expected SSRF policy error, got %v", err)
	}
}

func TestRunPilotDoctorNoNetworkUsesEnvironmentAndRedactsStdout(t *testing.T) {
	t.Setenv("WEBHOOKERY_ENVIRONMENT", "production")
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://webhookery:secret-db-password@db.internal/webhookery?sslmode=require")
	t.Setenv("WEBHOOKERY_SECRET_BOX_MODE", "local")
	t.Setenv("WEBHOOKERY_MASTER_KEY_BASE64", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	t.Setenv("WEBHOOKERY_RAW_STORAGE_MODE", "postgres")
	t.Setenv("WEBHOOKERY_PILOT_RECEIVER_CHECK_URL", "https://receiver.internal/webhook?token=secret")
	t.Setenv("WEBHOOKERY_PILOT_ALLOW_RECEIVER_CHECK", "true")
	t.Setenv("WEBHOOKERY_PROVIDER_PROOF_MANIFEST_PATH", "docs/provider-proof-manifest.json")

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	err = runPilotDoctor([]string{"--no-network", "--timeout", "1ms"})
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	output := string(body)
	for _, want := range []string{"ok: database - database URL is configured", "warning: database-connectivity", "warning: receiver-connectivity"} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected %q in pilot doctor output:\n%s", want, output)
		}
	}
	for _, forbidden := range []string{"secret-db-password", "token=secret", os.Getenv("WEBHOOKERY_DATABASE_URL")} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("pilot doctor stdout leaked sensitive value %q in %s", forbidden, output)
		}
	}
}

func requireDoctorFinding(t *testing.T, findings []doctorFinding, check string) doctorFinding {
	t.Helper()
	for _, finding := range findings {
		if finding.Check == check {
			return finding
		}
	}
	t.Fatalf("missing doctor finding %q in %+v", check, findings)
	return doctorFinding{}
}
