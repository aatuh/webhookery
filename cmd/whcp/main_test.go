package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apppkg "webhookery/internal/app"
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
			name:       "events search",
			args:       append([]string{"events", "search", "--provider", "stripe", "--external-id", "evt_external", "--verification", "invalid", "--status", "dlq", "--received-after", "2026-06-04T10:00:00Z", "--route-id", "rte_1", "--delivery-id", "del_1", "--limit", "25"}, common...),
			wantMethod: http.MethodGet,
			wantPath:   "/v1/events?delivery_id=del_1&external_id=evt_external&limit=25&provider=stripe&received_after=2026-06-04T10%3A00%3A00Z&route_id=rte_1&status=dlq&verification=invalid",
		},
		{
			name:         "endpoints validate url",
			args:         append([]string{"endpoints", "validate-url", "--url", "https://receiver.example.com/hook"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/endpoints:validate-url",
			bodyContains: []string{`"url":"https://receiver.example.com/hook"`},
		},
		{
			name:         "subscriptions create",
			args:         append([]string{"subscriptions", "create", "--endpoint-id", "end_1", "--event-types", "invoice.created,customer.created", "--payload-format", "canonical_json"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/subscriptions",
			bodyContains: []string{`"endpoint_id":"end_1"`, `"event_types":["invoice.created","customer.created"]`, `"payload_format":"canonical_json"`},
		},
		{
			name:         "retry policy create",
			args:         append([]string{"retry-policies", "create", "--name", "standard", "--max-attempts", "4", "--initial-delay-seconds", "2", "--max-delay-seconds", "30"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/retry-policies",
			bodyContains: []string{`"name":"standard"`, `"max_attempts":4`, `"initial_delay_seconds":2`, `"max_delay_seconds":30`},
		},
		{
			name:         "routes activate",
			args:         append([]string{"routes", "activate", "--route-id", "rte_1", "--reason", "ship"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/routes/rte_1:activate",
			bodyContains: []string{`"reason":"ship"`},
		},
		{
			name:         "replay create",
			args:         append([]string{"replay-jobs", "create", "--event-id", "evt_1", "--endpoint-id", "end_1", "--reason-code", "support_investigation", "--reason", "debug", "--require-approval", "--approval-expires-at", "2026-06-05T12:00:00Z"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/replay-jobs",
			bodyContains: []string{`"event_id":"evt_1"`, `"endpoint_id":"end_1"`, `"reason_code":"support_investigation"`, `"reason":"debug"`, `"require_approval":true`, `"approval_expires_at":"2026-06-05T12:00:00Z"`},
		},
		{
			name:         "replay preview",
			args:         append([]string{"replay-jobs", "preview", "--event-id", "evt_1", "--reason-code", "operator_requested", "--reason", "inspect"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/replay-jobs/preview",
			bodyContains: []string{`"event_id":"evt_1"`, `"reason_code":"operator_requested"`, `"reason":"inspect"`},
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
			name:         "notification channel test",
			args:         append([]string{"notification-channels", "test", "--channel-id", "nch_1", "--reason", "probe"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/notification-channels/nch_1:test",
			bodyContains: []string{`"reason":"probe"`},
		},
		{
			name:         "schema event type update",
			args:         append([]string{"schemas", "event-type-update", "--name", "invoice.created", "--description", "updated", "--state", "active", "--reason", "docs"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/event-types/invoice.created",
			bodyContains: []string{`"description":"updated"`, `"state":"active"`, `"reason":"docs"`},
		},
		{
			name:         "adapter transition",
			args:         append([]string{"adapters", "transition", "--adapter-id", "adp_1", "--version-id", "adv_1", "--action", "approve", "--reason", "reviewed"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/adapters/adp_1/versions/adv_1:transition",
			bodyContains: []string{`"action":"approve"`, `"reason":"reviewed"`},
		},
		{
			name:         "api key create",
			args:         append([]string{"api-keys", "create", "--name", "operator", "--user-id", "usr_1", "--email", "ops@example.com", "--role", "operator", "--scopes", "events:read,deliveries:read"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/api-keys",
			bodyContains: []string{`"email":"ops@example.com"`, `"role":"operator"`, `"scopes":["events:read","deliveries:read"]`},
		},
		{
			name:         "producer client update",
			args:         append([]string{"producer-clients", "update", "--client-id", "pcl_1", "--name", "producer", "--source-id", "src_1", "--scopes", "events:write", "--token-ttl-seconds", "120", "--state", "active", "--reason", "rotate"}, common...),
			wantMethod:   http.MethodPatch,
			wantPath:     "/v1/producer-clients/pcl_1",
			bodyContains: []string{`"name":"producer"`, `"source_id":"src_1"`, `"token_ttl_seconds":120`, `"reason":"rotate"`},
		},
		{
			name:         "identity provider create",
			args:         append([]string{"identity-providers", "create", "--name", "OIDC", "--issuer-url", "https://issuer.example.com", "--client-id", "client", "--client-secret", "secret", "--allowed-email-domains", "example.com,ops.example.com"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/identity-providers",
			bodyContains: []string{`"name":"OIDC"`, `"issuer_url":"https://issuer.example.com"`, `"client_secret":"secret"`, `"allowed_email_domains":["example.com","ops.example.com"]`},
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
			name:         "access policy create",
			args:         append([]string{"access-policies", "create", "--name", "deny raw", "--action", "events:raw", "--effect", "deny", "--resource-family", "events", "--environment", "prod", "--conditions", `{"ip":"outside"}`, "--reason", "policy"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/access-policies",
			bodyContains: []string{`"name":"deny raw"`, `"action":"events:raw"`, `"effect":"deny"`, `"conditions":{"ip":"outside"}`},
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
			name:         "audit export",
			args:         append([]string{"audit", "export", "--from", "2026-05-28T09:00:00Z", "--to", "2026-05-28T10:00:00Z", "--include-raw", "--include-payloads", "--include-timelines", "--reason", "evidence"}, common...),
			wantMethod:   http.MethodPost,
			wantPath:     "/v1/audit-events:export",
			bodyContains: []string{`"from":"2026-05-28T09:00:00Z"`, `"to":"2026-05-28T10:00:00Z"`, `"include_raw_payloads":true`, `"include_payload_bodies":true`, `"include_timelines":true`},
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
