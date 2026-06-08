package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCompletesEvidenceWorkflowAgainstWebhookeryAPI(t *testing.T) {
	workdir := t.TempDir()
	t.Chdir(workdir)
	output := filepath.Join(workdir, "evidence-workflow.tar.gz")
	var seen []string
	var createdEventID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer whkey_run" {
			t.Fatalf("authorization header=%q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/events":
			if r.Header.Get("Idempotency-Key") == "" {
				t.Fatal("event creation must set an idempotency key")
			}
			var event struct {
				ID       string         `json:"id"`
				Type     string         `json:"type"`
				SourceID string         `json:"source_id"`
				Data     map[string]any `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
				t.Fatal(err)
			}
			if event.Type != "sdk.evidence.demo" || event.SourceID != "src_run" || event.Data["sanitized"] != true {
				t.Fatalf("unexpected event payload: %+v", event)
			}
			createdEventID = "evt_from_server"
			_, _ = w.Write([]byte(`{"Accepted":true,"EventID":"evt_from_server"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/incidents":
			_, _ = w.Write([]byte(`{"id":"inc_1"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/incidents/inc_1/events":
			var body struct {
				EventID string `json:"event_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.EventID != createdEventID {
				t.Fatalf("incident event used %q, want %q", body.EventID, createdEventID)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/incidents/inc_1/generate-report":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/incidents/inc_1/evidence-export":
			_, _ = w.Write([]byte(`{"id":"exp_1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/audit-exports/exp_1:download":
			_, _ = w.Write([]byte("evidence bundle"))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/audit-chain:verify":
			_, _ = w.Write([]byte(`{"tenant_id":"ten_1","valid":true,"from_sequence":1,"to_sequence":1,"failures":[]}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	t.Setenv("WEBHOOKERY_BASE_URL", server.URL)
	t.Setenv("WEBHOOKERY_API_KEY", "whkey_run")
	t.Setenv("WEBHOOKERY_SOURCE_ID", "src_run")
	t.Setenv("WEBHOOKERY_EVIDENCE_OUTPUT", " ")

	if err := run(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "evidence bundle" {
		t.Fatalf("downloaded bundle=%q", string(body))
	}
	want := []string{
		"POST /v1/events",
		"POST /v1/incidents",
		"POST /v1/incidents/inc_1/events",
		"POST /v1/incidents/inc_1/generate-report",
		"POST /v1/incidents/inc_1/evidence-export",
		"GET /v1/audit-exports/exp_1:download",
		"POST /v1/audit-chain:verify",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("workflow requests:\n%s", strings.Join(seen, "\n"))
	}
}

func TestRunFailsBeforeNetworkWhenConfigurationIsMissing(t *testing.T) {
	t.Setenv("WEBHOOKERY_BASE_URL", " ")
	t.Setenv("WEBHOOKERY_API_KEY", "whkey_missing")
	t.Setenv("WEBHOOKERY_SOURCE_ID", "src_missing")

	err := run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "WEBHOOKERY_BASE_URL is required") {
		t.Fatalf("expected missing base URL error, got %v", err)
	}
}

func TestRunSurfacesWorkflowContractFailures(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr string
	}{
		{name: "missing incident id", mode: "missing_incident_id", wantErr: "incident response did not include id"},
		{name: "missing export id", mode: "missing_export_id", wantErr: "evidence export response did not include id"},
		{name: "invalid audit chain", mode: "invalid_audit_chain", wantErr: "audit chain did not verify"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "bundle.tar.gz")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer whkey_contract" {
					t.Fatalf("authorization header=%q", r.Header.Get("Authorization"))
				}
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/v1/events":
					_, _ = w.Write([]byte(`{"Accepted":true,"EventID":"evt_contract"}`))
				case r.Method == http.MethodPost && r.URL.Path == "/v1/incidents":
					if tt.mode == "missing_incident_id" {
						_, _ = w.Write([]byte(`{}`))
						return
					}
					_, _ = w.Write([]byte(`{"id":"inc_1"}`))
				case r.Method == http.MethodPost && r.URL.Path == "/v1/incidents/inc_1/events":
					w.WriteHeader(http.StatusNoContent)
				case r.Method == http.MethodPost && r.URL.Path == "/v1/incidents/inc_1/generate-report":
					w.WriteHeader(http.StatusNoContent)
				case r.Method == http.MethodPost && r.URL.Path == "/v1/incidents/inc_1/evidence-export":
					if tt.mode == "missing_export_id" {
						_, _ = w.Write([]byte(`{}`))
						return
					}
					_, _ = w.Write([]byte(`{"id":"exp_1"}`))
				case r.Method == http.MethodGet && r.URL.Path == "/v1/audit-exports/exp_1:download":
					_, _ = w.Write([]byte("evidence bundle"))
				case r.Method == http.MethodPost && r.URL.Path == "/v1/audit-chain:verify":
					valid := tt.mode != "invalid_audit_chain"
					_, _ = fmt.Fprintf(w, `{"tenant_id":"ten_1","valid":%t,"from_sequence":1,"to_sequence":1,"failures":[]}`, valid)
				default:
					t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				}
			}))
			defer server.Close()

			t.Setenv("WEBHOOKERY_BASE_URL", server.URL)
			t.Setenv("WEBHOOKERY_API_KEY", "whkey_contract")
			t.Setenv("WEBHOOKERY_SOURCE_ID", "src_contract")
			t.Setenv("WEBHOOKERY_EVIDENCE_OUTPUT", output)

			err := run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q error, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestRestClientDoJSONSendsBearerAndDecodesResponse(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotAccept, gotContentType, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(body)
		_, _ = w.Write([]byte(`{"id":"inc_1"}`))
	}))
	defer server.Close()
	rest := restClient{baseURL: server.URL + "/api/", apiKey: "whkey_example", client: server.Client()}

	var out struct {
		ID string `json:"id"`
	}
	if err := rest.doJSON(context.Background(), http.MethodPost, "/v1/incidents", map[string]string{"reason": "sdk example"}, &out); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/incidents" {
		t.Fatalf("request method/path=%s %s", gotMethod, gotPath)
	}
	if gotAuth != "Bearer whkey_example" || gotAccept != "application/json" || gotContentType != "application/json" {
		t.Fatalf("headers auth=%q accept=%q content-type=%q", gotAuth, gotAccept, gotContentType)
	}
	if gotBody != `{"reason":"sdk example"}` {
		t.Fatalf("request body=%q", gotBody)
	}
	if out.ID != "inc_1" {
		t.Fatalf("decoded id=%q", out.ID)
	}
}

func TestRestClientDownloadWritesPrivateEvidenceFile(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/audit-exports/exp_1:download" {
			t.Fatalf("unexpected download request %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("evidence bundle"))
	}))
	defer server.Close()
	rest := restClient{baseURL: server.URL, apiKey: "whkey_download", client: server.Client()}
	output := filepath.Join(t.TempDir(), "nested", "bundle.tar.gz")

	if err := rest.download(context.Background(), "/v1/audit-exports/exp_1:download", output); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer whkey_download" {
		t.Fatalf("authorization header=%q", gotAuth)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "evidence bundle" {
		t.Fatalf("download body=%q", string(body))
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("evidence file permissions=%o want 0600", got)
	}
}

func TestProblemErrorRedactsResponseBodyDetails(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Body:       io.NopCloser(strings.NewReader(`{"stable_code":"WEBHOOKERY_TENANT_ACCESS_DENIED","request_id":"req_1","detail":"secret body detail"}`)),
	}
	err := problemError(resp)
	if err == nil {
		t.Fatal("expected problem error")
	}
	got := err.Error()
	for _, want := range []string{"HTTP 403", "WEBHOOKERY_TENANT_ACCESS_DENIED", "req_1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("problem error %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "secret body detail") {
		t.Fatalf("problem error leaked body detail: %q", got)
	}
}

func TestEndpointRejectsUnsafeBaseURLs(t *testing.T) {
	if got := endpoint("https://webhookery.example/api?token=secret#frag", "/v1/events"); got != "https://webhookery.example/api/v1/events" {
		t.Fatalf("endpoint=%q", got)
	}
	for _, baseURL := range []string{"ftp://webhookery.example", "https://user:pass@webhookery.example", "https:///missing-host"} {
		t.Run(baseURL, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected endpoint(%q) to panic", baseURL)
				}
			}()
			_ = endpoint(baseURL, "/v1/events")
		})
	}
}

func TestRequiredEnvTrimsValueAndRequiresPresence(t *testing.T) {
	t.Setenv("WEBHOOKERY_EXAMPLE_TEST", "  value  ")
	got, err := requiredEnv("WEBHOOKERY_EXAMPLE_TEST")
	if err != nil {
		t.Fatal(err)
	}
	if got != "value" {
		t.Fatalf("required env=%q", got)
	}
	t.Setenv("WEBHOOKERY_EXAMPLE_TEST", " ")
	_, err = requiredEnv("WEBHOOKERY_EXAMPLE_TEST")
	if err == nil || !strings.Contains(err.Error(), "WEBHOOKERY_EXAMPLE_TEST is required") {
		t.Fatalf("expected missing env error, got %v", err)
	}
}

func TestRestClientReturnsProblemErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"validation_error"}`))
	}))
	defer server.Close()
	rest := restClient{baseURL: server.URL, apiKey: "whkey_problem", client: server.Client()}

	if err := rest.doJSON(context.Background(), http.MethodGet, "/v1/incidents", nil, nil); err == nil || !strings.Contains(err.Error(), "validation_error") {
		t.Fatalf("expected decoded problem error, got %v", err)
	}
	err := rest.download(context.Background(), "/v1/audit-exports/exp_1:download", filepath.Join(t.TempDir(), "bundle.tar.gz"))
	if err == nil || !strings.Contains(err.Error(), "validation_error") {
		t.Fatalf("expected download problem error, got %v", err)
	}
}

func TestRestClientSurfacesInvalidOutputPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("evidence bundle"))
	}))
	defer server.Close()
	rest := restClient{baseURL: server.URL, apiKey: "whkey_download", client: server.Client()}

	dir := t.TempDir()
	err := rest.download(context.Background(), "/v1/audit-exports/exp_1:download", dir)
	if err == nil {
		t.Fatal("expected writing to a directory path to fail")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected write failure, got %v", err)
	}
}
