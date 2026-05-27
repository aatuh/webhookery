package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
)

func TestOpenAPIAndRoutes(t *testing.T) {
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi route status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSystemRoutesExposeHealthReadinessAndMetrics(t *testing.T) {
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		Health: func(context.Context) error {
			return nil
		},
	})

	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			server.Routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"ok":true`) {
				t.Fatalf("unexpected health body %s", rec.Body.String())
			}
		})
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected metrics 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("unexpected metrics content-type %q", got)
	}
	if !strings.Contains(rec.Body.String(), "webhookery_events_total") {
		t.Fatalf("metrics body did not include expected series: %s", rec.Body.String())
	}
}

func TestReadyRouteReportsDependencyFailureAsRetryableProblem(t *testing.T) {
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		Health: func(context.Context) error {
			return errors.New("database unavailable")
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("X-Request-ID", "req_ready")
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`"code":"not_ready"`, `"request_id":"req_ready"`, `"retryable":true`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("readiness problem %s did not contain %s", rec.Body.String(), want)
		}
	}
	if strings.Contains(rec.Body.String(), "database unavailable") {
		t.Fatalf("readiness response leaked dependency detail: %s", rec.Body.String())
	}
}

func TestControlRoutesRequireBearer(t *testing.T) {
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthenticatedReadRoutesReturnJSON(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleOwner, Scopes: []string{"*"}})
	routes := []string{
		"/v1/auth/session",
		"/v1/auth/sessions",
		"/v1/identity-providers",
		"/v1/identity-providers/idp_1",
		"/v1/scim-tokens",
		"/v1/role-bindings",
		"/v1/access-policies",
		"/v1/api-keys",
		"/v1/producer-clients",
		"/v1/producer-clients/pcl_1",
		"/v1/producer-mtls-identities",
		"/v1/producer-mtls-identities/pmi_1",
		"/v1/sources",
		"/v1/sources/src_1",
		"/v1/provider-connections",
		"/v1/provider-connections/pcn_1",
		"/v1/adapters",
		"/v1/adapters/pad_1",
		"/v1/adapters/pad_1/versions",
		"/v1/endpoints",
		"/v1/endpoints/end_1",
		"/v1/subscriptions",
		"/v1/subscriptions/sub_1",
		"/v1/retry-policies",
		"/v1/retry-policies/rtp_1",
		"/v1/routes",
		"/v1/routes/rte_1",
		"/v1/routes/rte_1/versions",
		"/v1/event-types",
		"/v1/event-types/invoice.paid",
		"/v1/event-types/invoice.paid/schemas",
		"/v1/event-types/invoice.paid/schemas/2026-05-01",
		"/v1/events",
		"/v1/events/evt_1",
		"/v1/events/evt_1/timeline",
		"/v1/incidents",
		"/v1/incidents/inc_1",
		"/v1/incidents/inc_1/report",
		"/v1/transformations",
		"/v1/transformations/trn_1",
		"/v1/transformations/trn_1/versions",
		"/v1/deliveries",
		"/v1/deliveries/del_1/attempts",
		"/v1/delivery-attempts/att_1",
		"/v1/replay-jobs",
		"/v1/reconciliation-jobs",
		"/v1/reconciliation-jobs/rec_1",
		"/v1/reconciliation-jobs/rec_1/items",
		"/v1/dead-letter",
		"/v1/quarantine",
		"/v1/audit-events",
		"/v1/audit-chain/head",
		"/v1/audit-chain/anchors",
		"/v1/audit-chain/anchors/anc_1",
		"/v1/audit-exports",
		"/v1/audit-exports/exp_1",
		"/v1/admin/retention-policies",
		"/v1/endpoint-health",
		"/v1/ops/metrics",
		"/v1/ops/metrics/rollups?metric_name=deliveries",
		"/v1/ops/storage",
		"/v1/ops/workers",
		"/v1/ops/workers/wrk_1",
		"/v1/ops/queues",
		"/v1/alerts",
		"/v1/alerts/alr_1",
		"/v1/alert-firings",
		"/v1/alert-firings/afr_1",
		"/v1/notification-channels",
		"/v1/notification-channels/nch_1",
		"/v1/notification-deliveries",
		"/v1/notification-deliveries/ndel_1/attempts",
		"/v1/siem-sinks",
		"/v1/siem-sinks/snk_1",
		"/v1/siem-deliveries",
		"/v1/siem-deliveries/sdel_1/attempts",
	}
	expectedStatus := map[string]int{
		"/v1/auth/session":                   http.StatusUnauthorized,
		"/v1/auth/sessions":                  http.StatusBadRequest,
		"/v1/identity-providers":             http.StatusBadRequest,
		"/v1/identity-providers/idp_1":       http.StatusBadRequest,
		"/v1/scim-tokens":                    http.StatusBadRequest,
		"/v1/role-bindings":                  http.StatusBadRequest,
		"/v1/access-policies":                http.StatusBadRequest,
		"/v1/producer-clients":               http.StatusNotFound,
		"/v1/producer-clients/pcl_1":         http.StatusNotFound,
		"/v1/producer-mtls-identities":       http.StatusNotFound,
		"/v1/producer-mtls-identities/pmi_1": http.StatusNotFound,
	}
	for _, path := range routes {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer token")

			server.Routes().ServeHTTP(rec, req)

			wantStatus := http.StatusOK
			if status := expectedStatus[path]; status != 0 {
				wantStatus = status
			}
			if rec.Code != wantStatus {
				t.Fatalf("expected %d, got %d body=%s", wantStatus, rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
				t.Fatalf("expected JSON response, got content-type %q body=%s", got, rec.Body.String())
			}
		})
	}
}

func TestAuthenticatedMutationRoutesPreserveContracts(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleOwner, Scopes: []string{"*"}})
	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{name: "create api key", method: http.MethodPost, path: "/v1/api-keys", body: `{"name":"ops","user_id":"usr_2","email":"ops@example.com","role":"operator","scopes":["events:read"]}`, wantStatus: http.StatusCreated},
		{name: "revoke api key", method: http.MethodPost, path: "/v1/api-keys/key_1:revoke", body: `{"reason":"rotate"}`, wantStatus: http.StatusOK},
		{name: "create identity provider unavailable", method: http.MethodPost, path: "/v1/identity-providers", body: `{"name":"corp","provider_type":"oidc","issuer_url":"https://idp.example","authorization_endpoint":"https://idp.example/auth","token_endpoint":"https://idp.example/token","jwks_uri":"https://idp.example/keys","client_id":"webhookery","client_secret":"oidc-secret","allowed_email_domains":["example.com"]}`, wantStatus: http.StatusBadRequest},
		{name: "update identity provider unavailable", method: http.MethodPatch, path: "/v1/identity-providers/idp_1", body: `{"name":"corp-renamed","reason":"rename"}`, wantStatus: http.StatusBadRequest},
		{name: "disable identity provider unavailable", method: http.MethodDelete, path: "/v1/identity-providers/idp_1", body: `{"reason":"disable"}`, wantStatus: http.StatusBadRequest},
		{name: "test identity provider unavailable", method: http.MethodPost, path: "/v1/identity-providers/idp_1:test", body: `{"reason":"smoke"}`, wantStatus: http.StatusBadRequest},
		{name: "create scim token unavailable", method: http.MethodPost, path: "/v1/scim-tokens", body: `{"name":"directory-sync"}`, wantStatus: http.StatusBadRequest},
		{name: "revoke scim token unavailable", method: http.MethodDelete, path: "/v1/scim-tokens/sct_1", body: `{"reason":"rotate"}`, wantStatus: http.StatusBadRequest},
		{name: "create role binding unavailable", method: http.MethodPost, path: "/v1/role-bindings", body: `{"principal_type":"user","principal_id":"usr_2","role":"operator","resource_family":"tenant","resource_id":"ten_1","environment":"prod","reason":"delegate"}`, wantStatus: http.StatusBadRequest},
		{name: "update role binding unavailable", method: http.MethodPatch, path: "/v1/role-bindings/rbd_1", body: `{"role":"viewer","reason":"least privilege"}`, wantStatus: http.StatusBadRequest},
		{name: "disable role binding unavailable", method: http.MethodDelete, path: "/v1/role-bindings/rbd_1", body: `{"reason":"remove"}`, wantStatus: http.StatusBadRequest},
		{name: "create access policy unavailable", method: http.MethodPost, path: "/v1/access-policies", body: `{"name":"deny-export","action":"audit:export","effect":"deny","resource_family":"audit_export","environment":"prod","reason":"policy"}`, wantStatus: http.StatusBadRequest},
		{name: "update access policy unavailable", method: http.MethodPatch, path: "/v1/access-policies/apr_1", body: `{"effect":"allow","reason":"policy change"}`, wantStatus: http.StatusBadRequest},
		{name: "disable access policy unavailable", method: http.MethodDelete, path: "/v1/access-policies/apr_1", body: `{"reason":"retire"}`, wantStatus: http.StatusBadRequest},
		{name: "authz explain unavailable", method: http.MethodPost, path: "/v1/authz:explain", body: `{"actor_id":"usr_2","action":"events:read","resource_family":"event","resource_id":"evt_1","environment":"prod"}`, wantStatus: http.StatusBadRequest},
		{name: "create producer client unavailable", method: http.MethodPost, path: "/v1/producer-clients", body: `{"name":"billing","source_id":"src_1","scopes":["events:write"],"token_ttl_seconds":900}`, wantStatus: http.StatusNotFound},
		{name: "update producer client unavailable", method: http.MethodPatch, path: "/v1/producer-clients/pcl_1", body: `{"name":"billing-v2","reason":"rename"}`, wantStatus: http.StatusNotFound},
		{name: "delete producer client unavailable", method: http.MethodDelete, path: "/v1/producer-clients/pcl_1", body: `{"reason":"retire"}`, wantStatus: http.StatusNotFound},
		{name: "rotate producer client secret unavailable", method: http.MethodPost, path: "/v1/producer-clients/pcl_1/secrets:rotate", body: `{"reason":"rotate"}`, wantStatus: http.StatusNotFound},
		{name: "create producer mtls unavailable", method: http.MethodPost, path: "/v1/producer-mtls-identities", body: `{"name":"billing","source_id":"src_1","certificate_pem":"not a cert"}`, wantStatus: http.StatusNotFound},
		{name: "update producer mtls unavailable", method: http.MethodPatch, path: "/v1/producer-mtls-identities/pmi_1", body: `{"name":"billing-v2","reason":"rename"}`, wantStatus: http.StatusNotFound},
		{name: "delete producer mtls unavailable", method: http.MethodDelete, path: "/v1/producer-mtls-identities/pmi_1", body: `{"reason":"retire"}`, wantStatus: http.StatusNotFound},
		{name: "verify producer mtls unavailable", method: http.MethodPost, path: "/v1/producer-mtls-identities/pmi_1:verify", body: `{"certificate_pem":"not a cert"}`, wantStatus: http.StatusNotFound},
		{name: "create source", method: http.MethodPost, path: "/v1/sources", body: `{"name":"stripe-primary","provider":"stripe","adapter":"stripe","verification_secret":"whsec_test"}`, wantStatus: http.StatusCreated},
		{name: "update source", method: http.MethodPatch, path: "/v1/sources/src_1", body: `{"name":"stripe-renamed","state":"active","reason":"rename"}`, wantStatus: http.StatusOK},
		{name: "delete source", method: http.MethodDelete, path: "/v1/sources/src_1", body: `{"reason":"retire"}`, wantStatus: http.StatusOK},
		{name: "rotate source secret", method: http.MethodPost, path: "/v1/sources/src_1/secrets:rotate", body: `{"new_secret":"next-secret","reason":"rotate","grace_period_hours":1}`, wantStatus: http.StatusOK},
		{name: "create provider connection", method: http.MethodPost, path: "/v1/provider-connections", body: `{"name":"stripe-api","provider":"stripe","credential_type":"api_key","credential":"sk_test_secret","config":{"source_id":"src_1"}}`, wantStatus: http.StatusCreated},
		{name: "verify provider connection", method: http.MethodPost, path: "/v1/provider-connections/pcn_1:verify", body: `{"reason":"check"}`, wantStatus: http.StatusOK},
		{name: "revoke provider connection", method: http.MethodPost, path: "/v1/provider-connections/pcn_1:revoke", body: `{"reason":"rotate"}`, wantStatus: http.StatusOK},
		{name: "create adapter", method: http.MethodPost, path: "/v1/adapters", body: `{"name":"custom-provider","kind":"declarative","description":"test adapter","risk_level":"low"}`, wantStatus: http.StatusCreated},
		{name: "create adapter version", method: http.MethodPost, path: "/v1/adapters/pad_1/versions", body: `{"version":"2026-05-28","definition":{"provider":"custom"},"reason":"initial","risk_level":"low"}`, wantStatus: http.StatusCreated},
		{name: "create adapter test vector", method: http.MethodPost, path: "/v1/adapters/pad_1/versions/adv_1/test-vectors", body: `{"name":"valid-signature","purpose":"happy path","request":{"body":"{}"},"expected":{"verified":true}}`, wantStatus: http.StatusCreated},
		{name: "transition adapter", method: http.MethodPost, path: "/v1/adapters/pad_1/versions/adv_1:transition", body: `{"action":"activate","reason":"promote"}`, wantStatus: http.StatusOK},
		{name: "create endpoint", method: http.MethodPost, path: "/v1/endpoints", body: `{"name":"receiver","url":"https://receiver.example/hook"}`, wantStatus: http.StatusCreated},
		{name: "update endpoint", method: http.MethodPatch, path: "/v1/endpoints/end_1", body: `{"name":"receiver-renamed","url":"https://receiver.example/hook","state":"active","reason":"rename"}`, wantStatus: http.StatusOK},
		{name: "delete endpoint", method: http.MethodDelete, path: "/v1/endpoints/end_1", body: `{"reason":"retire"}`, wantStatus: http.StatusOK},
		{name: "validate endpoint url", method: http.MethodPost, path: "/v1/endpoints:validate-url", body: `{"url":"https://receiver.example/hook"}`, wantStatus: http.StatusOK},
		{name: "test endpoint", method: http.MethodPost, path: "/v1/endpoints/end_1:test", body: `{"reason":"smoke"}`, wantStatus: http.StatusAccepted},
		{name: "rotate endpoint secret", method: http.MethodPost, path: "/v1/endpoints/end_1/secrets:rotate", body: `{"reason":"rotate","grace_period_hours":1}`, wantStatus: http.StatusOK},
		{name: "create subscription", method: http.MethodPost, path: "/v1/subscriptions", body: `{"endpoint_id":"end_1","event_types":["invoice.paid"],"payload_format":"canonical_json"}`, wantStatus: http.StatusCreated},
		{name: "update subscription", method: http.MethodPatch, path: "/v1/subscriptions/sub_1", body: `{"state":"disabled","reason":"pause"}`, wantStatus: http.StatusOK},
		{name: "delete subscription", method: http.MethodDelete, path: "/v1/subscriptions/sub_1", body: `{"reason":"retire"}`, wantStatus: http.StatusOK},
		{name: "create retry policy", method: http.MethodPost, path: "/v1/retry-policies", body: `{"name":"standard","max_attempts":3,"max_duration_seconds":3600,"initial_delay_seconds":1,"max_delay_seconds":60,"state":"active"}`, wantStatus: http.StatusCreated},
		{name: "update retry policy", method: http.MethodPatch, path: "/v1/retry-policies/rtp_1", body: `{"max_attempts":6,"reason":"tune"}`, wantStatus: http.StatusOK},
		{name: "delete retry policy", method: http.MethodDelete, path: "/v1/retry-policies/rtp_1", body: `{"reason":"retire"}`, wantStatus: http.StatusOK},
		{name: "create route", method: http.MethodPost, path: "/v1/routes", body: `{"source_id":"src_1","name":"invoice-route","priority":10,"event_types":["invoice.paid"],"endpoint_id":"end_1","state":"active"}`, wantStatus: http.StatusCreated},
		{name: "update route", method: http.MethodPatch, path: "/v1/routes/rte_1", body: `{"priority":20,"reason":"reprioritize"}`, wantStatus: http.StatusOK},
		{name: "delete route", method: http.MethodDelete, path: "/v1/routes/rte_1", body: `{"reason":"retire"}`, wantStatus: http.StatusOK},
		{name: "activate route", method: http.MethodPost, path: "/v1/routes/rte_1:activate", body: `{"reason":"publish"}`, wantStatus: http.StatusOK},
		{name: "dry run route", method: http.MethodPost, path: "/v1/routes/rte_1:dry-run", body: `{"event_id":"evt_1"}`, wantStatus: http.StatusOK},
		{name: "create event type", method: http.MethodPost, path: "/v1/event-types", body: `{"name":"invoice.paid","description":"Invoice paid"}`, wantStatus: http.StatusCreated},
		{name: "update event type", method: http.MethodPatch, path: "/v1/event-types/invoice.paid", body: `{"description":"Invoice paid v2","state":"active","reason":"document"}`, wantStatus: http.StatusOK},
		{name: "delete event type", method: http.MethodDelete, path: "/v1/event-types/invoice.paid", body: `{"reason":"retire"}`, wantStatus: http.StatusOK},
		{name: "create schema", method: http.MethodPost, path: "/v1/event-types/invoice.paid/schemas", body: `{"version":"2026-05-01","schema":"{\"type\":\"object\"}"}`, wantStatus: http.StatusCreated},
		{name: "update schema", method: http.MethodPatch, path: "/v1/event-types/invoice.paid/schemas/2026-05-01", body: `{"state":"deprecated","reason":"replace"}`, wantStatus: http.StatusOK},
		{name: "delete schema", method: http.MethodDelete, path: "/v1/event-types/invoice.paid/schemas/2026-05-01", body: `{"reason":"retire"}`, wantStatus: http.StatusOK},
		{name: "validate schema", method: http.MethodPost, path: "/v1/event-types/invoice.paid/schemas/2026-05-01:validate", body: `{"payload":"{\"id\":\"evt_1\"}"}`, wantStatus: http.StatusOK},
		{name: "check schema compatibility", method: http.MethodPost, path: "/v1/event-types/invoice.paid/schemas/2026-05-01:check-compatibility", body: `{"new_schema":"{\"type\":\"object\"}"}`, wantStatus: http.StatusOK},
		{name: "create transformation", method: http.MethodPost, path: "/v1/transformations", body: `{"name":"redact-email","operations":[{"op":"redact","path":"/data/email"}]}`, wantStatus: http.StatusCreated},
		{name: "create transformation version", method: http.MethodPost, path: "/v1/transformations/trn_1/versions", body: `{"operations":[{"op":"redact","path":"/data/email"}]}`, wantStatus: http.StatusCreated},
		{name: "activate transformation version", method: http.MethodPost, path: "/v1/transformations/trn_1/versions/trv_1:activate", body: `{"reason":"publish"}`, wantStatus: http.StatusOK},
		{name: "retry delivery", method: http.MethodPost, path: "/v1/deliveries/del_1:retry", body: `{"reason":"retry"}`, wantStatus: http.StatusAccepted},
		{name: "cancel delivery", method: http.MethodPost, path: "/v1/deliveries/del_1:cancel", body: `{"reason":"cancel"}`, wantStatus: http.StatusOK},
		{name: "dry run replay", method: http.MethodPost, path: "/v1/replay-jobs:dry-run", body: `{"event_id":"evt_1","reason_code":"operator_requested","reason":"inspect"}`, wantStatus: http.StatusOK},
		{name: "create reconciliation", method: http.MethodPost, path: "/v1/reconciliation-jobs", body: `{"connection_id":"pcn_1","reason":"recover"}`, wantStatus: http.StatusCreated},
		{name: "approve replay", method: http.MethodPost, path: "/v1/replay-jobs/rpl_1:approve", body: `{"reason":"approve"}`, wantStatus: http.StatusOK},
		{name: "pause replay", method: http.MethodPost, path: "/v1/replay-jobs/rpl_1:pause", body: `{"reason":"pause"}`, wantStatus: http.StatusOK},
		{name: "resume replay", method: http.MethodPost, path: "/v1/replay-jobs/rpl_1:resume", body: `{"reason":"resume"}`, wantStatus: http.StatusOK},
		{name: "cancel replay", method: http.MethodPost, path: "/v1/replay-jobs/rpl_1:cancel", body: `{"reason":"cancel"}`, wantStatus: http.StatusOK},
		{name: "dry run reconciliation", method: http.MethodPost, path: "/v1/reconciliation-jobs:dry-run", body: `{"connection_id":"pcn_1","reason":"preview"}`, wantStatus: http.StatusOK},
		{name: "cancel reconciliation", method: http.MethodPost, path: "/v1/reconciliation-jobs/rec_1:cancel", body: `{"reason":"stop"}`, wantStatus: http.StatusOK},
		{name: "bulk release dead letter", method: http.MethodPost, path: "/v1/dead-letter:bulk-release", body: `{"entry_ids":["dlq_1"],"reason_code":"incident_recovery","reason":"release"}`, wantStatus: http.StatusAccepted},
		{name: "approve quarantine", method: http.MethodPost, path: "/v1/quarantine/qrn_1:approve", body: `{"reason":"safe","route_after_release":true}`, wantStatus: http.StatusOK},
		{name: "reject quarantine", method: http.MethodPost, path: "/v1/quarantine/qrn_1:reject", body: `{"reason":"reject"}`, wantStatus: http.StatusOK},
		{name: "verify audit chain", method: http.MethodPost, path: "/v1/audit-chain:verify", body: `{"from_sequence":1,"to_sequence":2}`, wantStatus: http.StatusOK},
		{name: "anchor audit chain", method: http.MethodPost, path: "/v1/audit-chain:anchor", body: `{"from_sequence":1,"to_sequence":2,"reason":"daily"}`, wantStatus: http.StatusCreated},
		{name: "create audit export", method: http.MethodPost, path: "/v1/audit-events:export", body: `{"include_raw_payloads":false,"include_timelines":true,"reason":"support"}`, wantStatus: http.StatusAccepted},
		{name: "create incident", method: http.MethodPost, path: "/v1/incidents", body: `{"title":"Stripe payment webhook failed","reason":"support investigation"}`, wantStatus: http.StatusCreated},
		{name: "add incident event", method: http.MethodPost, path: "/v1/incidents/inc_1/events", body: `{"event_id":"evt_1","reason":"attach failed payment"}`, wantStatus: http.StatusCreated},
		{name: "remove incident event", method: http.MethodDelete, path: "/v1/incidents/inc_1/events/evt_1", body: `{"reason":"not related"}`, wantStatus: http.StatusOK},
		{name: "generate incident report", method: http.MethodPost, path: "/v1/incidents/inc_1/generate-report", body: `{"reason":"support handoff"}`, wantStatus: http.StatusCreated},
		{name: "create incident evidence export", method: http.MethodPost, path: "/v1/incidents/inc_1/evidence-export", body: `{"reason":"customer evidence"}`, wantStatus: http.StatusAccepted},
		{name: "create retention", method: http.MethodPost, path: "/v1/admin/retention-policies", body: `{"resource_type":"raw_payload","retention_days":30}`, wantStatus: http.StatusCreated},
		{name: "update retention", method: http.MethodPatch, path: "/v1/admin/retention-policies/ret_1", body: `{"retention_days":30}`, wantStatus: http.StatusOK},
		{name: "create alert", method: http.MethodPost, path: "/v1/alerts", body: `{"name":"dlq-open","rule_type":"dead_letter_open","threshold":1,"comparator":">=","window_seconds":60,"state":"active","channel_ids":["nch_1"]}`, wantStatus: http.StatusCreated},
		{name: "update alert", method: http.MethodPatch, path: "/v1/alerts/alr_1", body: `{"threshold":2,"reason":"tune"}`, wantStatus: http.StatusOK},
		{name: "delete alert", method: http.MethodDelete, path: "/v1/alerts/alr_1", body: `{"reason":"retire"}`, wantStatus: http.StatusOK},
		{name: "ack alert", method: http.MethodPost, path: "/v1/alert-firings/afr_1:acknowledge", body: `{"reason":"seen"}`, wantStatus: http.StatusOK},
		{name: "create notification", method: http.MethodPost, path: "/v1/notification-channels", body: `{"name":"ops-webhook","channel_type":"webhook","url":"https://signals.example/hook","signing_secret":"notify-secret-123"}`, wantStatus: http.StatusCreated},
		{name: "update notification", method: http.MethodPatch, path: "/v1/notification-channels/nch_1", body: `{"name":"ops-webhook-2","reason":"rename"}`, wantStatus: http.StatusOK},
		{name: "delete notification", method: http.MethodDelete, path: "/v1/notification-channels/nch_1", body: `{"reason":"retire"}`, wantStatus: http.StatusOK},
		{name: "test notification", method: http.MethodPost, path: "/v1/notification-channels/nch_1:test", body: `{"reason":"smoke"}`, wantStatus: http.StatusAccepted},
		{name: "retry notification", method: http.MethodPost, path: "/v1/notification-deliveries/ndel_1:retry", body: `{"reason":"retry"}`, wantStatus: http.StatusOK},
		{name: "create siem", method: http.MethodPost, path: "/v1/siem-sinks", body: `{"name":"secops","sink_type":"webhook","url":"https://siem.example/ingest","signing_secret":"siem-secret-1234"}`, wantStatus: http.StatusCreated},
		{name: "update siem", method: http.MethodPatch, path: "/v1/siem-sinks/snk_1", body: `{"name":"secops-2","reason":"rename"}`, wantStatus: http.StatusOK},
		{name: "delete siem", method: http.MethodDelete, path: "/v1/siem-sinks/snk_1", body: `{"reason":"retire"}`, wantStatus: http.StatusOK},
		{name: "test siem", method: http.MethodPost, path: "/v1/siem-sinks/snk_1:test", body: `{"reason":"smoke"}`, wantStatus: http.StatusAccepted},
		{name: "retry siem", method: http.MethodPost, path: "/v1/siem-deliveries/sdel_1:retry", body: `{"reason":"retry"}`, wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			req.Header.Set("Authorization", "Bearer token")
			req.Header.Set("Content-Type", "application/json")

			server.Routes().ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d body=%s", tt.wantStatus, rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
				t.Fatalf("expected JSON response, got content-type %q body=%s", got, rec.Body.String())
			}
		})
	}
}

func TestProductEventSourceIDExtractionPreservesRawBodyPath(t *testing.T) {
	sourceID := productSourceID([]byte(`{"source_id":"src_internal","id":"evt_1"}`))
	if sourceID != "src_internal" {
		t.Fatalf("unexpected source id %q", sourceID)
	}
	if productSourceID([]byte(`{"id":"evt_1"}`)) != "" {
		t.Fatal("missing source_id must not be accepted")
	}
}

func TestOAuthTokenEndpointUsesBasicAuthAndNoStore(t *testing.T) {
	store := &producerTokenControlStore{
		client: domain.ProducerClient{
			ID:              "pcl_1",
			TenantID:        "ten_1",
			Scopes:          []string{"events:write"},
			TokenTTLSeconds: 900,
			State:           domain.StateActive,
		},
	}
	server := NewServer(ServerConfig{
		Control: app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}}),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("api-key", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", strings.NewReader("grant_type=client_credentials"))
	req.SetBasicAuth("pcl_1", "client-secret")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected token response, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"token_type":"Bearer"`) || !strings.Contains(body, `"expires_in":900`) {
		t.Fatalf("unexpected token body: %s", body)
	}
	if strings.Contains(body, "client-secret") || store.secretHash != app.HashToken("client-secret") || store.tokenInput.Token.Hash == "" {
		t.Fatalf("token endpoint leaked or failed to hash credentials: body=%s hash=%q token=%+v", body, store.secretHash, store.tokenInput.Token)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("token response must be non-cacheable: headers=%v", rec.Header())
	}
}

func TestOAuthTokenEndpointRejectsBodyClientSecret(t *testing.T) {
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", strings.NewReader("grant_type=client_credentials&client_secret=body-secret"))

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "body-secret") {
		t.Fatalf("error response leaked submitted secret: %s", rec.Body.String())
	}
}

func TestProductEventsRequireEventsWrite(t *testing.T) {
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"source_id":"src_1","id":"evt_1"}`))
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProductEventsRejectSourceBoundProducerMismatch(t *testing.T) {
	ingest := &trackingIngestStore{}
	server := NewServer(ServerConfig{
		Control:      NewNoopControl(),
		Ingest:       app.NewIngestService(ingest, app.SystemClock{}),
		ProducerAuth: app.NewStaticAuthenticator("producer-token", authz.Actor{ID: "producer_client:pcl_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"events:write"}, SourceID: "src_allowed"}),
		OpenAPI:      []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"source_id":"src_other","id":"evt_1"}`))
	req.Header.Set("Authorization", "Bearer producer-token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	if ingest.called {
		t.Fatal("source-bound producer mismatch must not reach ingestion")
	}
}

func TestProductEventsAcceptProducerOAuthToken(t *testing.T) {
	ingest := &acceptingIngestStore{}
	server := NewServer(ServerConfig{
		Control:      NewNoopControl(),
		Ingest:       app.NewIngestService(ingest, app.SystemClock{}),
		ProducerAuth: app.NewStaticAuthenticator("producer-token", authz.Actor{ID: "producer_client:pcl_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"events:write"}, SourceID: "src_allowed"}),
		OpenAPI:      []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"source_id":"src_allowed","id":"evt_1"}`))
	req.Header.Set("Authorization", "Bearer producer-token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !ingest.called {
		t.Fatal("producer OAuth request should reach ingestion")
	}
}

func TestProductEventsAcceptVerifiedProducerMTLS(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("producer-cert")}
	ingest := &acceptingIngestStore{}
	server := NewServer(ServerConfig{
		Control:          NewNoopControl(),
		Ingest:           app.NewIngestService(ingest, app.SystemClock{}),
		ProducerMTLSAuth: app.ProducerMTLSAuthenticator{Lookup: fakeProducerMTLSLookup{fingerprint: app.CertificateFingerprintSHA256(cert)}},
		OpenAPI:          []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"source_id":"src_allowed","id":"evt_1"}`))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !ingest.called {
		t.Fatal("verified producer mTLS request should reach ingestion")
	}
}

func TestProductEventsRejectUnverifiedProducerMTLS(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("producer-cert")}
	ingest := &trackingIngestStore{}
	server := NewServer(ServerConfig{
		Control:          NewNoopControl(),
		Ingest:           app.NewIngestService(ingest, app.SystemClock{}),
		ProducerMTLSAuth: app.ProducerMTLSAuthenticator{Lookup: fakeProducerMTLSLookup{fingerprint: app.CertificateFingerprintSHA256(cert)}},
		OpenAPI:          []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"source_id":"src_allowed","id":"evt_1"}`))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
	}
	if ingest.called {
		t.Fatal("unverified producer mTLS request must not reach ingestion")
	}
}

func TestProducerClientCreateRequiresSecurityWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAuditor, Scopes: []string{"security:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/producer-clients", strings.NewReader(`{"name":"billing","scopes":["events:write"]}`))
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPrometheusMetricsDoesNotRequireBearer(t *testing.T) {
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected public metrics, got %d", rec.Code)
	}
}

func TestPrometheusAuditChainMetricsAreAggregate(t *testing.T) {
	body := formatPrometheus(domain.OpsMetrics{
		AuditChainUnchainedEvents:      2,
		AuditChainVerificationFailures: 1,
		AuditChainLastAnchorAgeSec:     3600,
		DeliveriesByState:              map[string]int64{},
		ReplayJobsByState:              map[string]int64{},
	})
	if !strings.Contains(body, "webhookery_audit_chain_unchained_events 2") {
		t.Fatalf("missing unchained audit metric:\n%s", body)
	}
	if !strings.Contains(body, "webhookery_audit_chain_verification_failures 1") {
		t.Fatalf("missing audit chain failure metric:\n%s", body)
	}
	if !strings.Contains(body, "webhookery_audit_chain_last_anchor_age_seconds 3600") {
		t.Fatalf("missing last anchor age metric:\n%s", body)
	}
	if strings.Contains(body, "tenant=") {
		t.Fatalf("public metrics must not expose tenant labels:\n%s", body)
	}
}

func TestOpsConfigRouteReturnsRedactedRuntimeMetadata(t *testing.T) {
	control := app.NewControlServiceWithRuntimeConfig(noopControlStore{}, ssrf.Validator{Resolver: ssrf.StaticResolver{}}, domain.OpsConfig{
		Environment:             "production",
		UIEnabled:               true,
		RawStorageMode:          domain.RawStorageS3,
		ObjectStorageConfigured: true,
		SecretBoxMode:           "vault-transit",
		MaxIngressBodyBytes:     2 << 20,
		MaxHeaderBytes:          64 << 10,
		MaxHeaderPairs:          128,
		MaxHeaderValueBytes:     8 << 10,
	})
	server := NewServer(ServerConfig{
		Control: control,
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleOperator, Scopes: []string{"ops:read"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/ops/config", nil)
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "DATABASE_URL") || strings.Contains(body, "MASTER_KEY") || strings.Contains(body, "VAULT_TOKEN") {
		t.Fatalf("ops config leaked secret-shaped fields: %s", body)
	}
	if !strings.Contains(body, `"raw_storage_mode":"s3"`) || !strings.Contains(body, `"object_storage_configured":true`) {
		t.Fatalf("ops config missing safe metadata: %s", body)
	}
}

func TestSlackChallengeExtraction(t *testing.T) {
	challenge := slackChallenge([]byte(`{"type":"url_verification","challenge":"abc123"}`))
	if challenge != "abc123" {
		t.Fatalf("unexpected challenge %q", challenge)
	}
	if slackChallenge([]byte(`{"type":"event_callback","challenge":"abc123"}`)) != "" {
		t.Fatal("non-url-verification payload must not be treated as challenge")
	}
}

func TestIngressRejectsOversizedHeaderBeforeCapture(t *testing.T) {
	store := &trackingIngestStore{}
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(store, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/ten_1/src_1", strings.NewReader(`{}`))
	req.Header.Set("X-Oversized", strings.Repeat("a", maxHeaderValueBytes+1))

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("expected 431, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.called {
		t.Fatal("oversized headers must be rejected before ingest store lookup")
	}
}

func TestIngressRejectsTooManyHeadersBeforeCapture(t *testing.T) {
	store := &trackingIngestStore{}
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(store, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"*"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/ten_1/src_1", strings.NewReader(`{}`))
	for i := 0; i <= maxHeaderPairs; i++ {
		req.Header.Set(fmt.Sprintf("X-Many-%03d", i), "a")
	}

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("expected 431, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.called {
		t.Fatal("excessive headers must be rejected before ingest store lookup")
	}
}

func TestIngestRouteDispatchesTenantAndProviderAliases(t *testing.T) {
	store := &routeDispatchIngestStore{}
	server := NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(store, app.SystemClock{}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})

	generic := httptest.NewRecorder()
	genericReq := httptest.NewRequest(http.MethodPost, "/v1/ingest/ten_route/src_route", strings.NewReader(`{"specversion":"1.0","id":"evt_1","type":"thing.created","source":"tests"}`))
	server.Routes().ServeHTTP(generic, genericReq)
	if generic.Code != http.StatusOK {
		t.Fatalf("expected generic tenant ingest to succeed, got %d body=%s", generic.Code, generic.Body.String())
	}
	if store.lastTenantID != "ten_route" || store.lastSourceID != "src_route" || store.providerLookupCalled {
		t.Fatalf("generic route used wrong lookup path: %+v", store)
	}

	store.providerLookupCalled = false
	provider := httptest.NewRecorder()
	providerReq := httptest.NewRequest(http.MethodPost, "/v1/ingest/cloudevents/src_route", strings.NewReader(`{"specversion":"1.0","id":"evt_2","type":"thing.created","source":"tests"}`))
	server.Routes().ServeHTTP(provider, providerReq)
	if provider.Code != http.StatusOK {
		t.Fatalf("expected provider alias ingest to succeed, got %d body=%s", provider.Code, provider.Body.String())
	}
	if !store.providerLookupCalled || store.lastProvider != "cloudevents" || store.lastProviderSourceID != "src_route" {
		t.Fatalf("provider alias route used wrong lookup path: %+v", store)
	}
}

func TestAuditExportWithRawRequiresRawScope(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAdmin, Scopes: []string{"audit:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/audit-events:export", bytes.NewBufferString(`{"include_raw_payloads":true}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for raw-inclusive export without events:raw, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRetentionPolicyWriteRequiresSecurityWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAuditor, Scopes: []string{"security:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/retention-policies", bytes.NewBufferString(`{"resource_type":"raw_payload","retention_days":30}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for retention write without security:write, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuditExportDownloadReturnsBundleWithHashHeader(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleOwner, Scopes: []string{"*"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/audit-exports/exp_1:download", nil)
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/gzip" {
		t.Fatalf("content type=%q want application/gzip", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Webhookery-Export-SHA256") == "" {
		t.Fatal("expected export hash header")
	}
}

func TestNormalizedEventBodyRequiresRawScope(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/events/evt_1/normalized?include_data=true", nil)
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRawPayloadRequiresRawScopeBeforeStoreAccess(t *testing.T) {
	store := &rawPayloadControlStore{}
	server := NewServer(ServerConfig{
		Control: app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}}),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/events/evt_1/raw", nil)
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.rawCalled {
		t.Fatal("raw payload store must not be called without events:raw")
	}
}

func TestRawPayloadEndpointEncodesBodyAndTenantActorContext(t *testing.T) {
	store := &rawPayloadControlStore{}
	server := NewServer(ServerConfig{
		Control: app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}}),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_raw", TenantID: "ten_raw", Role: authz.RoleOwner, Scopes: []string{"events:raw"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/events/evt_raw/raw", nil)
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !store.rawCalled || store.tenantID != "ten_raw" || store.eventID != "evt_raw" || store.actorID != "usr_raw" {
		t.Fatalf("raw payload store called with wrong context: %+v", store)
	}
	wantBody := base64.StdEncoding.EncodeToString([]byte("raw evidence bytes"))
	body := rec.Body.String()
	if !strings.Contains(body, `"body_base64":"`+wantBody+`"`) {
		t.Fatalf("raw payload body was not base64 encoded: %s", body)
	}
	if strings.Contains(body, "raw evidence bytes") {
		t.Fatalf("raw payload response leaked plaintext body outside base64 field: %s", body)
	}
}

func TestCreateReplayPropagatesReasonCodeReasonAndConfig(t *testing.T) {
	store := &replayControlStore{}
	server := NewServer(ServerConfig{
		Control: app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}}),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_replay", TenantID: "ten_replay", Role: authz.RoleOperator, Scopes: []string{"replay:write"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/replay-jobs", bytes.NewBufferString(`{"event_id":"evt_1","reason_code":"receiver_fixed","reason":"customer fixed receiver","config_mode":"original","rate_limit_per_minute":25}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !store.replayCalled || store.tenantID != "ten_replay" || store.actorID != "usr_replay" {
		t.Fatalf("replay store called with wrong context: %+v", store)
	}
	if store.replayReq.EventID != "evt_1" || store.replayReq.ReasonCode != app.ReplayReasonReceiverFixed || store.replayReq.Reason != "customer fixed receiver" || store.replayReq.ConfigMode != app.ReplayConfigOriginal || store.replayReq.RateLimitPerMinute != 25 {
		t.Fatalf("replay request was not propagated: %+v", store.replayReq)
	}
}

func TestCreateReplayRejectsMissingReasonBeforeStoreAccess(t *testing.T) {
	store := &replayControlStore{}
	server := NewServer(ServerConfig{
		Control: app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}}),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_replay", TenantID: "ten_replay", Role: authz.RoleOperator, Scopes: []string{"replay:write"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/replay-jobs", bytes.NewBufferString(`{"event_id":"evt_1"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.replayCalled {
		t.Fatal("missing replay reason must be rejected before store side effects")
	}
}

func TestCreateReplayRejectsMissingReasonCodeBeforeStoreAccess(t *testing.T) {
	store := &replayControlStore{}
	server := NewServer(ServerConfig{
		Control: app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}}),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_replay", TenantID: "ten_replay", Role: authz.RoleOperator, Scopes: []string{"replay:write"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/replay-jobs", bytes.NewBufferString(`{"event_id":"evt_1","reason":"customer fixed receiver"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.replayCalled {
		t.Fatal("missing replay reason code must be rejected before store side effects")
	}
}

func TestDeadLetterReleasePropagatesReasonCodeAndReason(t *testing.T) {
	store := &replayControlStore{}
	server := NewServer(ServerConfig{
		Control: app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}}),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_ops", TenantID: "ten_ops", Role: authz.RoleOperator, Scopes: []string{"deliveries:retry"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/dead-letter/dlq_1:release", bytes.NewBufferString(`{"reason_code":"receiver_fixed","reason":"receiver recovered"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !store.deadLetterCalled || store.entryID != "dlq_1" || store.reasonCode != app.ReplayReasonReceiverFixed || store.reason != "receiver recovered" || store.tenantID != "ten_ops" || store.actorID != "usr_ops" {
		t.Fatalf("dead-letter release used wrong context: %+v", store)
	}
}

func TestDeadLetterReleaseRequiresRetryScopeBeforeStoreAccess(t *testing.T) {
	store := &replayControlStore{}
	server := NewServer(ServerConfig{
		Control: app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{}}),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", authz.Actor{ID: "usr_support", TenantID: "ten_ops", Role: authz.RoleSupport, Scopes: []string{"deliveries:read"}}),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/dead-letter/dlq_1:release", bytes.NewBufferString(`{"reason_code":"receiver_fixed","reason":"receiver recovered"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.deadLetterCalled {
		t.Fatal("dead-letter release store must not be called without deliveries:retry")
	}
}

func TestTransformationWriteRequiresRoutesWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"routes:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/transformations", bytes.NewBufferString(`{"name":"redact","operations":[{"op":"redact","path":"/data/email"}]}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProviderConnectionCreateRequiresSourcesWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"sources:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/provider-connections", bytes.NewBufferString(`{"name":"Stripe","provider":"stripe","credential":"sk_test_secret"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSourceUpdateRequiresSourcesWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"sources:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/sources/src_1", bytes.NewBufferString(`{"name":"renamed","reason":"rename"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEndpointUpdateRequiresEndpointsWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"endpoints:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/endpoints/end_1", bytes.NewBufferString(`{"name":"renamed","reason":"rename"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSubscriptionUpdateRequiresSubscriptionsWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"subscriptions:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/subscriptions/sub_1", bytes.NewBufferString(`{"state":"disabled","reason":"pause"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRouteUpdateRequiresRoutesWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"routes:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/routes/rte_1", bytes.NewBufferString(`{"state":"inactive","reason":"pause"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRetryPolicyUpdateRequiresRoutesWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"routes:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/retry-policies/rtp_1", bytes.NewBufferString(`{"max_attempts":6,"reason":"tune"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSchemaGetRequiresSchemasRead(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"events:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/event-types/invoice.paid/schemas/2026-05-01", nil)
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSchemaLifecycleRequiresSchemasWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"schemas:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/event-types/invoice.paid/schemas/2026-05-01", bytes.NewBufferString(`{"state":"deprecated","reason":"replace"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReconciliationCreateRequiresReplayWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleSupport, Scopes: []string{"replay:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/reconciliation-jobs", bytes.NewBufferString(`{"connection_id":"pcn_1","reason":"recover"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuditChainAnchorRequiresSecurityWrite(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleAuditor, Scopes: []string{"audit:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/audit-chain:anchor", bytes.NewBufferString(`{"reason":"daily"}`))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOpsWorkersRequireOpsRead(t *testing.T) {
	server := testServerWithActor(authz.Actor{ID: "usr_1", TenantID: "ten_1", Role: authz.RoleSupport, Scopes: []string{"events:read"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/ops/workers", nil)
	req.Header.Set("Authorization", "Bearer token")

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

type fakeIngestStore struct{}

func (fakeIngestStore) FindSource(context.Context, string, string) (domain.Source, error) {
	return domain.Source{}, app.ErrNotFound
}
func (fakeIngestStore) FindSourceByProviderPath(context.Context, string, string) (domain.Source, error) {
	return domain.Source{}, app.ErrNotFound
}
func (fakeIngestStore) CaptureInbound(context.Context, app.CaptureInboundInput) (app.CaptureInboundResult, error) {
	return app.CaptureInboundResult{}, nil
}

type trackingIngestStore struct {
	called bool
}

func (f *trackingIngestStore) FindSource(context.Context, string, string) (domain.Source, error) {
	f.called = true
	return domain.Source{}, app.ErrNotFound
}
func (f *trackingIngestStore) FindSourceByProviderPath(context.Context, string, string) (domain.Source, error) {
	f.called = true
	return domain.Source{}, app.ErrNotFound
}
func (f *trackingIngestStore) CaptureInbound(context.Context, app.CaptureInboundInput) (app.CaptureInboundResult, error) {
	f.called = true
	return app.CaptureInboundResult{}, nil
}

type acceptingIngestStore struct {
	called bool
}

func (f *acceptingIngestStore) FindSource(context.Context, string, string) (domain.Source, error) {
	return domain.Source{ID: "src_allowed", TenantID: "ten_1", Provider: "internal", Adapter: "internal", State: domain.StateActive}, nil
}
func (f *acceptingIngestStore) FindSourceByProviderPath(context.Context, string, string) (domain.Source, error) {
	return domain.Source{}, app.ErrNotFound
}
func (f *acceptingIngestStore) CaptureInbound(context.Context, app.CaptureInboundInput) (app.CaptureInboundResult, error) {
	f.called = true
	return app.CaptureInboundResult{EventID: "evt_1", ReceiptID: "rcp_1", RawPayloadID: "raw_1", DedupeStatus: domain.DedupeUnique}, nil
}

type routeDispatchIngestStore struct {
	providerLookupCalled bool
	lastTenantID         string
	lastSourceID         string
	lastProvider         string
	lastProviderSourceID string
}

func (f *routeDispatchIngestStore) FindSource(_ context.Context, tenantID, sourceID string) (domain.Source, error) {
	f.lastTenantID = tenantID
	f.lastSourceID = sourceID
	return domain.Source{ID: sourceID, TenantID: tenantID, Provider: "cloudevents", Adapter: "cloudevents", State: domain.StateActive}, nil
}

func (f *routeDispatchIngestStore) FindSourceByProviderPath(_ context.Context, provider, sourceID string) (domain.Source, error) {
	f.providerLookupCalled = true
	f.lastProvider = provider
	f.lastProviderSourceID = sourceID
	return domain.Source{ID: sourceID, TenantID: "ten_provider", Provider: provider, Adapter: provider, State: domain.StateActive}, nil
}

func (f *routeDispatchIngestStore) CaptureInbound(context.Context, app.CaptureInboundInput) (app.CaptureInboundResult, error) {
	return app.CaptureInboundResult{EventID: "evt_1", ReceiptID: "rcp_1", RawPayloadID: "raw_1", DedupeStatus: domain.DedupeUnique}, nil
}

type fakeProducerMTLSLookup struct {
	fingerprint string
}

func (f fakeProducerMTLSLookup) AuthenticateProducerMTLSIdentity(_ context.Context, fingerprintSHA256 string) (authz.Actor, error) {
	if fingerprintSHA256 != f.fingerprint {
		return authz.Actor{}, app.ErrUnauthorized
	}
	return authz.Actor{ID: "producer_mtls:pmi_1", TenantID: "ten_1", Role: authz.RoleDeveloper, Scopes: []string{"events:write"}, SourceID: "src_allowed"}, nil
}

type producerTokenControlStore struct {
	noopControlStore
	client     domain.ProducerClient
	secretHash string
	tokenInput app.ProducerAccessTokenCreateInput
}

func (f *producerTokenControlStore) AuthenticateProducerClient(_ context.Context, clientID, secretHash string) (domain.ProducerClient, error) {
	f.secretHash = secretHash
	if clientID != f.client.ID {
		return domain.ProducerClient{}, app.ErrUnauthorized
	}
	return f.client, nil
}

func (f *producerTokenControlStore) CreateProducerAccessToken(_ context.Context, input app.ProducerAccessTokenCreateInput) (domain.ProducerAccessToken, error) {
	f.tokenInput = input
	return input.Token, nil
}

func NewNoopControl() *app.ControlService {
	return app.NewControlService(noopControlStore{}, ssrf.Validator{Resolver: ssrf.StaticResolver{
		"receiver.example": {netip.MustParseAddr("93.184.216.34")},
		"signals.example":  {netip.MustParseAddr("93.184.216.34")},
		"siem.example":     {netip.MustParseAddr("93.184.216.34")},
	}})
}

func testServerWithActor(actor authz.Actor) *Server {
	return NewServer(ServerConfig{
		Control: NewNoopControl(),
		Ingest:  app.NewIngestService(&fakeIngestStore{}, app.SystemClock{}),
		Auth:    app.NewStaticAuthenticator("token", actor),
		OpenAPI: []byte("openapi: 3.1.0\n"),
	})
}

type noopControlStore struct{}

func (noopControlStore) CreateAPIKey(context.Context, app.APIKeyCreateInput) (domain.APIKey, error) {
	return domain.APIKey{}, nil
}
func (noopControlStore) ListAPIKeys(context.Context, string, int) ([]domain.APIKey, error) {
	return nil, nil
}
func (noopControlStore) RevokeAPIKey(context.Context, string, string, string, string) (domain.APIKey, error) {
	return domain.APIKey{}, nil
}
func (noopControlStore) CreateSource(context.Context, domain.Source) (domain.Source, error) {
	return domain.Source{}, nil
}
func (noopControlStore) ListSources(context.Context, string, int) ([]domain.Source, error) {
	return nil, nil
}
func (noopControlStore) GetSource(context.Context, string, string) (domain.Source, error) {
	return domain.Source{}, nil
}
func (noopControlStore) UpdateSource(context.Context, string, string, string, app.UpdateSourceRequest) (domain.Source, error) {
	return domain.Source{}, nil
}
func (noopControlStore) DeleteSource(context.Context, string, string, string, string) (domain.Source, error) {
	return domain.Source{}, nil
}
func (noopControlStore) RotateSourceSecret(context.Context, string, string, string, app.RotateSourceSecretRequest) (domain.SourceSecretVersion, error) {
	return domain.SourceSecretVersion{}, nil
}
func (noopControlStore) CreateEndpoint(context.Context, domain.Endpoint) (domain.Endpoint, error) {
	return domain.Endpoint{}, nil
}
func (noopControlStore) ListEndpoints(context.Context, string, int) ([]domain.Endpoint, error) {
	return nil, nil
}
func (noopControlStore) GetEndpoint(context.Context, string, string) (domain.Endpoint, error) {
	return domain.Endpoint{}, nil
}
func (noopControlStore) UpdateEndpoint(context.Context, string, string, string, app.UpdateEndpointRequest) (domain.Endpoint, error) {
	return domain.Endpoint{}, nil
}
func (noopControlStore) DeleteEndpoint(context.Context, string, string, string, string) (domain.Endpoint, error) {
	return domain.Endpoint{}, nil
}
func (noopControlStore) TestEndpoint(context.Context, string, string, string, string) (domain.Delivery, error) {
	return domain.Delivery{}, nil
}
func (noopControlStore) RotateEndpointSecret(context.Context, string, string, string, app.RotateEndpointSecretRequest) (domain.EndpointSecretVersion, error) {
	return domain.EndpointSecretVersion{}, nil
}
func (noopControlStore) CreateSubscription(context.Context, domain.Subscription) (domain.Subscription, error) {
	return domain.Subscription{}, nil
}
func (noopControlStore) ListSubscriptions(context.Context, string, int) ([]domain.Subscription, error) {
	return nil, nil
}
func (noopControlStore) GetSubscription(context.Context, string, string) (domain.Subscription, error) {
	return domain.Subscription{}, nil
}
func (noopControlStore) UpdateSubscription(context.Context, string, string, string, app.UpdateSubscriptionRequest) (domain.Subscription, error) {
	return domain.Subscription{}, nil
}
func (noopControlStore) DeleteSubscription(context.Context, string, string, string, string) (domain.Subscription, error) {
	return domain.Subscription{}, nil
}
func (noopControlStore) CreateRoute(context.Context, domain.Route) (domain.Route, error) {
	return domain.Route{}, nil
}
func (noopControlStore) ListRoutes(context.Context, string, int) ([]domain.Route, error) {
	return nil, nil
}
func (noopControlStore) GetRoute(context.Context, string, string) (domain.Route, error) {
	return domain.Route{}, nil
}
func (noopControlStore) UpdateRoute(context.Context, string, string, string, app.UpdateRouteRequest) (domain.Route, error) {
	return domain.Route{}, nil
}
func (noopControlStore) DeleteRoute(context.Context, string, string, string, string) (domain.Route, error) {
	return domain.Route{}, nil
}
func (noopControlStore) ListRouteVersions(context.Context, string, string, int) ([]domain.RouteVersion, error) {
	return nil, nil
}
func (noopControlStore) ActivateRoute(context.Context, string, string, string, string) (domain.Route, error) {
	return domain.Route{}, nil
}
func (noopControlStore) DryRunRoute(context.Context, string, string, string) (app.RouteDryRun, error) {
	return app.RouteDryRun{}, nil
}
func (noopControlStore) CreateRetryPolicy(context.Context, string, string, app.CreateRetryPolicyRequest) (domain.RetryPolicy, error) {
	return domain.RetryPolicy{}, nil
}
func (noopControlStore) ListRetryPolicies(context.Context, string, int) ([]domain.RetryPolicy, error) {
	return nil, nil
}
func (noopControlStore) GetRetryPolicy(context.Context, string, string) (domain.RetryPolicy, error) {
	return domain.RetryPolicy{}, nil
}
func (noopControlStore) UpdateRetryPolicy(context.Context, string, string, string, app.UpdateRetryPolicyRequest) (domain.RetryPolicy, error) {
	return domain.RetryPolicy{}, nil
}
func (noopControlStore) DeleteRetryPolicy(context.Context, string, string, string, string) (domain.RetryPolicy, error) {
	return domain.RetryPolicy{}, nil
}
func (noopControlStore) CreateEventType(context.Context, domain.EventType) (domain.EventType, error) {
	return domain.EventType{}, nil
}
func (noopControlStore) ListEventTypes(context.Context, string, int) ([]domain.EventType, error) {
	return nil, nil
}
func (noopControlStore) GetEventType(context.Context, string, string) (domain.EventType, error) {
	return domain.EventType{}, nil
}
func (noopControlStore) UpdateEventType(context.Context, string, string, string, app.UpdateEventTypeRequest) (domain.EventType, error) {
	return domain.EventType{}, nil
}
func (noopControlStore) DeleteEventType(context.Context, string, string, string, string) (domain.EventType, error) {
	return domain.EventType{}, nil
}
func (noopControlStore) CreateEventSchema(context.Context, domain.EventSchema) (domain.EventSchema, error) {
	return domain.EventSchema{}, nil
}
func (noopControlStore) ListEventSchemas(context.Context, string, string, int) ([]domain.EventSchema, error) {
	return nil, nil
}
func (noopControlStore) GetEventSchema(context.Context, string, string, string) (domain.EventSchema, error) {
	return domain.EventSchema{Schema: `{"type":"object"}`}, nil
}
func (noopControlStore) UpdateEventSchema(context.Context, string, string, string, string, app.UpdateEventSchemaRequest) (domain.EventSchema, error) {
	return domain.EventSchema{}, nil
}
func (noopControlStore) DeleteEventSchema(context.Context, string, string, string, string, string) (domain.EventSchema, error) {
	return domain.EventSchema{}, nil
}
func (noopControlStore) ListEvents(context.Context, string, int) ([]domain.Event, error) {
	return nil, nil
}
func (noopControlStore) GetEvent(context.Context, string, string) (domain.Event, error) {
	return domain.Event{}, nil
}
func (noopControlStore) GetRawPayload(context.Context, string, string, string) (domain.RawPayload, error) {
	return domain.RawPayload{}, nil
}
func (noopControlStore) GetNormalizedEvent(_ context.Context, tenantID, eventID, actorID string, includeData bool) (domain.NormalizedEnvelope, error) {
	return domain.NormalizedEnvelope{ID: "nenv_1", TenantID: tenantID, EventID: eventID, StorageStatus: domain.StorageStatusStored}, nil
}
func (noopControlStore) ListEventTimeline(context.Context, string, string, int) ([]map[string]any, error) {
	return nil, nil
}
func (noopControlStore) CreateIncident(_ context.Context, incident domain.Incident) (domain.Incident, error) {
	incident.ID = "inc_1"
	return incident, nil
}
func (noopControlStore) ListIncidents(context.Context, string, int) ([]domain.Incident, error) {
	return nil, nil
}
func (noopControlStore) GetIncident(_ context.Context, tenantID, incidentID string) (domain.Incident, error) {
	return domain.Incident{ID: incidentID, TenantID: tenantID, Title: "Stripe payment failed", Reason: "support case", State: domain.StateActive}, nil
}
func (noopControlStore) AddIncidentEvent(_ context.Context, tenantID, incidentID, eventID, actorID, reason string) (domain.IncidentEvent, error) {
	return domain.IncidentEvent{ID: "ine_1", TenantID: tenantID, IncidentID: incidentID, EventID: eventID, AddedBy: actorID, Reason: reason}, nil
}
func (noopControlStore) RemoveIncidentEvent(_ context.Context, tenantID, incidentID, eventID, actorID, reason string) (domain.IncidentEvent, error) {
	return domain.IncidentEvent{ID: "ine_1", TenantID: tenantID, IncidentID: incidentID, EventID: eventID, AddedBy: actorID, Reason: reason}, nil
}
func (noopControlStore) ListIncidentEvents(_ context.Context, tenantID, incidentID string) ([]domain.IncidentEvent, error) {
	return []domain.IncidentEvent{{ID: "ine_1", TenantID: tenantID, IncidentID: incidentID, EventID: "evt_1", AddedBy: "usr_1", Reason: "investigate"}}, nil
}
func (noopControlStore) CreateIncidentReportSnapshot(_ context.Context, tenantID, incidentID, actorID, reason string, report app.IncidentReport, markdown string) (domain.IncidentReportSnapshot, error) {
	raw, _ := json.Marshal(report)
	return domain.IncidentReportSnapshot{ID: "irs_1", TenantID: tenantID, IncidentID: incidentID, SchemaVersion: report.SchemaVersion, Report: raw, Markdown: markdown, GeneratedBy: actorID}, nil
}
func (noopControlStore) GetIncidentReportSnapshot(_ context.Context, tenantID, incidentID string) (domain.IncidentReportSnapshot, error) {
	return domain.IncidentReportSnapshot{ID: "irs_1", TenantID: tenantID, IncidentID: incidentID, SchemaVersion: "webhookery.incident_report.v1", Markdown: "incident report"}, nil
}
func (noopControlStore) CreateIncidentEvidenceExport(_ context.Context, tenantID, incidentID, actorID string, req app.CreateIncidentEvidenceExportRequest, report app.IncidentReport, markdown string) (domain.IncidentEvidenceExport, domain.EvidenceExport, error) {
	return domain.IncidentEvidenceExport{ID: "iex_1", TenantID: tenantID, IncidentID: incidentID, ExportID: "exp_1", CreatedBy: actorID}, domain.EvidenceExport{ID: "exp_1", TenantID: tenantID, State: domain.EvidenceExportStateReady, IncludeTimelines: true, CreatedBy: actorID}, nil
}
func (noopControlStore) ListDeliveries(context.Context, string, int) ([]domain.Delivery, error) {
	return nil, nil
}
func (noopControlStore) ListDeliveryAttempts(context.Context, string, string, int) ([]domain.DeliveryAttempt, error) {
	return nil, nil
}
func (noopControlStore) GetDeliveryAttempt(context.Context, string, string) (domain.DeliveryAttempt, error) {
	return domain.DeliveryAttempt{}, nil
}
func (noopControlStore) RetryDelivery(context.Context, string, string, string, string) (domain.Delivery, error) {
	return domain.Delivery{}, nil
}
func (noopControlStore) CancelDelivery(context.Context, string, string, string, string) (domain.Delivery, error) {
	return domain.Delivery{}, nil
}
func (noopControlStore) ListEndpointHealth(context.Context, string, int) ([]domain.EndpointHealth, error) {
	return nil, nil
}
func (noopControlStore) OpsMetrics(context.Context, string) (domain.OpsMetrics, error) {
	return domain.OpsMetrics{DeliveriesByState: map[string]int64{}, ReplayJobsByState: map[string]int64{}}, nil
}
func (noopControlStore) ListWorkers(context.Context, string, int) ([]domain.WorkerStatus, error) {
	return nil, nil
}
func (noopControlStore) GetWorker(context.Context, string, string) (domain.WorkerStatus, error) {
	return domain.WorkerStatus{}, nil
}
func (noopControlStore) ListQueues(context.Context, string) ([]domain.QueueStats, error) {
	return nil, nil
}
func (noopControlStore) OpsStorage(_ context.Context, tenantID string) (domain.OpsStorageStatus, error) {
	return domain.OpsStorageStatus{
		TenantID:                tenantID,
		RawStorageMode:          domain.RawStoragePostgres,
		RawPayloadsByStatus:     map[string]int64{},
		RawPayloadsByBackend:    map[string]int64{},
		ObjectStorageConfigured: false,
	}, nil
}
func (noopControlStore) ListMetricRollups(_ context.Context, tenantID, metricName string, limit int) ([]domain.MetricRollup, error) {
	return []domain.MetricRollup{{ID: "mru_1", TenantID: tenantID, MetricName: metricName, BucketSeconds: 60, Dimensions: map[string]string{}, Value: 1}}, nil
}
func (noopControlStore) CreateAlertRule(_ context.Context, tenantID, actorID string, req app.CreateAlertRuleRequest) (domain.AlertRule, error) {
	return domain.AlertRule{ID: "alr_1", TenantID: tenantID, Name: req.Name, RuleType: req.RuleType, MetricName: req.MetricName, Threshold: req.Threshold, Comparator: req.Comparator, WindowSeconds: req.WindowSeconds, State: req.State, CreatedBy: actorID}, nil
}
func (noopControlStore) ListAlertRules(context.Context, string, int) ([]domain.AlertRule, error) {
	return nil, nil
}
func (noopControlStore) GetAlertRule(_ context.Context, tenantID, alertID string) (domain.AlertRule, error) {
	return domain.AlertRule{ID: alertID, TenantID: tenantID}, nil
}
func (noopControlStore) UpdateAlertRule(_ context.Context, tenantID, alertID, actorID string, req app.UpdateAlertRuleRequest) (domain.AlertRule, error) {
	return domain.AlertRule{ID: alertID, TenantID: tenantID, State: domain.StateActive}, nil
}
func (noopControlStore) DeleteAlertRule(_ context.Context, tenantID, alertID, actorID, reason string) (domain.AlertRule, error) {
	return domain.AlertRule{ID: alertID, TenantID: tenantID, State: domain.StateDisabled}, nil
}
func (noopControlStore) ListAlertFirings(context.Context, string, string, int) ([]domain.AlertFiring, error) {
	return nil, nil
}
func (noopControlStore) GetAlertFiring(_ context.Context, tenantID, firingID string) (domain.AlertFiring, error) {
	return domain.AlertFiring{ID: firingID, TenantID: tenantID, State: domain.AlertFiringOpen}, nil
}
func (noopControlStore) AcknowledgeAlertFiring(_ context.Context, tenantID, firingID, actorID, reason string) (domain.AlertFiring, error) {
	return domain.AlertFiring{ID: firingID, TenantID: tenantID, State: domain.AlertFiringAcknowledged, AcknowledgedBy: actorID, Reason: reason}, nil
}
func (noopControlStore) CreateNotificationChannel(_ context.Context, tenantID, actorID string, req app.CreateNotificationChannelRequest) (domain.NotificationChannel, error) {
	return domain.NotificationChannel{ID: "nch_1", TenantID: tenantID, Name: req.Name, ChannelType: req.ChannelType, URL: req.URL, State: domain.StateActive, SecretHint: "configured", CreatedBy: actorID}, nil
}
func (noopControlStore) ListNotificationChannels(context.Context, string, int) ([]domain.NotificationChannel, error) {
	return nil, nil
}
func (noopControlStore) GetNotificationChannel(_ context.Context, tenantID, channelID string) (domain.NotificationChannel, error) {
	return domain.NotificationChannel{ID: channelID, TenantID: tenantID, ChannelType: domain.NotificationChannelWebhook, URL: "https://signals.example/hook", State: domain.StateActive, SecretHint: "configured"}, nil
}
func (noopControlStore) UpdateNotificationChannel(_ context.Context, tenantID, channelID, actorID string, req app.UpdateNotificationChannelRequest) (domain.NotificationChannel, error) {
	return domain.NotificationChannel{ID: channelID, TenantID: tenantID, State: domain.StateActive, SecretHint: "configured"}, nil
}
func (noopControlStore) DeleteNotificationChannel(_ context.Context, tenantID, channelID, actorID, reason string) (domain.NotificationChannel, error) {
	return domain.NotificationChannel{ID: channelID, TenantID: tenantID, State: domain.StateDisabled, SecretHint: "configured"}, nil
}
func (noopControlStore) TestNotificationChannel(_ context.Context, tenantID, channelID, actorID, reason string) (domain.NotificationDelivery, error) {
	return domain.NotificationDelivery{ID: "ndel_1", TenantID: tenantID, ChannelID: channelID, Transition: "test", State: domain.SignalDeliveryScheduled}, nil
}
func (noopControlStore) ListNotificationDeliveries(_ context.Context, tenantID, state string, limit int) ([]domain.NotificationDelivery, error) {
	return []domain.NotificationDelivery{{ID: "ndel_1", TenantID: tenantID, State: domain.SignalDeliveryScheduled}}, nil
}
func (noopControlStore) ListNotificationDeliveryAttempts(_ context.Context, tenantID, deliveryID string, limit int) ([]domain.NotificationDeliveryAttempt, error) {
	return []domain.NotificationDeliveryAttempt{{ID: "natt_1", TenantID: tenantID, DeliveryID: deliveryID}}, nil
}
func (noopControlStore) RetryNotificationDelivery(_ context.Context, tenantID, deliveryID, actorID, reason string) (domain.NotificationDelivery, error) {
	return domain.NotificationDelivery{ID: deliveryID, TenantID: tenantID, State: domain.SignalDeliveryScheduled}, nil
}
func (noopControlStore) CreateSIEMSink(_ context.Context, tenantID, actorID string, req app.CreateSIEMSinkRequest) (domain.SIEMSink, error) {
	return domain.SIEMSink{ID: "snk_1", TenantID: tenantID, Name: req.Name, SinkType: req.SinkType, URL: req.URL, State: domain.StateActive, SecretHint: "configured", CreatedBy: actorID}, nil
}
func (noopControlStore) ListSIEMSinks(context.Context, string, int) ([]domain.SIEMSink, error) {
	return nil, nil
}
func (noopControlStore) GetSIEMSink(_ context.Context, tenantID, sinkID string) (domain.SIEMSink, error) {
	return domain.SIEMSink{ID: sinkID, TenantID: tenantID, SinkType: domain.SIEMSinkWebhook, URL: "https://siem.example/ingest", State: domain.StateActive, SecretHint: "configured"}, nil
}
func (noopControlStore) UpdateSIEMSink(_ context.Context, tenantID, sinkID, actorID string, req app.UpdateSIEMSinkRequest) (domain.SIEMSink, error) {
	return domain.SIEMSink{ID: sinkID, TenantID: tenantID, State: domain.StateActive, SecretHint: "configured"}, nil
}
func (noopControlStore) DeleteSIEMSink(_ context.Context, tenantID, sinkID, actorID, reason string) (domain.SIEMSink, error) {
	return domain.SIEMSink{ID: sinkID, TenantID: tenantID, State: domain.StateDisabled, SecretHint: "configured"}, nil
}
func (noopControlStore) TestSIEMSink(_ context.Context, tenantID, sinkID, actorID, reason string) (domain.SIEMDelivery, error) {
	return domain.SIEMDelivery{ID: "sdel_1", TenantID: tenantID, SinkID: sinkID, State: domain.SignalDeliveryScheduled}, nil
}
func (noopControlStore) ListSIEMDeliveries(_ context.Context, tenantID, state string, limit int) ([]domain.SIEMDelivery, error) {
	return []domain.SIEMDelivery{{ID: "sdel_1", TenantID: tenantID, State: domain.SignalDeliveryScheduled}}, nil
}
func (noopControlStore) ListSIEMDeliveryAttempts(_ context.Context, tenantID, deliveryID string, limit int) ([]domain.SIEMDeliveryAttempt, error) {
	return []domain.SIEMDeliveryAttempt{{ID: "satt_1", TenantID: tenantID, DeliveryID: deliveryID}}, nil
}
func (noopControlStore) RetrySIEMDelivery(_ context.Context, tenantID, deliveryID, actorID, reason string) (domain.SIEMDelivery, error) {
	return domain.SIEMDelivery{ID: deliveryID, TenantID: tenantID, State: domain.SignalDeliveryScheduled}, nil
}
func (noopControlStore) ListAuditEvents(context.Context, string, int) ([]domain.AuditEvent, error) {
	return nil, nil
}
func (noopControlStore) GetAuditChainHead(context.Context, string) (domain.AuditChainHead, error) {
	return domain.AuditChainHead{}, nil
}
func (noopControlStore) VerifyAuditChain(context.Context, string, app.AuditChainVerifyRequest) (domain.AuditChainVerification, error) {
	return domain.AuditChainVerification{}, nil
}
func (noopControlStore) CreateAuditChainAnchor(context.Context, string, string, app.AuditChainAnchorRequest) (domain.AuditChainAnchor, error) {
	return domain.AuditChainAnchor{}, nil
}
func (noopControlStore) ListAuditChainAnchors(context.Context, string, int) ([]domain.AuditChainAnchor, error) {
	return nil, nil
}
func (noopControlStore) GetAuditChainAnchor(context.Context, string, string) (domain.AuditChainAnchor, error) {
	return domain.AuditChainAnchor{}, nil
}
func (noopControlStore) ListRetentionPolicies(context.Context, string, int) ([]domain.RetentionPolicy, error) {
	return nil, nil
}
func (noopControlStore) CreateRetentionPolicy(_ context.Context, tenantID, actorID string, req app.CreateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	return domain.RetentionPolicy{ID: "ret_1", TenantID: tenantID, ResourceType: req.ResourceType, RetentionDays: req.RetentionDays, State: domain.StateActive, CreatedBy: actorID}, nil
}
func (noopControlStore) UpdateRetentionPolicy(_ context.Context, tenantID, policyID, actorID string, req app.UpdateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	days := 30
	if req.RetentionDays != nil {
		days = *req.RetentionDays
	}
	return domain.RetentionPolicy{ID: policyID, TenantID: tenantID, ResourceType: domain.RetentionResourceRawPayload, RetentionDays: days, State: domain.StateActive, CreatedBy: actorID}, nil
}
func (noopControlStore) CreateProviderConnection(_ context.Context, tenantID, actorID string, req app.CreateProviderConnectionRequest) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{ID: "pcn_1", TenantID: tenantID, Name: req.Name, Provider: req.Provider, State: domain.ProviderConnectionStateActive, CredentialType: req.CredentialType, CredentialHint: "***", Config: req.Config, CreatedBy: actorID}, nil
}
func (noopControlStore) ListProviderConnections(context.Context, string, int) ([]domain.ProviderConnection, error) {
	return nil, nil
}
func (noopControlStore) GetProviderConnection(_ context.Context, tenantID, connectionID string) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{ID: connectionID, TenantID: tenantID, State: domain.ProviderConnectionStateActive}, nil
}
func (noopControlStore) VerifyProviderConnection(_ context.Context, tenantID, connectionID, actorID, reason string) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{ID: connectionID, TenantID: tenantID, State: domain.ProviderConnectionStateActive, CreatedBy: actorID}, nil
}
func (noopControlStore) RevokeProviderConnection(_ context.Context, tenantID, connectionID, actorID, reason string) (domain.ProviderConnection, error) {
	return domain.ProviderConnection{ID: connectionID, TenantID: tenantID, State: domain.ProviderConnectionStateRevoked, CreatedBy: actorID}, nil
}
func (noopControlStore) CreateProviderAdapter(_ context.Context, tenantID, actorID string, req app.CreateProviderAdapterRequest) (domain.ProviderAdapter, error) {
	return domain.ProviderAdapter{ID: "pad_1", TenantID: tenantID, Name: req.Name, Kind: req.Kind, State: domain.AdapterStateDraft}, nil
}
func (noopControlStore) ListProviderAdapters(context.Context, string, int) ([]domain.ProviderAdapter, error) {
	return nil, nil
}
func (noopControlStore) GetProviderAdapter(_ context.Context, tenantID, adapterID string) (domain.ProviderAdapter, error) {
	return domain.ProviderAdapter{ID: adapterID, TenantID: tenantID}, nil
}
func (noopControlStore) CreateAdapterVersion(_ context.Context, tenantID, adapterID, actorID string, req app.CreateAdapterVersionRequest) (domain.AdapterVersion, error) {
	return domain.AdapterVersion{ID: "adv_1", TenantID: tenantID, AdapterID: adapterID, Version: req.Version, State: domain.AdapterStateDraft}, nil
}
func (noopControlStore) ListAdapterVersions(context.Context, string, string, int) ([]domain.AdapterVersion, error) {
	return nil, nil
}
func (noopControlStore) CreateAdapterTestVector(_ context.Context, tenantID, adapterID, versionID, actorID string, req app.CreateAdapterTestVectorRequest) (domain.AdapterTestVector, error) {
	return domain.AdapterTestVector{ID: "atv_1", TenantID: tenantID, AdapterVersionID: versionID, Name: req.Name}, nil
}
func (noopControlStore) TransitionAdapterVersion(_ context.Context, tenantID, adapterID, versionID, actorID string, req app.AdapterVersionTransitionRequest) (domain.AdapterVersion, error) {
	return domain.AdapterVersion{ID: versionID, TenantID: tenantID, AdapterID: adapterID, State: req.Action}, nil
}
func (noopControlStore) DryRunReconciliation(_ context.Context, tenantID string, req app.ReconciliationJobRequest) (domain.ReconciliationJob, error) {
	return domain.ReconciliationJob{ID: "rec_dry", TenantID: tenantID, ConnectionID: req.ConnectionID, State: domain.ReconciliationJobStateCompleted, DryRun: true}, nil
}
func (noopControlStore) CreateReconciliationJob(_ context.Context, tenantID, actorID string, req app.ReconciliationJobRequest) (domain.ReconciliationJob, error) {
	return domain.ReconciliationJob{ID: "rec_1", TenantID: tenantID, ConnectionID: req.ConnectionID, State: domain.ReconciliationJobStateScheduled, CreatedBy: actorID}, nil
}
func (noopControlStore) ListReconciliationJobs(context.Context, string, int) ([]domain.ReconciliationJob, error) {
	return nil, nil
}
func (noopControlStore) GetReconciliationJob(_ context.Context, tenantID, jobID string) (domain.ReconciliationJob, error) {
	return domain.ReconciliationJob{ID: jobID, TenantID: tenantID}, nil
}
func (noopControlStore) ListReconciliationItems(context.Context, string, string, int) ([]domain.ReconciliationItem, error) {
	return nil, nil
}
func (noopControlStore) CancelReconciliationJob(_ context.Context, tenantID, jobID, actorID, reason string) (domain.ReconciliationJob, error) {
	return domain.ReconciliationJob{ID: jobID, TenantID: tenantID, State: domain.ReconciliationJobStateCanceled}, nil
}
func (noopControlStore) CreateAuditExport(_ context.Context, tenantID, actorID string, req app.CreateAuditExportRequest) (domain.EvidenceExport, error) {
	return domain.EvidenceExport{ID: "exp_1", TenantID: tenantID, State: domain.EvidenceExportStateReady, IncludeRawPayloads: req.IncludeRawPayloads, CreatedBy: actorID}, nil
}
func (noopControlStore) ListAuditExports(context.Context, string, int) ([]domain.EvidenceExport, error) {
	return nil, nil
}
func (noopControlStore) GetAuditExport(_ context.Context, tenantID, exportID string) (domain.EvidenceExport, error) {
	return domain.EvidenceExport{ID: exportID, TenantID: tenantID, State: domain.EvidenceExportStateReady}, nil
}
func (noopControlStore) DownloadAuditExport(_ context.Context, tenantID, exportID, actorID string) (app.EvidenceExportDownload, error) {
	return app.EvidenceExportDownload{Export: domain.EvidenceExport{ID: exportID, TenantID: tenantID, State: domain.EvidenceExportStateReady, SHA256: "sha256:test"}, Filename: exportID + ".tar.gz", ContentType: "application/gzip", Body: []byte("bundle")}, nil
}
func (noopControlStore) ListDeadLetter(context.Context, string, int) ([]map[string]any, error) {
	return nil, nil
}
func (noopControlStore) ReleaseDeadLetter(context.Context, string, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) BulkReleaseDeadLetter(context.Context, string, []string, string, string, string) ([]app.ReplayJob, error) {
	return nil, nil
}
func (noopControlStore) ListQuarantine(context.Context, string, int) ([]map[string]any, error) {
	return nil, nil
}
func (noopControlStore) ApproveQuarantine(context.Context, string, string, string, string, bool) (map[string]any, error) {
	return nil, nil
}
func (noopControlStore) RejectQuarantine(context.Context, string, string, string, string) (map[string]any, error) {
	return nil, nil
}
func (noopControlStore) DryRunReplay(context.Context, string, app.ReplayRequest) (app.ReplayDryRun, error) {
	return app.ReplayDryRun{}, nil
}
func (noopControlStore) CreateReplay(context.Context, string, string, app.ReplayRequest) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) ListReplayJobs(context.Context, string, int) ([]app.ReplayJob, error) {
	return nil, nil
}
func (noopControlStore) ApproveReplayJob(context.Context, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) PauseReplayJob(context.Context, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) ResumeReplayJob(context.Context, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) CancelReplayJob(context.Context, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) CreateTransformation(_ context.Context, tenantID, actorID string, req app.CreateTransformationRequest) (domain.Transformation, error) {
	return domain.Transformation{ID: "trn_1", TenantID: tenantID, Name: req.Name, CreatedBy: actorID}, nil
}
func (noopControlStore) ListTransformations(context.Context, string, int) ([]domain.Transformation, error) {
	return nil, nil
}
func (noopControlStore) GetTransformation(context.Context, string, string) (domain.Transformation, error) {
	return domain.Transformation{}, nil
}
func (noopControlStore) CreateTransformationVersion(context.Context, string, string, string, app.CreateTransformationVersionRequest) (domain.TransformationVersion, error) {
	return domain.TransformationVersion{}, nil
}
func (noopControlStore) ListTransformationVersions(context.Context, string, string, int) ([]domain.TransformationVersion, error) {
	return nil, nil
}
func (noopControlStore) ActivateTransformationVersion(context.Context, string, string, string, string, string) (domain.TransformationVersion, error) {
	return domain.TransformationVersion{}, nil
}

type rawPayloadControlStore struct {
	noopControlStore
	rawCalled bool
	tenantID  string
	eventID   string
	actorID   string
}

func (s *rawPayloadControlStore) GetRawPayload(_ context.Context, tenantID, eventID, actorID string) (domain.RawPayload, error) {
	s.rawCalled = true
	s.tenantID = tenantID
	s.eventID = eventID
	s.actorID = actorID
	return domain.RawPayload{
		ID:             "raw_1",
		TenantID:       tenantID,
		EventID:        eventID,
		SHA256:         domain.HashSHA256([]byte("raw evidence bytes")),
		ContentType:    "application/json",
		SizeBytes:      int64(len("raw evidence bytes")),
		Body:           []byte("raw evidence bytes"),
		StorageBackend: domain.RawStoragePostgres,
		StorageStatus:  domain.StorageStatusStored,
	}, nil
}

type replayControlStore struct {
	noopControlStore
	replayCalled     bool
	deadLetterCalled bool
	tenantID         string
	actorID          string
	entryID          string
	reasonCode       string
	reason           string
	replayReq        app.ReplayRequest
}

func (s *replayControlStore) CreateReplay(_ context.Context, tenantID, actorID string, req app.ReplayRequest) (app.ReplayJob, error) {
	s.replayCalled = true
	s.tenantID = tenantID
	s.actorID = actorID
	s.replayReq = req
	return app.ReplayJob{ID: "rpl_1", State: "scheduled", ReasonCode: req.ReasonCode, Reason: req.Reason, ConfigMode: req.ConfigMode, RateLimitPerMinute: req.RateLimitPerMinute, TotalItems: 1}, nil
}

func (s *replayControlStore) ReleaseDeadLetter(_ context.Context, tenantID, entryID, actorID, reasonCode, reason string) (app.ReplayJob, error) {
	s.deadLetterCalled = true
	s.tenantID = tenantID
	s.actorID = actorID
	s.entryID = entryID
	s.reasonCode = reasonCode
	s.reason = reason
	return app.ReplayJob{ID: "rpl_dlq_1", State: "scheduled", ReasonCode: reasonCode, Reason: reason, TotalItems: 1}, nil
}
