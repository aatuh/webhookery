package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	return app.NewControlService(noopControlStore{}, ssrf.Validator{Resolver: ssrf.StaticResolver{}})
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
	return domain.EventSchema{}, nil
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
func (noopControlStore) ReleaseDeadLetter(context.Context, string, string, string, string) (app.ReplayJob, error) {
	return app.ReplayJob{}, nil
}
func (noopControlStore) BulkReleaseDeadLetter(context.Context, string, []string, string, string) ([]app.ReplayJob, error) {
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
