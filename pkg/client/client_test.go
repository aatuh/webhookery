package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateEventSendsBearerAndProductBody(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"Accepted":true,"EventID":"evt_1","DedupeStatus":"unique"}`))
	}))
	defer server.Close()

	c, err := New(server.URL, "key_123")
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.CreateEvent(context.Background(), ProductEvent{
		ID: "evt_1", Type: "invoice.paid", SourceID: "src_internal", Data: map[string]any{"amount": 42},
	}, WithIdempotencyKey("invoice:1:paid"))
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer key_123" {
		t.Fatalf("unexpected auth header %q", gotAuth)
	}
	if gotBody["source_id"] != "src_internal" {
		t.Fatalf("missing source_id in body: %#v", gotBody)
	}
	if !result.Accepted || result.EventID != "evt_1" || result.DedupeStatus != "unique" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestClientRejectsUnsafeBaseURL(t *testing.T) {
	if _, err := New("file:///tmp/webhookery.sock", "key"); err == nil {
		t.Fatal("expected unsafe base URL rejection")
	}
	if _, err := New("https://", "key"); err == nil {
		t.Fatal("expected missing host rejection")
	}
}

func TestClientUsesInjectedHTTPClientAndJoinsBasePath(t *testing.T) {
	called := false
	custom := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		if req.URL.String() != "https://api.example.test/base/v1/audit-chain/head" {
			t.Fatalf("unexpected URL %s", req.URL.String())
		}
		if req.Header.Get("Authorization") != "Bearer key_123" {
			t.Fatalf("missing bearer auth")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"tenant_id":"ten_1","sequence":3,"chain_hash":"sha256:def","unchained_events":0}`)),
			Request:    req,
		}, nil
	})}

	c, err := New("https://api.example.test/base/", "key_123", WithHTTPClient(custom))
	if err != nil {
		t.Fatal(err)
	}
	head, err := c.AuditChainHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !called || head.Sequence != 3 {
		t.Fatalf("custom client not used or unexpected head: called=%t head=%+v", called, head)
	}
}

func TestCreateEventValidatesRequiredFieldsBeforeRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	c, err := New(server.URL, "key_123")
	if err != nil {
		t.Fatal(err)
	}

	tests := []ProductEvent{
		{ID: "evt_1", Type: "invoice.paid"},
		{Type: "invoice.paid", SourceID: "src_1"},
		{ID: "evt_1", SourceID: "src_1"},
	}
	for _, event := range tests {
		if _, err := c.CreateEvent(context.Background(), event); err == nil {
			t.Fatalf("expected validation error for %+v", event)
		}
	}
	if called {
		t.Fatal("request should not be sent for invalid product event")
	}
}

func TestIdempotencyKeyIgnoresBlankValues(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://api.example.test/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	WithIdempotencyKey("  ")(req)
	if req.Header.Get("Idempotency-Key") != "" {
		t.Fatalf("blank idempotency key should not be set: %+v", req.Header)
	}
}

func TestClientErrorDoesNotLeakBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()
	c, err := New(server.URL, "secret-key")
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.CreateEvent(context.Background(), ProductEvent{ID: "evt_1", Type: "x", SourceID: "src"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "secret-key") {
		t.Fatalf("error leaked API key: %v", err)
	}
}

func TestHTTPErrorFormatsEmptyAndNonEmptyBodies(t *testing.T) {
	if got := (HTTPError{StatusCode: http.StatusInternalServerError}).Error(); got != "webhookery API returned HTTP 500" {
		t.Fatalf("unexpected empty-body error %q", got)
	}
	if got := (HTTPError{StatusCode: http.StatusBadRequest, Body: "bad request"}).Error(); got != "webhookery API returned HTTP 400: bad request" {
		t.Fatalf("unexpected body error %q", got)
	}
}

func TestAuditChainHead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audit-chain/head" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer key_123" {
			t.Fatalf("missing bearer auth")
		}
		_, _ = w.Write([]byte(`{"tenant_id":"ten_1","sequence":7,"chain_hash":"sha256:abc","unchained_events":0}`))
	}))
	defer server.Close()
	c, err := New(server.URL, "key_123")
	if err != nil {
		t.Fatal(err)
	}
	head, err := c.AuditChainHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if head.Sequence != 7 || head.ChainHash != "sha256:abc" {
		t.Fatalf("unexpected head: %+v", head)
	}
}

func TestVerifyAuditChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audit-chain:verify" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var req AuditChainVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.FromSequence != 2 || req.ToSequence != 5 {
			t.Fatalf("unexpected request: %+v", req)
		}
		_, _ = w.Write([]byte(`{"tenant_id":"ten_1","valid":true,"from_sequence":2,"to_sequence":5,"checked_entries":4,"failures":[]}`))
	}))
	defer server.Close()
	c, err := New(server.URL, "key_123")
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.VerifyAuditChain(context.Background(), AuditChainVerifyRequest{FromSequence: 2, ToSequence: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.CheckedEntries != 4 {
		t.Fatalf("unexpected verification: %+v", result)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
