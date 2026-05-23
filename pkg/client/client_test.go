package client

import (
	"context"
	"encoding/json"
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
