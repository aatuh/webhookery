package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"webhookery/internal/domain"
)

func TestIngestCapturesBeforeAccepted(t *testing.T) {
	store := &fakeStore{source: domain.Source{
		ID:                 "src_123",
		TenantID:           "ten_123",
		Provider:           "github",
		Adapter:            "github",
		State:              domain.StateActive,
		VerificationSecret: []byte("secret"),
	}}
	svc := NewIngestService(store, fixedClock(time.Unix(1_700_000_000, 0)))
	body := []byte(`{"id":"evt_123"}`)
	signature := hmacHex([]byte("secret"), body)
	headers := []domain.HeaderPair{
		{Name: "X-Hub-Signature-256", Value: "sha256=" + signature},
		{Name: "X-GitHub-Delivery", Value: "delivery-guid"},
		{Name: "X-GitHub-Event", Value: "push"},
	}

	res, err := svc.Ingest(context.Background(), IngestRequest{
		TenantID: "ten_123",
		SourceID: "src_123",
		Provider: "github",
		RawBody:  body,
		Headers:  headers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted || !store.captured {
		t.Fatalf("expected accepted after capture, result=%+v captured=%v", res, store.captured)
	}
	if store.last.RawPayload.SHA256 != domain.HashSHA256(body) {
		t.Fatalf("raw hash mismatch: %+v", store.last.RawPayload)
	}
	if len(store.last.Normalized.Envelope) == 0 || store.last.Normalized.Type != "push" {
		t.Fatalf("expected normalized envelope for verified provider payload, got %+v", store.last.Normalized)
	}
}

func TestIngestInvalidSignatureCapturesEvidenceButDoesNotAccept(t *testing.T) {
	store := &fakeStore{source: domain.Source{
		ID:                 "src_123",
		TenantID:           "ten_123",
		Provider:           "github",
		Adapter:            "github",
		State:              domain.StateActive,
		VerificationSecret: []byte("secret"),
	}}
	svc := NewIngestService(store, fixedClock(time.Unix(1_700_000_000, 0)))

	res, err := svc.Ingest(context.Background(), IngestRequest{
		TenantID: "ten_123",
		SourceID: "src_123",
		Provider: "github",
		RawBody:  []byte(`{"id":"evt_123"}`),
		Headers: []domain.HeaderPair{
			{Name: "X-Hub-Signature-256", Value: "sha256=bad"},
			{Name: "X-GitHub-Delivery", Value: "delivery-guid"},
			{Name: "X-GitHub-Event", Value: "push"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Accepted {
		t.Fatal("invalid signature must not be accepted")
	}
	if !store.captured || store.last.VerificationOK {
		t.Fatalf("expected rejected evidence capture, captured=%v input=%+v", store.captured, store.last)
	}
	if len(store.last.Normalized.Envelope) != 0 {
		t.Fatal("unverified provider payload must not create a normalized envelope")
	}
}

func TestIngestInternalProducerCreatesNormalizedEnvelope(t *testing.T) {
	store := &fakeStore{source: domain.Source{
		ID:       "src_internal",
		TenantID: "ten_123",
		Provider: "internal",
		Adapter:  "internal",
		State:    domain.StateActive,
	}}
	svc := NewIngestService(store, fixedClock(time.Unix(1_700_000_000, 0)))

	res, err := svc.Ingest(context.Background(), IngestRequest{
		TenantID: "ten_123",
		SourceID: "src_internal",
		Provider: "internal",
		RawBody:  []byte(`{"id":"evt_internal","type":"invoice.paid","source_id":"src_internal","data":{"amount":42}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted {
		t.Fatal("internal producer event should be accepted after durable capture")
	}
	if len(store.last.Normalized.Envelope) == 0 || store.last.Normalized.Provider != "internal" {
		t.Fatalf("expected internal normalized envelope, got %+v", store.last.Normalized)
	}
}

func TestIngestStorageFailureDoesNotAccept(t *testing.T) {
	store := &fakeStore{
		source: domain.Source{ID: "src_123", TenantID: "ten_123", Provider: "github", Adapter: "github", State: domain.StateActive, VerificationSecret: []byte("secret")},
		err:    errors.New("database down"),
	}
	svc := NewIngestService(store, fixedClock(time.Unix(1_700_000_000, 0)))

	_, err := svc.Ingest(context.Background(), IngestRequest{
		TenantID: "ten_123",
		SourceID: "src_123",
		Provider: "github",
		RawBody:  []byte(`{"id":"evt_123"}`),
	})
	if err == nil {
		t.Fatal("expected storage error")
	}
}

func TestIngestCloudEventsStructuredMetadata(t *testing.T) {
	store := &fakeStore{source: domain.Source{
		ID:                 "src_cloud",
		TenantID:           "ten_123",
		Provider:           "cloudevents",
		Adapter:            "cloudevents",
		State:              domain.StateActive,
		VerificationSecret: []byte("unused"),
	}}
	svc := NewIngestService(store, fixedClock(time.Unix(1_700_000_000, 0)))

	res, err := svc.Ingest(context.Background(), IngestRequest{
		TenantID:    "ten_123",
		SourceID:    "src_cloud",
		Provider:    "cloudevents",
		ContentType: "application/cloudevents+json",
		RawBody:     []byte(`{"specversion":"1.0","id":"evt_cloud","type":"customer.created","source":"tests"}`),
		Headers:     []domain.HeaderPair{{Name: "Content-Type", Value: "application/cloudevents+json"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted {
		t.Fatal("structured CloudEvents request should be accepted after capture")
	}
	if store.last.Event.ProviderID != "evt_cloud" || store.last.Event.Type != "customer.created" {
		t.Fatalf("unexpected CloudEvents metadata: %+v", store.last.Event)
	}
}

type fakeStore struct {
	source   domain.Source
	captured bool
	last     CaptureInboundInput
	err      error
}

func (f *fakeStore) FindSource(ctx context.Context, tenantID, sourceID string) (domain.Source, error) {
	if f.source.TenantID != tenantID || f.source.ID != sourceID {
		return domain.Source{}, ErrNotFound
	}
	return f.source, nil
}

func (f *fakeStore) FindSourceByProviderPath(ctx context.Context, provider, sourceID string) (domain.Source, error) {
	if f.source.Provider != provider || f.source.ID != sourceID {
		return domain.Source{}, ErrNotFound
	}
	return f.source, nil
}

func (f *fakeStore) CaptureInbound(ctx context.Context, input CaptureInboundInput) (CaptureInboundResult, error) {
	if f.err != nil {
		return CaptureInboundResult{}, f.err
	}
	f.captured = true
	f.last = input
	return CaptureInboundResult{
		EventID:      "evt_stored",
		ReceiptID:    "rcp_stored",
		RawPayloadID: "raw_stored",
		DedupeStatus: domain.DedupeUnique,
	}, nil
}

type fixedClock time.Time

func (f fixedClock) Now() time.Time { return time.Time(f) }

func hmacHex(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
