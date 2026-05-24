package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"webhookery/internal/domain"
	"webhookery/internal/provider"
	"webhookery/pkg/verifier"
)

var (
	ErrNotFound = errors.New("not found")
	ErrGone     = errors.New("gone")
)

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

type IngestStore interface {
	FindSource(ctx context.Context, tenantID, sourceID string) (domain.Source, error)
	FindSourceByProviderPath(ctx context.Context, provider, sourceID string) (domain.Source, error)
	CaptureInbound(ctx context.Context, input CaptureInboundInput) (CaptureInboundResult, error)
}

type AdapterDefinitionLookup interface {
	ActiveDeclarativeAdapterVersion(ctx context.Context, tenantID, adapterName string) (domain.AdapterVersion, error)
}

type IngestService struct {
	store    IngestStore
	clock    Clock
	registry provider.Registry
}

func NewIngestService(store IngestStore, clock Clock) *IngestService {
	if clock == nil {
		clock = SystemClock{}
	}
	return &IngestService{store: store, clock: clock, registry: provider.BuiltInRegistry()}
}

type IngestRequest struct {
	TenantID    string
	SourceID    string
	Provider    string
	RawBody     []byte
	Headers     []domain.HeaderPair
	ContentType string
	RemoteIP    string
}

type IngestResult struct {
	Accepted     bool
	EventID      string
	ReceiptID    string
	RawPayloadID string
	TraceID      string
	VerifyReason string
	DedupeStatus string
}

type CaptureInboundInput struct {
	Source         domain.Source
	RawPayload     domain.RawPayload
	Receipt        domain.Receipt
	Event          domain.Event
	Normalized     domain.NormalizedEnvelope
	VerificationOK bool
	VerifyReason   string
}

type CaptureInboundResult struct {
	EventID      string
	ReceiptID    string
	RawPayloadID string
	DedupeStatus string
}

func (s *IngestService) Ingest(ctx context.Context, req IngestRequest) (IngestResult, error) {
	source, err := s.store.FindSource(ctx, req.TenantID, req.SourceID)
	if err != nil {
		return IngestResult{}, err
	}
	return s.capture(ctx, source, req)
}

func (s *IngestService) IngestProviderPath(ctx context.Context, providerName, sourceID string, req IngestRequest) (IngestResult, error) {
	source, err := s.store.FindSourceByProviderPath(ctx, providerName, sourceID)
	if err != nil {
		return IngestResult{}, err
	}
	req.TenantID = source.TenantID
	req.SourceID = source.ID
	req.Provider = providerName
	return s.capture(ctx, source, req)
}

func (s *IngestService) capture(ctx context.Context, source domain.Source, req IngestRequest) (IngestResult, error) {
	if source.State != "" && source.State != domain.StateActive {
		return IngestResult{}, fmt.Errorf("%w: source is not active", ErrInvalidInput)
	}
	now := s.clock.Now()
	adapter, ok := s.registry.Adapter(source.Adapter)
	var adapterDefinition json.RawMessage
	var adapterVersionID string
	if !ok {
		adapter, ok = s.registry.Adapter(source.Provider)
	}
	if !ok {
		if lookup, supports := s.store.(AdapterDefinitionLookup); supports {
			version, err := lookup.ActiveDeclarativeAdapterVersion(ctx, source.TenantID, source.Adapter)
			if err == nil && version.Kind == domain.AdapterKindDeclarative && version.State == domain.AdapterStateActive {
				if custom, err := provider.NewDeclarativeAdapter(version.Definition); err == nil {
					adapter = custom
					adapterDefinition = version.Definition
					adapterVersionID = version.ID
					ok = true
				}
			}
		}
	}
	if !ok {
		adapter, _ = s.registry.Adapter("generic-unsafe")
	}
	headers := domain.CanonicalHeaders(req.Headers)
	verify := provider.VerifyResult{Verified: false, Reason: verifier.ReasonMissingSignature}
	secrets := source.VerificationSecrets
	if len(secrets) == 0 && len(source.VerificationSecret) > 0 {
		secrets = [][]byte{source.VerificationSecret}
	}
	if len(secrets) == 0 {
		secrets = [][]byte{nil}
	}
	for _, secret := range secrets {
		verify = adapter.Verify(provider.VerifyInput{
			RawBody: req.RawBody,
			Headers: headers,
			Secret:  secret,
			Now:     now,
		})
		if verify.Verified {
			break
		}
	}
	rawHash := domain.HashSHA256(req.RawBody)
	providerEventID, eventType := extractEventMetadataForProvider(source.Adapter, req.RawBody, headers)
	if len(adapterDefinition) != 0 {
		if id, typ := provider.DeclarativeMetadata(adapterDefinition, req.RawBody, headers); id != "" || typ != "" {
			providerEventID, eventType = firstNonEmpty(id, providerEventID), firstNonEmpty(typ, eventType)
		}
	}
	dedupeKey := dedupeKey(source, providerEventID, rawHash)
	normalized := domain.NormalizedEnvelope{}
	if verify.Verified {
		env, err := provider.Normalize(provider.NormalizeInput{
			Adapter:           source.Adapter,
			Provider:          source.Provider,
			TenantID:          source.TenantID,
			SourceID:          source.ID,
			RawBody:           req.RawBody,
			Headers:           headers,
			Verified:          verify.Verified,
			VerifyReason:      verify.Reason,
			RawHash:           rawHash,
			AdapterDefinition: adapterDefinition,
		})
		if err == nil {
			normalized = domain.NormalizedEnvelope{
				TenantID:         source.TenantID,
				AdapterVersionID: adapterVersionID,
				Provider:         source.Provider,
				ProviderEventID:  env.ProviderEventID,
				Type:             env.Type,
				Source:           env.Source,
				Subject:          env.Subject,
				Envelope:         append([]byte(nil), env.Envelope...),
				Data:             append([]byte(nil), env.Data...),
				Metadata:         append([]byte(nil), env.Metadata...),
				EnvelopeSHA256:   env.EnvelopeHash,
				DataSHA256:       env.DataHash,
				MetadataSHA256:   env.MetadataHash,
				StorageStatus:    domain.StorageStatusStored,
				CreatedAt:        now,
			}
			if providerEventID == "" {
				providerEventID = env.ProviderEventID
			}
			if eventType == "" {
				eventType = env.Type
			}
		}
	}
	input := CaptureInboundInput{
		Source: source,
		RawPayload: domain.RawPayload{
			TenantID:    source.TenantID,
			SHA256:      rawHash,
			ContentType: req.ContentType,
			SizeBytes:   int64(len(req.RawBody)),
			Body:        append([]byte(nil), req.RawBody...),
			CreatedAt:   now,
		},
		Receipt: domain.Receipt{
			TenantID:     source.TenantID,
			SourceID:     source.ID,
			RawHeaders:   append([]domain.HeaderPair(nil), req.Headers...),
			RemoteIP:     req.RemoteIP,
			ReceivedAt:   now,
			VerifyOK:     verify.Verified,
			VerifyReason: verify.Reason,
		},
		Event: domain.Event{
			TenantID:       source.TenantID,
			SourceID:       source.ID,
			Provider:       source.Provider,
			Type:           eventType,
			ProviderID:     providerEventID,
			RawPayloadHash: rawHash,
			Verified:       verify.Verified,
			VerifyReason:   verify.Reason,
			DedupeKey:      dedupeKey,
			DedupeStatus:   domain.DedupeUnique,
			ReceivedAt:     now,
		},
		Normalized:     normalized,
		VerificationOK: verify.Verified,
		VerifyReason:   verify.Reason,
	}
	result, err := s.store.CaptureInbound(ctx, input)
	if err != nil {
		return IngestResult{}, err
	}
	accepted := verify.Verified || source.Adapter == "cloudevents"
	return IngestResult{
		Accepted:     accepted,
		EventID:      result.EventID,
		ReceiptID:    result.ReceiptID,
		RawPayloadID: result.RawPayloadID,
		VerifyReason: verify.Reason,
		DedupeStatus: result.DedupeStatus,
	}, nil
}

func extractEventMetadataForProvider(adapter string, raw []byte, headers map[string][]string) (string, string) {
	if strings.EqualFold(adapter, "cloudevents") {
		id := firstHeader(headers, "ce-id")
		eventType := firstHeader(headers, "ce-type")
		if id != "" || eventType != "" {
			return id, eventType
		}
	}
	providerID, eventType := extractEventMetadata(raw)
	if eventType == "" {
		eventType = firstHeader(headers, "x-github-event")
	}
	if providerID == "" && strings.EqualFold(adapter, "github") {
		providerID = firstHeader(headers, "x-github-delivery")
	}
	if providerID == "" && strings.EqualFold(adapter, "shopify") {
		providerID = firstHeader(headers, "x-shopify-webhook-id")
	}
	return providerID, eventType
}

func extractEventMetadata(raw []byte) (string, string) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", ""
	}
	providerID, _ := payload["id"].(string)
	eventType, _ := payload["type"].(string)
	if eventType == "" {
		if v, ok := payload["event"].(map[string]any); ok {
			eventType, _ = v["type"].(string)
		}
	}
	if providerID == "" {
		providerID, _ = payload["event_id"].(string)
	}
	return providerID, eventType
}

func dedupeKey(source domain.Source, providerID, rawHash string) string {
	if providerID != "" {
		return strings.Join([]string{source.Provider, source.TenantID, source.ID, providerID}, ":")
	}
	return strings.Join([]string{source.Provider, source.TenantID, source.ID, rawHash}, ":")
}

func firstHeader(headers map[string][]string, name string) string {
	values := headers[strings.ToLower(name)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func IsInvalidSignature(result IngestResult) bool {
	return result.VerifyReason == verifier.ReasonInvalidSignature ||
		result.VerifyReason == verifier.ReasonMissingSignature ||
		result.VerifyReason == verifier.ReasonExpiredTimestamp ||
		result.VerifyReason == verifier.ReasonMalformedHeader
}
