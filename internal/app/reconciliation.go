package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"webhookery/internal/domain"
	"webhookery/internal/reconcile"
	"webhookery/internal/worker"
)

type ReconciliationAdapterRegistry interface {
	Adapter(provider string) (reconcile.Adapter, bool)
}

type ReconciliationWorkStore interface {
	GetReconciliationConnection(ctx context.Context, tenantID, connectionID string) (domain.ProviderConnection, string, error)
	GetReconciliationWork(ctx context.Context, tenantID, jobID string) (ReconciliationWork, error)
	StartReconciliationJob(ctx context.Context, tenantID, jobID string) (bool, error)
	RecordProviderAPIEvidence(ctx context.Context, record ProviderAPIEvidenceRecord) (string, error)
	FindLocalProviderEvent(ctx context.Context, tenantID string, conn domain.ProviderConnection, providerObjectID string) (string, error)
	CaptureRecoveredProviderEvent(ctx context.Context, input RecoveredProviderEventCapture) (string, error)
	InsertReconciliationItem(ctx context.Context, input ReconciliationItemRecord) (string, error)
	AttachProviderEvidenceToItem(ctx context.Context, tenantID, itemID, evidenceID string) error
	UpdateReconciliationCursor(ctx context.Context, tenantID, jobID, cursor string) error
	CompleteReconciliationJob(ctx context.Context, tenantID, jobID string) error
	FailReconciliationJob(ctx context.Context, tenantID, jobID, errorText string) error
}

type ReconciliationWork struct {
	Job        domain.ReconciliationJob
	Connection domain.ProviderConnection
	Credential string
}

type ProviderAPIEvidenceRecord struct {
	TenantID     string
	JobID        string
	ItemID       string
	ConnectionID string
	Provider     string
	Evidence     ProviderAPIEvidence
}

type ProviderAPIEvidence struct {
	Method     string
	URL        string
	StatusCode int
	Body       []byte
	Error      string
}

type RecoveredProviderEventCapture struct {
	Connection     domain.ProviderConnection
	ObjectID       string
	EventType      string
	RawBody        []byte
	RequestHeaders map[string]string
	RouteRecovered bool
}

type ReconciliationItemRecord struct {
	TenantID            string
	JobID               string
	Provider            string
	ObjectID            string
	ObjectType          string
	Outcome             string
	LocalEventID        string
	RecoveredEventID    string
	EvidenceID          string
	RedeliveryRequested bool
	Error               string
	Metadata            json.RawMessage
}

type ReconciliationService struct {
	store    ReconciliationWorkStore
	registry ReconciliationAdapterRegistry
}

func NewReconciliationService(store ReconciliationWorkStore, registry ReconciliationAdapterRegistry) *ReconciliationService {
	if registry == nil {
		builtIn := reconcile.BuiltInRegistry(nil)
		registry = builtIn
	}
	return &ReconciliationService{store: store, registry: registry}
}

func (s *ReconciliationService) DryRunReconciliation(ctx context.Context, tenantID string, req ReconciliationJobRequest) (domain.ReconciliationJob, error) {
	conn, credential, err := s.store.GetReconciliationConnection(ctx, tenantID, req.ConnectionID)
	if err != nil {
		return domain.ReconciliationJob{}, err
	}
	adapter, ok := s.registry.Adapter(conn.Provider)
	if !ok {
		return domain.ReconciliationJob{}, ErrInvalidInput
	}
	now := time.Now().UTC()
	job := domain.ReconciliationJob{
		ID:              "dry_run",
		TenantID:        tenantID,
		ConnectionID:    conn.ID,
		Provider:        conn.Provider,
		State:           domain.ReconciliationJobStateCompleted,
		DryRun:          true,
		CaptureMissing:  req.CaptureMissing,
		RouteRecovered:  req.RouteRecovered,
		RedeliverFailed: req.RedeliverFailed,
		ScopeObjectID:   req.ScopeObjectID,
		WindowStart:     req.WindowStart,
		WindowEnd:       req.WindowEnd,
		Reason:          req.Reason,
		CreatedAt:       now,
		CompletedAt:     now,
	}
	caps := adapter.Capabilities(conn.Config)
	if !caps.CanScanEvents {
		job.TotalItems = 1
		job.UnrecoverableItems = 1
		job.Error = strings.Join(caps.Limitations, "; ")
		return job, nil
	}
	scan, err := adapter.Scan(ctx, reconcile.ScanRequest{
		Connection: reconcile.Connection{
			ID: conn.ID, Provider: conn.Provider, CredentialType: conn.CredentialType, Credential: credential, Config: conn.Config,
		},
		WindowStart: req.WindowStart, WindowEnd: req.WindowEnd, ScopeObjectID: req.ScopeObjectID,
		CaptureMissing: req.CaptureMissing, RedeliverFailed: req.RedeliverFailed,
	})
	if err != nil {
		job.State = domain.ReconciliationJobStateFailed
		job.Error = providerErrorForDB(err)
		return job, nil
	}
	for _, object := range scan.Objects {
		job.TotalItems++
		localID, err := s.store.FindLocalProviderEvent(ctx, tenantID, conn, object.ID)
		if err != nil {
			return domain.ReconciliationJob{}, err
		}
		if localID != "" {
			job.MatchedItems++
		} else {
			job.MissingItems++
		}
		if object.Failed && req.RedeliverFailed && object.Redeliverable {
			job.RedeliveredItems++
		}
	}
	return job, nil
}

func (s *ReconciliationService) RunReconciliationJob(ctx context.Context, tenantID, jobID string) error {
	work, err := s.store.GetReconciliationWork(ctx, tenantID, jobID)
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	job := work.Job
	if job.State == domain.ReconciliationJobStateCanceled || job.State == domain.ReconciliationJobStateCompleted {
		return nil
	}
	adapter, ok := s.registry.Adapter(work.Connection.Provider)
	if !ok {
		return s.store.FailReconciliationJob(ctx, tenantID, jobID, providerErrorForDB(reconcile.ProviderError{Class: reconcile.ErrorUnsupported, Message: "unsupported provider"}))
	}
	started, err := s.store.StartReconciliationJob(ctx, tenantID, jobID)
	if err != nil {
		return err
	}
	if !started {
		return worker.ErrDeferred
	}
	caps := adapter.Capabilities(work.Connection.Config)
	if !caps.CanScanEvents {
		metadata, _ := json.Marshal(map[string]any{"limitations": caps.Limitations})
		if _, err := s.store.InsertReconciliationItem(ctx, ReconciliationItemRecord{
			TenantID: tenantID, JobID: jobID, Provider: work.Connection.Provider, ObjectID: work.Connection.Provider + ":unsupported", ObjectType: "capability",
			Outcome: domain.ReconciliationOutcomeUnrecoverable, Error: strings.Join(caps.Limitations, "; "), Metadata: metadata,
		}); err != nil {
			return err
		}
		return s.store.CompleteReconciliationJob(ctx, tenantID, jobID)
	}
	scan, err := adapter.Scan(ctx, reconcile.ScanRequest{
		Connection: reconcile.Connection{
			ID: work.Connection.ID, Provider: work.Connection.Provider, CredentialType: work.Connection.CredentialType, Credential: work.Credential, Config: work.Connection.Config,
		},
		WindowStart: job.WindowStart, WindowEnd: job.WindowEnd, ScopeObjectID: job.ScopeObjectID, Cursor: job.Cursor,
		CaptureMissing: job.CaptureMissing, RedeliverFailed: job.RedeliverFailed,
	})
	for _, ev := range scan.Evidence {
		if _, recErr := s.recordProviderAPIEvidence(ctx, tenantID, jobID, "", work.Connection, ev); recErr != nil {
			return recErr
		}
	}
	if err != nil {
		return s.store.FailReconciliationJob(ctx, tenantID, jobID, providerErrorForDB(err))
	}
	for _, object := range scan.Objects {
		if err := s.reconcileProviderObject(ctx, job, work.Connection, work.Credential, adapter, object); err != nil {
			return s.store.FailReconciliationJob(ctx, tenantID, jobID, providerErrorForDB(err))
		}
	}
	if scan.NextCursor != "" {
		if err := s.store.UpdateReconciliationCursor(ctx, tenantID, jobID, scan.NextCursor); err != nil {
			return err
		}
	}
	return s.store.CompleteReconciliationJob(ctx, tenantID, jobID)
}

func (s *ReconciliationService) reconcileProviderObject(ctx context.Context, job domain.ReconciliationJob, conn domain.ProviderConnection, credential string, adapter reconcile.Adapter, object reconcile.ProviderObject) error {
	tenantID := job.TenantID
	localEventID, err := s.store.FindLocalProviderEvent(ctx, tenantID, conn, object.ID)
	if err != nil {
		return err
	}
	outcome := domain.ReconciliationOutcomeMatched
	if localEventID == "" {
		outcome = domain.ReconciliationOutcomeMissing
	}
	metadata, _ := json.Marshal(object.Metadata)
	var evidenceID string
	var recoveredEventID string
	var errText string
	if localEventID == "" && job.CaptureMissing {
		lookupObject := object
		lookupEvidence := []reconcile.Evidence(nil)
		if len(lookupObject.RawBody) == 0 || !lookupObject.Recoverable {
			lookedUp, evs, lookupErr := adapter.Lookup(ctx, reconcile.Connection{ID: conn.ID, Provider: conn.Provider, CredentialType: conn.CredentialType, Credential: credential, Config: conn.Config}, providerLookupID(object))
			lookupEvidence = evs
			if lookupErr == nil {
				lookupObject = lookedUp
			} else if errors.Is(lookupErr, reconcile.ErrUnsupported) {
				outcome = domain.ReconciliationOutcomeUnrecoverable
				errText = "provider does not expose recoverable payload evidence for this object"
			} else {
				outcome = domain.ReconciliationOutcomeFailed
				errText = providerErrorForDB(lookupErr)
			}
		}
		for _, ev := range lookupEvidence {
			id, recErr := s.recordProviderAPIEvidence(ctx, tenantID, job.ID, "", conn, ev)
			if recErr != nil {
				return recErr
			}
			evidenceID = id
		}
		if outcome == domain.ReconciliationOutcomeMissing && lookupObject.Recoverable && len(lookupObject.RawBody) > 0 {
			recoveredEventID, err = s.store.CaptureRecoveredProviderEvent(ctx, RecoveredProviderEventCapture{
				Connection: conn, ObjectID: lookupObject.ID, EventType: lookupObject.EventType,
				RawBody: append([]byte(nil), lookupObject.RawBody...), RequestHeaders: lookupObject.RequestHeaders,
				RouteRecovered: job.RouteRecovered,
			})
			if err != nil {
				outcome = domain.ReconciliationOutcomeFailed
				errText = err.Error()
			} else {
				outcome = domain.ReconciliationOutcomeCaptured
			}
		} else if outcome == domain.ReconciliationOutcomeMissing {
			outcome = domain.ReconciliationOutcomeUnrecoverable
			errText = "provider API did not include a recoverable payload body"
		}
	}
	redeliveryRequested := false
	if job.RedeliverFailed && object.Failed && object.Redeliverable {
		evs, redeliverErr := adapter.RequestRedelivery(ctx, reconcile.Connection{ID: conn.ID, Provider: conn.Provider, CredentialType: conn.CredentialType, Credential: credential, Config: conn.Config}, providerLookupID(object))
		for _, ev := range evs {
			id, recErr := s.recordProviderAPIEvidence(ctx, tenantID, job.ID, "", conn, ev)
			if recErr != nil {
				return recErr
			}
			evidenceID = id
		}
		if redeliverErr != nil {
			outcome = domain.ReconciliationOutcomeFailed
			errText = providerErrorForDB(redeliverErr)
		} else {
			outcome = domain.ReconciliationOutcomeRedeliveryRequested
			redeliveryRequested = true
		}
	}
	itemID, err := s.store.InsertReconciliationItem(ctx, ReconciliationItemRecord{
		TenantID: tenantID, JobID: job.ID, Provider: conn.Provider, ObjectID: object.ID, ObjectType: object.ObjectType,
		Outcome: outcome, LocalEventID: localEventID, RecoveredEventID: recoveredEventID, EvidenceID: evidenceID,
		RedeliveryRequested: redeliveryRequested, Error: errText, Metadata: metadata,
	})
	if err != nil {
		return err
	}
	if evidenceID != "" {
		return s.store.AttachProviderEvidenceToItem(ctx, tenantID, itemID, evidenceID)
	}
	return nil
}

func (s *ReconciliationService) recordProviderAPIEvidence(ctx context.Context, tenantID, jobID, itemID string, conn domain.ProviderConnection, ev reconcile.Evidence) (string, error) {
	return s.store.RecordProviderAPIEvidence(ctx, ProviderAPIEvidenceRecord{
		TenantID: tenantID, JobID: jobID, ItemID: itemID, ConnectionID: conn.ID, Provider: conn.Provider,
		Evidence: ProviderAPIEvidence{Method: ev.Method, URL: ev.URL, StatusCode: ev.StatusCode, Body: append([]byte(nil), ev.Body...), Error: ev.Error},
	})
}

func providerLookupID(object reconcile.ProviderObject) string {
	if value, ok := object.Metadata["delivery_id"]; ok && fmt.Sprint(value) != "" {
		return fmt.Sprint(value)
	}
	return object.ID
}

func providerErrorForDB(err error) string {
	if err == nil {
		return ""
	}
	var providerErr reconcile.ProviderError
	if errors.As(err, &providerErr) && providerErr.Class != "" {
		return providerErr.Class
	}
	if errors.Is(err, reconcile.ErrUnsupported) {
		return reconcile.ErrorUnsupported
	}
	msg := err.Error()
	for _, marker := range []string{"sk_", "ghp_", "github_pat_", "xoxb-", "shpat_"} {
		if strings.Contains(msg, marker) {
			return "provider request failed"
		}
	}
	return msg
}
