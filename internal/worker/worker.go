package worker

import (
	"context"
	"errors"
)

var ErrDeferred = errors.New("work deferred")

type OutboxItem struct {
	ID         string
	TenantID   string
	Kind       string
	ResourceID string
}

type OutboxStore interface {
	ClaimOutbox(ctx context.Context, workerID string, limit int) ([]OutboxItem, error)
	CompleteOutbox(ctx context.Context, outboxID string) error
}

type OutboxProcessor interface {
	ProcessOutbox(ctx context.Context, item OutboxItem) error
}

type DeliveryItem struct {
	ID                string
	TenantID          string
	EventID           string
	EndpointID        string
	EndpointURL       string
	AttemptCount      int
	RetryPolicyID     string
	RetrySeed         string
	SigningSecret     []byte
	SigningKeyID      string
	SigningKeyVersion int
	MTLSClientCertPEM []byte
	MTLSClientKeyPEM  []byte
	Body              []byte
}

type DeliveryResult struct {
	StatusCode        int
	ResponseBody      []byte
	ResponseTruncated bool
	FailureClass      string
}

type DeliveryClient interface {
	Deliver(ctx context.Context, rawURL string, body []byte, secret []byte, keyID string, keyVersion int, mtlsCertPEM, mtlsKeyPEM []byte) (DeliveryResult, error)
}

type DeliveryStore interface {
	ClaimDueDeliveries(ctx context.Context, workerID string, limit int) ([]DeliveryItem, error)
	RecordDeliveryAttempt(ctx context.Context, item DeliveryItem, result DeliveryResult, deliverErr error) error
}

type SignalDeliveryItem struct {
	ID           string
	TenantID     string
	URL          string
	AttemptCount int
	Secret       []byte
	Body         []byte
}

type SignalDeliveryResult struct {
	StatusCode        int
	ResponseBody      []byte
	ResponseTruncated bool
	FailureClass      string
}

type SignalClient interface {
	Deliver(ctx context.Context, rawURL string, body []byte, secret []byte) (SignalDeliveryResult, error)
}

type NotificationDeliveryStore interface {
	ClaimNotificationDeliveries(ctx context.Context, workerID string, limit int) ([]SignalDeliveryItem, error)
	RecordNotificationDeliveryAttempt(ctx context.Context, item SignalDeliveryItem, result SignalDeliveryResult, deliverErr error) error
}

type SIEMDeliveryStore interface {
	EnqueueSIEMDeliveries(ctx context.Context, workerID string, limit int) error
	ClaimSIEMDeliveries(ctx context.Context, workerID string, limit int) ([]SignalDeliveryItem, error)
	RecordSIEMDeliveryAttempt(ctx context.Context, item SignalDeliveryItem, result SignalDeliveryResult, deliverErr error) error
}

type RetentionStore interface {
	ApplyRetentionPolicies(ctx context.Context, workerID string, limit int) error
}

type MetricsStore interface {
	RefreshMetricsRollups(ctx context.Context, workerID string, limit int) error
}

type AlertStore interface {
	EvaluateAlertRules(ctx context.Context, workerID string, limit int) error
}

type Worker struct {
	Store                     OutboxStore
	Processor                 OutboxProcessor
	DeliveryStore             DeliveryStore
	DeliveryClient            DeliveryClient
	NotificationDeliveryStore NotificationDeliveryStore
	NotificationClient        SignalClient
	SIEMDeliveryStore         SIEMDeliveryStore
	SIEMClient                SignalClient
	RetentionStore            RetentionStore
	MetricsStore              MetricsStore
	AlertStore                AlertStore
	WorkerID                  string
	Limit                     int
}

func (w Worker) RunOnce(ctx context.Context) error {
	limit := w.Limit
	if limit <= 0 {
		limit = 10
	}
	items, err := w.Store.ClaimOutbox(ctx, w.WorkerID, limit)
	if err != nil {
		return err
	}
	for _, item := range items {
		if w.Processor != nil {
			if err := w.Processor.ProcessOutbox(ctx, item); err != nil {
				if errors.Is(err, ErrDeferred) {
					continue
				}
				return err
			}
		}
		if err := w.Complete(item, ctx); err != nil {
			return err
		}
	}
	if w.DeliveryStore != nil && w.DeliveryClient != nil {
		deliveries, err := w.DeliveryStore.ClaimDueDeliveries(ctx, w.WorkerID, limit)
		if err != nil {
			return err
		}
		for _, item := range deliveries {
			result, deliverErr := w.DeliveryClient.Deliver(ctx, item.EndpointURL, item.Body, item.SigningSecret, item.SigningKeyID, item.SigningKeyVersion, item.MTLSClientCertPEM, item.MTLSClientKeyPEM)
			if err := w.DeliveryStore.RecordDeliveryAttempt(ctx, item, result, deliverErr); err != nil {
				return err
			}
		}
	}
	if w.RetentionStore != nil {
		if err := w.RetentionStore.ApplyRetentionPolicies(ctx, w.WorkerID, limit); err != nil {
			return err
		}
	}
	if w.MetricsStore != nil {
		if err := w.MetricsStore.RefreshMetricsRollups(ctx, w.WorkerID, limit); err != nil {
			return err
		}
	}
	if w.AlertStore != nil {
		if err := w.AlertStore.EvaluateAlertRules(ctx, w.WorkerID, limit); err != nil {
			return err
		}
	}
	if w.NotificationDeliveryStore != nil && w.NotificationClient != nil {
		deliveries, err := w.NotificationDeliveryStore.ClaimNotificationDeliveries(ctx, w.WorkerID, limit)
		if err != nil {
			return err
		}
		for _, item := range deliveries {
			result, deliverErr := w.NotificationClient.Deliver(ctx, item.URL, item.Body, item.Secret)
			if err := w.NotificationDeliveryStore.RecordNotificationDeliveryAttempt(ctx, item, result, deliverErr); err != nil {
				return err
			}
		}
	}
	if w.SIEMDeliveryStore != nil && w.SIEMClient != nil {
		if err := w.SIEMDeliveryStore.EnqueueSIEMDeliveries(ctx, w.WorkerID, limit); err != nil {
			return err
		}
		deliveries, err := w.SIEMDeliveryStore.ClaimSIEMDeliveries(ctx, w.WorkerID, limit)
		if err != nil {
			return err
		}
		for _, item := range deliveries {
			result, deliverErr := w.SIEMClient.Deliver(ctx, item.URL, item.Body, item.Secret)
			if err := w.SIEMDeliveryStore.RecordSIEMDeliveryAttempt(ctx, item, result, deliverErr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w Worker) Complete(item OutboxItem, ctx context.Context) error {
	return w.Store.CompleteOutbox(ctx, item.ID)
}
