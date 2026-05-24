package postgres

import (
	"context"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webhookery/internal/adapters/crypto"
	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
	"webhookery/internal/worker"
	"webhookery/pkg/verifier"
)

func TestPostgresMigrationAndAPIKeyAuthentication(t *testing.T) {
	databaseURL := os.Getenv("RANDONNEE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("RANDONNEE_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	migrationsDir := filepath.Join("..", "..", "..", "migrations")
	if err := MigrateUp(ctx, databaseURL, migrationsDir); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	box, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(ctx, databaseURL, box)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	rawToken := "whkey_integration_" + time.Now().UTC().Format("20060102150405")
	tenantID := "ten_it_" + time.Now().UTC().Format("150405")
	created, err := store.CreateAPIKey(ctx, app.APIKeyCreateInput{
		Key: domain.APIKey{
			TenantID: tenantID,
			UserID:   "usr_it",
			Name:     "integration",
			Prefix:   "whkey_in",
			Last4:    "0405",
			Hash:     app.HashToken(rawToken),
			Scopes:   []string{"events:read"},
			State:    domain.StateActive,
		},
		Role:    authz.RoleOperator,
		ActorID: "usr_it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" {
		t.Fatal("expected created API key id")
	}
	actor, err := store.AuthenticateAPIKey(ctx, app.HashToken(rawToken))
	if err != nil {
		t.Fatal(err)
	}
	if actor.TenantID != tenantID || actor.Role != authz.RoleOperator {
		t.Fatalf("unexpected actor: %+v", actor)
	}
}

func TestPostgresWorkerLeaseRecoveryAndLivePriority(t *testing.T) {
	ctx, store, actor := openPostgresIntegrationStore(t)
	defer store.Close()

	now := time.Date(2026, 5, 26, 16, 0, 0, 0, time.UTC)
	if _, err := store.pool.Exec(ctx, `UPDATE outbox SET state='completed', locked_by=NULL, lock_expires_at=NULL WHERE tenant_id LIKE 'ten_it_%' AND state <> 'completed'`); err != nil {
		t.Fatalf("clear prior integration outbox work: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE deliveries SET state='succeeded', locked_by=NULL, lock_expires_at=NULL WHERE tenant_id LIKE 'ten_it_%' AND state IN ('scheduled','in_progress')`); err != nil {
		t.Fatalf("clear prior integration delivery work: %v", err)
	}
	control := app.NewControlService(store, ssrf.Validator{Resolver: ssrf.StaticResolver{"receiver.example.com": {netip.MustParseAddr("93.184.216.34")}}})
	source, _ := createPostgresIntegrationRoute(t, ctx, control, actor, "invoice.created")
	first := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, "invoice.created", "evt_it_recovery_"+time.Now().UTC().Format("150405.000000000"), now)

	stuckOutbox, err := store.ClaimOutbox(ctx, "it-stuck-outbox", 1)
	if err != nil {
		t.Fatalf("claim outbox before recovery: %v", err)
	}
	if len(stuckOutbox) != 1 || stuckOutbox[0].ResourceID != first.EventID {
		t.Fatalf("expected first outbox item for accepted event: %+v", stuckOutbox)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox SET lock_expires_at=now() - interval '1 second' WHERE id=$1`, stuckOutbox[0].ID); err != nil {
		t.Fatalf("expire outbox lock: %v", err)
	}
	recoveredOutbox, err := store.ClaimOutbox(ctx, "it-recovered-outbox", 1)
	if err != nil {
		t.Fatalf("claim expired outbox: %v", err)
	}
	if len(recoveredOutbox) != 1 || recoveredOutbox[0].ID != stuckOutbox[0].ID {
		t.Fatalf("expected expired outbox to be reclaimed, got %+v", recoveredOutbox)
	}
	if err := store.ProcessOutbox(ctx, recoveredOutbox[0]); err != nil {
		t.Fatalf("process recovered outbox: %v", err)
	}
	if err := store.CompleteOutbox(ctx, recoveredOutbox[0].ID); err != nil {
		t.Fatalf("complete recovered outbox: %v", err)
	}

	stuckDelivery, err := store.ClaimDueDeliveries(ctx, "it-stuck-delivery", 1)
	if err != nil {
		t.Fatalf("claim delivery before recovery: %v", err)
	}
	if len(stuckDelivery) != 1 || stuckDelivery[0].EventID != first.EventID {
		t.Fatalf("expected first delivery for accepted event: %+v", stuckDelivery)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE deliveries SET lock_expires_at=now() - interval '1 second' WHERE tenant_id=$1 AND id=$2`, actor.TenantID, stuckDelivery[0].ID); err != nil {
		t.Fatalf("expire delivery lock: %v", err)
	}
	recoveredDelivery, err := store.ClaimDueDeliveries(ctx, "it-recovered-delivery", 1)
	if err != nil {
		t.Fatalf("claim expired delivery: %v", err)
	}
	if len(recoveredDelivery) != 1 || recoveredDelivery[0].ID != stuckDelivery[0].ID {
		t.Fatalf("expected expired delivery to be reclaimed, got %+v", recoveredDelivery)
	}
	if err := store.RecordDeliveryAttempt(ctx, recoveredDelivery[0], worker.DeliveryResult{StatusCode: 202, ResponseBody: []byte("ok"), FailureClass: "success"}, nil); err != nil {
		t.Fatalf("complete recovered delivery: %v", err)
	}

	second := ingestPostgresIntegrationEvent(t, ctx, store, actor, source.ID, "invoice.created", "evt_it_priority_"+time.Now().UTC().Format("150405.000000000"), now.Add(time.Second))
	if _, err := store.CreateReplay(ctx, actor.TenantID, actor.ID, app.ReplayRequest{EventID: second.EventID, Reason: "integration priority drill", ConfigMode: app.ReplayConfigCurrent}); err != nil {
		t.Fatalf("create replay for priority drill: %v", err)
	}
	outboxItems, err := store.ClaimOutbox(ctx, "it-priority-outbox", 10)
	if err != nil {
		t.Fatalf("claim priority outbox items: %v", err)
	}
	if len(outboxItems) < 2 {
		t.Fatalf("expected live and replay outbox work, got %+v", outboxItems)
	}
	for _, item := range outboxItems {
		if err := store.ProcessOutbox(ctx, item); err != nil {
			t.Fatalf("process priority outbox item %+v: %v", item, err)
		}
		if err := store.CompleteOutbox(ctx, item.ID); err != nil {
			t.Fatalf("complete priority outbox item %+v: %v", item, err)
		}
	}
	priorityDelivery, err := store.ClaimDueDeliveries(ctx, "it-priority-delivery", 1)
	if err != nil {
		t.Fatalf("claim priority delivery: %v", err)
	}
	if len(priorityDelivery) != 1 {
		t.Fatalf("expected one priority delivery, got %+v", priorityDelivery)
	}
	var replayJobID string
	if err := store.pool.QueryRow(ctx, `SELECT COALESCE(replay_job_id,'') FROM deliveries WHERE tenant_id=$1 AND id=$2`, actor.TenantID, priorityDelivery[0].ID).Scan(&replayJobID); err != nil {
		t.Fatalf("read claimed delivery replay marker: %v", err)
	}
	if replayJobID != "" {
		t.Fatalf("live delivery must be prioritized over replay delivery, claimed replay job %s", replayJobID)
	}
}

func openPostgresIntegrationStore(t *testing.T) (context.Context, *Store, authz.Actor) {
	t.Helper()
	databaseURL := os.Getenv("RANDONNEE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("RANDONNEE_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	migrationsDir := filepath.Join("..", "..", "..", "migrations")
	if err := MigrateUp(ctx, databaseURL, migrationsDir); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	box, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(ctx, databaseURL, box)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UTC().Format("150405.000000000")
	actor := authz.Actor{ID: "usr_it_" + suffix, TenantID: "ten_it_" + suffix, Role: authz.RoleOwner, Scopes: []string{"*"}}
	return ctx, store, actor
}

func createPostgresIntegrationRoute(t *testing.T, ctx context.Context, control *app.ControlService, actor authz.Actor, eventType string) (domain.Source, domain.Endpoint) {
	t.Helper()
	source, err := control.CreateSource(ctx, actor, app.CreateSourceRequest{Name: "integration source", Provider: "stripe", Adapter: "stripe", VerificationSecret: "whsec_it"})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, _, err := control.CreateEndpoint(ctx, actor, app.CreateEndpointRequest{Name: "integration endpoint", URL: "https://receiver.example.com/webhook"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.CreateRoute(ctx, actor, app.CreateRouteRequest{SourceID: source.ID, Name: "integration route", Priority: 10, EventTypes: []string{eventType}, EndpointID: endpoint.ID, State: domain.StateActive}); err != nil {
		t.Fatal(err)
	}
	return source, endpoint
}

func ingestPostgresIntegrationEvent(t *testing.T, ctx context.Context, store *Store, actor authz.Actor, sourceID, eventType, providerID string, now time.Time) app.IngestResult {
	t.Helper()
	body := []byte(`{"id":"` + providerID + `","type":"` + eventType + `","account":"acct_it"}`)
	result, err := app.NewIngestService(store, fixedIntegrationClock{now: now}).Ingest(ctx, app.IngestRequest{
		TenantID:    actor.TenantID,
		SourceID:    sourceID,
		Provider:    "stripe",
		RawBody:     body,
		Headers:     []domain.HeaderPair{{Name: "Stripe-Signature", Value: verifier.TimestampedHeader("v1", now, []byte("whsec_it"), body)}},
		ContentType: "application/json",
		RemoteIP:    "198.51.100.20",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.EventID == "" {
		t.Fatalf("expected accepted integration event, got %+v", result)
	}
	return result
}

type fixedIntegrationClock struct {
	now time.Time
}

func (c fixedIntegrationClock) Now() time.Time {
	return c.now
}
