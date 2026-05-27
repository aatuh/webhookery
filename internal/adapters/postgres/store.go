package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"webhookery/internal/app"
	"webhookery/internal/auditchain"
	"webhookery/internal/authz"
	"webhookery/internal/blobstore"
	"webhookery/internal/domain"
	"webhookery/internal/evidence"
	"webhookery/internal/provider"
	"webhookery/internal/random"
	"webhookery/internal/reconcile"
	"webhookery/internal/retry"
	"webhookery/internal/transform"
	"webhookery/internal/worker"
)

type SecretBox interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

type ContextualSecretBox interface {
	EncryptWithContext(ctx context.Context, tenantID, purpose string, plaintext []byte) ([]byte, error)
	DecryptWithContext(ctx context.Context, tenantID, purpose string, ciphertext []byte) ([]byte, error)
}

type Store struct {
	pool           *pgxpool.Pool
	box            SecretBox
	rawStorageMode string
	objectStore    blobstore.Store
	objectBucket   string
}

func (s *Store) encryptSecret(ctx context.Context, tenantID, purpose string, plaintext []byte) ([]byte, error) {
	if box, ok := s.box.(ContextualSecretBox); ok {
		return box.EncryptWithContext(ctx, tenantID, purpose, plaintext)
	}
	return s.box.Encrypt(plaintext)
}

func (s *Store) decryptSecret(ctx context.Context, tenantID, purpose string, ciphertext []byte) ([]byte, error) {
	if box, ok := s.box.(ContextualSecretBox); ok {
		return box.DecryptWithContext(ctx, tenantID, purpose, ciphertext)
	}
	return s.box.Decrypt(ciphertext)
}

type StoreOptions struct {
	RawStorageMode string
	ObjectStore    blobstore.Store
	ObjectBucket   string
}

var errObjectStoreReadFailed = errors.New("object store read failed")

func New(ctx context.Context, databaseURL string, box SecretBox) (*Store, error) {
	return NewWithOptions(ctx, databaseURL, box, StoreOptions{RawStorageMode: domain.RawStoragePostgres})
}

func NewWithOptions(ctx context.Context, databaseURL string, box SecretBox, opts StoreOptions) (*Store, error) {
	if box == nil {
		return nil, errors.New("secret box is required")
	}
	if opts.RawStorageMode == "" {
		opts.RawStorageMode = domain.RawStoragePostgres
	}
	if opts.RawStorageMode != domain.RawStoragePostgres && opts.RawStorageMode != domain.RawStorageS3 {
		return nil, errors.New("raw storage mode must be postgres or s3")
	}
	if opts.RawStorageMode == domain.RawStorageS3 {
		if opts.ObjectStore == nil || strings.TrimSpace(opts.ObjectBucket) == "" {
			return nil, errors.New("s3 raw storage requires object store and bucket")
		}
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	store := &Store{
		pool:           pool,
		box:            box,
		rawStorageMode: opts.RawStorageMode,
		objectStore:    opts.ObjectStore,
		objectBucket:   strings.TrimSpace(opts.ObjectBucket),
	}
	return store, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Health(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

const (
	auditChainBackfillLeaseID = "audit-chain-backfill"
	auditChainBackfillMax     = 1000
)

func (s *Store) BackfillAuditChain(ctx context.Context, workerID string, limit int) (worker.AuditChainBackfillResult, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > auditChainBackfillMax {
		limit = auditChainBackfillMax
	}
	result := worker.AuditChainBackfillResult{}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx)
	var exists bool
	if err := tx.QueryRow(ctx, "SELECT to_regclass('audit_chain_entries') IS NOT NULL").Scan(&exists); err != nil {
		return result, err
	}
	if !exists {
		return result, tx.Commit(ctx)
	}
	acquired, err := tryAcquireWorkerLease(ctx, tx, auditChainBackfillLeaseID, workerID, time.Minute)
	if err != nil {
		return result, err
	}
	result.LeaseAcquired = acquired
	if !acquired {
		return result, tx.Commit(ctx)
	}
	rows, err := tx.Query(ctx, `
		SELECT a.tenant_id
		FROM audit_events a
		WHERE NOT EXISTS (
		      SELECT 1 FROM audit_chain_entries c
		      WHERE c.tenant_id=a.tenant_id AND c.audit_event_id=a.id
		)
		GROUP BY a.tenant_id
		ORDER BY min(a.occurred_at) ASC, min(a.id) ASC, a.tenant_id ASC
		LIMIT $1`, limit)
	if err != nil {
		return result, err
	}
	var tenantIDs []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			rows.Close()
			return result, err
		}
		tenantIDs = append(tenantIDs, tenantID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	rows.Close()
	remaining := limit
	now := time.Now().UTC()
	for _, tenantID := range tenantIDs {
		if remaining <= 0 {
			break
		}
		backfilled, err := s.backfillTenantAuditChain(ctx, tx, tenantID, remaining, now)
		if err != nil {
			return result, err
		}
		result.TenantsScanned++
		result.EventsBackfilled += backfilled
		remaining -= backfilled
	}
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM audit_events a
			WHERE NOT EXISTS (
			      SELECT 1 FROM audit_chain_entries c
			      WHERE c.tenant_id=a.tenant_id AND c.audit_event_id=a.id
			)
		)`).Scan(&result.More); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (s *Store) backfillTenantAuditChain(ctx context.Context, tx pgx.Tx, tenantID string, limit int, now time.Time) (int, error) {
	sequence, previousHash, err := ensureAuditChainHead(ctx, tx, tenantID)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `
		SELECT a.id, a.tenant_id, a.actor_id, a.action, a.resource, a.resource_id, a.reason, a.occurred_at
		FROM audit_events a
		WHERE a.tenant_id=$1
		  AND NOT EXISTS (
		      SELECT 1 FROM audit_chain_entries c
		      WHERE c.tenant_id=a.tenant_id AND c.audit_event_id=a.id
		  )
		ORDER BY a.occurred_at ASC, a.id ASC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return 0, err
	}
	var events []domain.AuditEvent
	for rows.Next() {
		var event domain.AuditEvent
		if err := rows.Scan(&event.ID, &event.TenantID, &event.ActorID, &event.Action, &event.Resource, &event.ResourceID, &event.Reason, &event.OccurredAt); err != nil {
			rows.Close()
			return 0, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	lastAuditEventID := ""
	backfilled := 0
	for _, event := range events {
		sequence++
		entry, err := auditchain.ComputeEntry(mustID("ace"), event, sequence, previousHash, domain.AuditChainEntrySourceBackfill, now)
		if err != nil {
			return 0, err
		}
		if err := insertAuditChainEntry(ctx, tx, entry); err != nil {
			return 0, err
		}
		previousHash = entry.ChainHash
		lastAuditEventID = event.ID
		backfilled++
	}
	if lastAuditEventID != "" {
		if _, err := tx.Exec(ctx, `UPDATE audit_chain_heads SET sequence=$2, chain_hash=$3, last_audit_event_id=$4, updated_at=now() WHERE tenant_id=$1`, tenantID, sequence, previousHash, lastAuditEventID); err != nil {
			return 0, err
		}
	}
	return backfilled, nil
}

func ensureAuditChainHead(ctx context.Context, tx pgx.Tx, tenantID string) (int64, string, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO audit_chain_heads(tenant_id, sequence, chain_hash) VALUES($1,0,'') ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
		return 0, "", err
	}
	var sequence int64
	var chainHash string
	if err := tx.QueryRow(ctx, `SELECT sequence, chain_hash FROM audit_chain_heads WHERE tenant_id=$1 FOR UPDATE`, tenantID).Scan(&sequence, &chainHash); err != nil {
		return 0, "", err
	}
	return sequence, chainHash, nil
}

func insertAuditChainEntry(ctx context.Context, tx pgx.Tx, entry domain.AuditChainEntry) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_chain_entries(id, tenant_id, sequence, audit_event_id, event_hash, previous_chain_hash, chain_hash,
			canonicalization_version, source, state, created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (tenant_id, audit_event_id) DO NOTHING`,
		entry.ID, entry.TenantID, entry.Sequence, entry.AuditEventID, entry.EventHash, entry.PreviousChainHash, entry.ChainHash,
		entry.CanonicalizationVersion, entry.Source, entry.State, entry.CreatedAt)
	return err
}

type auditEventInput struct {
	TenantID   string
	ActorID    string
	Action     string
	Resource   string
	ResourceID string
	Reason     string
	OccurredAt time.Time
	Source     string
}

func (s *Store) recordAuditEvent(ctx context.Context, input auditEventInput) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if _, err := recordAuditEventTx(ctx, tx, input); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func recordAuditEventTx(ctx context.Context, tx pgx.Tx, input auditEventInput) (domain.AuditEvent, error) {
	if input.Source == "" {
		input.Source = domain.AuditChainEntrySourceLive
	}
	if input.OccurredAt.IsZero() {
		input.OccurredAt = time.Now().UTC()
	}
	occurredAt := input.OccurredAt.UTC().Truncate(time.Microsecond)
	event := domain.AuditEvent{
		ID:         mustID("aud"),
		TenantID:   input.TenantID,
		ActorID:    input.ActorID,
		Action:     input.Action,
		Resource:   input.Resource,
		ResourceID: input.ResourceID,
		Reason:     input.Reason,
		OccurredAt: occurredAt,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason, occurred_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		event.ID, event.TenantID, event.ActorID, event.Action, event.Resource, event.ResourceID, event.Reason, event.OccurredAt); err != nil {
		return domain.AuditEvent{}, err
	}
	sequence, previousHash, err := ensureAuditChainHead(ctx, tx, event.TenantID)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	entry, err := auditchain.ComputeEntry(mustID("ace"), event, sequence+1, previousHash, input.Source, event.OccurredAt)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	if err := insertAuditChainEntry(ctx, tx, entry); err != nil {
		return domain.AuditEvent{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE audit_chain_heads SET sequence=$2, chain_hash=$3, last_audit_event_id=$4, updated_at=now() WHERE tenant_id=$1`, event.TenantID, entry.Sequence, entry.ChainHash, event.ID); err != nil {
		return domain.AuditEvent{}, err
	}
	return event, nil
}

func (s *Store) AuthenticateAPIKey(ctx context.Context, keyHash string) (authz.Actor, error) {
	var actor authz.Actor
	var role string
	err := s.pool.QueryRow(ctx, `
		SELECT k.user_id, k.tenant_id, m.role, k.scopes
		FROM api_keys k
		JOIN memberships m ON m.tenant_id=k.tenant_id AND m.user_id=k.user_id AND m.state='active'
		WHERE k.key_hash=$1
		  AND k.state='active'
		  AND (k.expires_at IS NULL OR k.expires_at > now())`,
		keyHash,
	).Scan(&actor.ID, &actor.TenantID, &role, &actor.Scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Actor{}, app.ErrUnauthorized
	}
	if err != nil {
		return authz.Actor{}, err
	}
	actor.Role = authz.Role(role)
	_, _ = s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at=now() WHERE key_hash=$1`, keyHash)
	return actor, nil
}

func (s *Store) CreateAPIKey(ctx context.Context, input app.APIKeyCreateInput) (domain.APIKey, error) {
	key := input.Key
	if key.ID == "" {
		key.ID = mustID("key")
	}
	if key.State == "" {
		key.State = domain.StateActive
	}
	if key.UserID == "" {
		key.UserID = mustID("usr")
	}
	membershipID := mustID("mem")
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.APIKey{}, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, "INSERT INTO tenants(id, name) VALUES($1, $1) ON CONFLICT (id) DO NOTHING", key.TenantID); err != nil {
		return domain.APIKey{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users(id, email, state)
		VALUES($1,$2,'active')
		ON CONFLICT (id) DO UPDATE SET email=COALESCE(NULLIF(EXCLUDED.email,''), users.email)`,
		key.UserID, input.Email,
	); err != nil {
		return domain.APIKey{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO memberships(id, tenant_id, user_id, role, state)
		VALUES($1,$2,$3,$4,'active')
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET role=EXCLUDED.role, state='active'`,
		membershipID, key.TenantID, key.UserID, string(input.Role),
	); err != nil {
		return domain.APIKey{}, err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO api_keys(id, tenant_id, user_id, name, key_hash, key_prefix, key_last4, scopes, state)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING created_at`,
		key.ID, key.TenantID, key.UserID, key.Name, key.Hash, key.Prefix, key.Last4, key.Scopes, key.State,
	).Scan(&key.CreatedAt)
	if err != nil {
		return domain.APIKey{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: key.TenantID, ActorID: input.ActorID, Action: "api_key.created", Resource: "api_key", ResourceID: key.ID, Reason: key.Name}); err != nil {
		return domain.APIKey{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.APIKey{}, err
	}
	return key, nil
}

func (s *Store) ListAPIKeys(ctx context.Context, tenantID string, limit int) ([]domain.APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, user_id, name, key_prefix, key_last4, scopes, state, created_at, COALESCE(revoked_at, 'epoch'::timestamptz)
		FROM api_keys
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.APIKey
	for rows.Next() {
		var item domain.APIKey
		if err := rows.Scan(&item.ID, &item.TenantID, &item.UserID, &item.Name, &item.Prefix, &item.Last4, &item.Scopes, &item.State, &item.CreatedAt, &item.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIKey(ctx context.Context, tenantID, apiKeyID, actorID, reason string) (domain.APIKey, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.APIKey{}, err
	}
	defer rollback(ctx, tx)
	var item domain.APIKey
	err = tx.QueryRow(ctx, `
		UPDATE api_keys
		SET state='revoked', revoked_at=now()
		WHERE tenant_id=$1 AND id=$2 AND state <> 'revoked'
		RETURNING id, tenant_id, user_id, name, key_prefix, key_last4, scopes, state, created_at, revoked_at`,
		tenantID, apiKeyID,
	).Scan(&item.ID, &item.TenantID, &item.UserID, &item.Name, &item.Prefix, &item.Last4, &item.Scopes, &item.State, &item.CreatedAt, &item.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.APIKey{}, app.ErrNotFound
	}
	if err != nil {
		return domain.APIKey{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "api_key.revoked", Resource: "api_key", ResourceID: apiKeyID, Reason: reason}); err != nil {
		return domain.APIKey{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.APIKey{}, err
	}
	return item, nil
}

func (s *Store) CreateProducerClient(ctx context.Context, input app.ProducerClientCreateInput) (domain.ProducerClient, error) {
	client := input.Client
	secret := input.Secret
	if client.ID == "" {
		client.ID = mustID("pcl")
	}
	if client.State == "" {
		client.State = domain.StateActive
	}
	if client.TokenTTLSeconds == 0 {
		client.TokenTTLSeconds = 900
	}
	if len(client.Scopes) == 0 {
		client.Scopes = []string{"events:write"}
	}
	if secret.ID == "" {
		secret.ID = mustID("pcs")
	}
	if secret.State == "" {
		secret.State = domain.StateActive
	}
	secret.TenantID = client.TenantID
	secret.ClientID = client.ID
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ProducerClient{}, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, "INSERT INTO tenants(id, name) VALUES($1, $1) ON CONFLICT (id) DO NOTHING", client.TenantID); err != nil {
		return domain.ProducerClient{}, err
	}
	if client.SourceID != "" {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sources WHERE tenant_id=$1 AND id=$2)`, client.TenantID, client.SourceID).Scan(&exists); err != nil {
			return domain.ProducerClient{}, err
		}
		if !exists {
			return domain.ProducerClient{}, app.ErrNotFound
		}
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO producer_clients(id, tenant_id, name, source_id, scopes, token_ttl_seconds, state, created_by)
		VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8)
		RETURNING created_at, updated_at`,
		client.ID, client.TenantID, client.Name, client.SourceID, client.Scopes, client.TokenTTLSeconds, client.State, input.ActorID,
	).Scan(&client.CreatedAt, &client.UpdatedAt)
	if err != nil {
		return domain.ProducerClient{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO producer_client_secrets(id, tenant_id, client_id, secret_hash, secret_prefix, secret_last4, state)
		VALUES($1,$2,$3,$4,$5,$6,$7)`,
		secret.ID, secret.TenantID, secret.ClientID, secret.Hash, secret.Prefix, secret.Last4, secret.State,
	)
	if err != nil {
		return domain.ProducerClient{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: client.TenantID, ActorID: input.ActorID, Action: "producer_client.created", Resource: "producer_client", ResourceID: client.ID, Reason: client.Name}); err != nil {
		return domain.ProducerClient{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ProducerClient{}, err
	}
	return client, nil
}

func (s *Store) ListProducerClients(ctx context.Context, tenantID string, limit int) ([]domain.ProducerClient, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT pc.id, pc.tenant_id, pc.name, COALESCE(pc.source_id,''), pc.scopes, pc.token_ttl_seconds, pc.state, pc.created_by, pc.created_at, pc.updated_at, COALESCE(pc.disabled_at, 'epoch'::timestamptz)
		FROM producer_clients pc
		WHERE pc.tenant_id=$1
		ORDER BY pc.created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ProducerClient
	for rows.Next() {
		item, err := scanProducerClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetProducerClient(ctx context.Context, tenantID, clientID string) (domain.ProducerClient, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT pc.id, pc.tenant_id, pc.name, COALESCE(pc.source_id,''), pc.scopes, pc.token_ttl_seconds, pc.state, pc.created_by, pc.created_at, pc.updated_at, COALESCE(pc.disabled_at, 'epoch'::timestamptz)
		FROM producer_clients pc
		WHERE pc.tenant_id=$1 AND pc.id=$2`, tenantID, clientID)
	item, err := scanProducerClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProducerClient{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateProducerClient(ctx context.Context, tenantID, clientID, actorID string, req app.UpdateProducerClientRequest) (domain.ProducerClient, error) {
	current, err := s.GetProducerClient(ctx, tenantID, clientID)
	if err != nil {
		return domain.ProducerClient{}, err
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.SourceID != nil {
		current.SourceID = *req.SourceID
	}
	if req.Scopes != nil {
		current.Scopes = req.Scopes
	}
	if req.TokenTTLSeconds != nil {
		current.TokenTTLSeconds = *req.TokenTTLSeconds
	}
	if req.State != nil {
		current.State = *req.State
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ProducerClient{}, err
	}
	defer rollback(ctx, tx)
	if current.SourceID != "" {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sources WHERE tenant_id=$1 AND id=$2)`, tenantID, current.SourceID).Scan(&exists); err != nil {
			return domain.ProducerClient{}, err
		}
		if !exists {
			return domain.ProducerClient{}, app.ErrNotFound
		}
	}
	err = tx.QueryRow(ctx, `
		UPDATE producer_clients
		SET name=$3, source_id=NULLIF($4,''), scopes=$5, token_ttl_seconds=$6, state=$7, updated_at=now(), disabled_at=CASE WHEN $7='disabled' THEN COALESCE(disabled_at, now()) ELSE NULL END
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, COALESCE(source_id,''), scopes, token_ttl_seconds, state, created_by, created_at, updated_at, COALESCE(disabled_at, 'epoch'::timestamptz)`,
		tenantID, clientID, current.Name, current.SourceID, current.Scopes, current.TokenTTLSeconds, current.State,
	).Scan(&current.ID, &current.TenantID, &current.Name, &current.SourceID, &current.Scopes, &current.TokenTTLSeconds, &current.State, &current.CreatedBy, &current.CreatedAt, &current.UpdatedAt, &current.DisabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProducerClient{}, app.ErrNotFound
	}
	if err != nil {
		return domain.ProducerClient{}, err
	}
	if current.DisabledAt.Equal(time.Unix(0, 0).UTC()) {
		current.DisabledAt = time.Time{}
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "producer_client.updated", Resource: "producer_client", ResourceID: clientID, Reason: req.Reason}); err != nil {
		return domain.ProducerClient{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ProducerClient{}, err
	}
	return current, nil
}

func (s *Store) DeleteProducerClient(ctx context.Context, tenantID, clientID, actorID, reason string) (domain.ProducerClient, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ProducerClient{}, err
	}
	defer rollback(ctx, tx)
	var item domain.ProducerClient
	err = tx.QueryRow(ctx, `
		UPDATE producer_clients
		SET state='disabled', disabled_at=COALESCE(disabled_at, now()), updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, COALESCE(source_id,''), scopes, token_ttl_seconds, state, created_by, created_at, updated_at, COALESCE(disabled_at, 'epoch'::timestamptz)`,
		tenantID, clientID,
	).Scan(&item.ID, &item.TenantID, &item.Name, &item.SourceID, &item.Scopes, &item.TokenTTLSeconds, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt, &item.DisabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProducerClient{}, app.ErrNotFound
	}
	if err != nil {
		return domain.ProducerClient{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE producer_client_secrets SET state='revoked', revoked_at=COALESCE(revoked_at, now()) WHERE tenant_id=$1 AND client_id=$2 AND state <> 'revoked'`, tenantID, clientID); err != nil {
		return domain.ProducerClient{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE producer_access_tokens SET state='revoked', revoked_at=COALESCE(revoked_at, now()) WHERE tenant_id=$1 AND client_id=$2 AND state <> 'revoked'`, tenantID, clientID); err != nil {
		return domain.ProducerClient{}, err
	}
	if item.DisabledAt.Equal(time.Unix(0, 0).UTC()) {
		item.DisabledAt = time.Time{}
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "producer_client.disabled", Resource: "producer_client", ResourceID: clientID, Reason: reason}); err != nil {
		return domain.ProducerClient{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ProducerClient{}, err
	}
	return item, nil
}

func (s *Store) RotateProducerClientSecret(ctx context.Context, tenantID, clientID string, input app.ProducerClientSecretRotateInput) (domain.ProducerClientSecret, error) {
	secret := input.Secret
	if secret.ID == "" {
		secret.ID = mustID("pcs")
	}
	secret.TenantID = tenantID
	secret.ClientID = clientID
	secret.State = domain.StateActive
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ProducerClientSecret{}, err
	}
	defer rollback(ctx, tx)
	tag, err := tx.Exec(ctx, `UPDATE producer_client_secrets SET state='revoked', revoked_at=now() WHERE tenant_id=$1 AND client_id=$2 AND state='active'`, tenantID, clientID)
	if err != nil {
		return domain.ProducerClientSecret{}, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM producer_clients WHERE tenant_id=$1 AND id=$2)`, tenantID, clientID).Scan(&exists); err != nil {
		return domain.ProducerClientSecret{}, err
	}
	if !exists || tag.RowsAffected() == 0 {
		return domain.ProducerClientSecret{}, app.ErrNotFound
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO producer_client_secrets(id, tenant_id, client_id, secret_hash, secret_prefix, secret_last4, state)
		VALUES($1,$2,$3,$4,$5,$6,'active')
		RETURNING created_at`,
		secret.ID, secret.TenantID, secret.ClientID, secret.Hash, secret.Prefix, secret.Last4,
	).Scan(&secret.CreatedAt)
	if err != nil {
		return domain.ProducerClientSecret{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: input.ActorID, Action: "producer_client.secret_rotated", Resource: "producer_client", ResourceID: clientID, Reason: input.Reason}); err != nil {
		return domain.ProducerClientSecret{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ProducerClientSecret{}, err
	}
	return secret, nil
}

func (s *Store) AuthenticateProducerClient(ctx context.Context, clientID, secretHash string) (domain.ProducerClient, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT pc.id, pc.tenant_id, pc.name, COALESCE(pc.source_id,''), pc.scopes, pc.token_ttl_seconds, pc.state, pc.created_by, pc.created_at, pc.updated_at, COALESCE(pc.disabled_at, 'epoch'::timestamptz)
		FROM producer_clients pc
		JOIN producer_client_secrets pcs ON pcs.tenant_id=pc.tenant_id AND pcs.client_id=pc.id AND pcs.state='active'
		WHERE pc.id=$1 AND pcs.secret_hash=$2 AND pc.state='active'`,
		clientID, secretHash)
	client, err := scanProducerClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProducerClient{}, app.ErrUnauthorized
	}
	if err != nil {
		return domain.ProducerClient{}, err
	}
	_, _ = s.pool.Exec(ctx, `UPDATE producer_client_secrets SET last_used_at=now() WHERE tenant_id=$1 AND client_id=$2 AND secret_hash=$3`, client.TenantID, client.ID, secretHash)
	return client, nil
}

func (s *Store) CreateProducerAccessToken(ctx context.Context, input app.ProducerAccessTokenCreateInput) (domain.ProducerAccessToken, error) {
	token := input.Token
	if token.ID == "" {
		token.ID = mustID("pat")
	}
	if token.State == "" {
		token.State = domain.StateActive
	}
	if len(token.Scopes) == 0 {
		token.Scopes = []string{"events:write"}
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO producer_access_tokens(id, tenant_id, client_id, token_hash, token_prefix, token_last4, scopes, state, expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING created_at`,
		token.ID, token.TenantID, token.ClientID, token.Hash, token.Prefix, token.Last4, token.Scopes, token.State, token.ExpiresAt,
	).Scan(&token.CreatedAt)
	if err != nil {
		return domain.ProducerAccessToken{}, err
	}
	return token, nil
}

func (s *Store) AuthenticateProducerAccessToken(ctx context.Context, tokenHash string) (authz.Actor, error) {
	var actor authz.Actor
	var clientID string
	err := s.pool.QueryRow(ctx, `
		SELECT pat.client_id, pat.tenant_id, COALESCE(pc.source_id,''), pat.scopes
		FROM producer_access_tokens pat
		JOIN producer_clients pc ON pc.tenant_id=pat.tenant_id AND pc.id=pat.client_id AND pc.state='active'
		WHERE pat.token_hash=$1
		  AND pat.state='active'
		  AND pat.expires_at > now()`,
		tokenHash,
	).Scan(&clientID, &actor.TenantID, &actor.SourceID, &actor.Scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Actor{}, app.ErrUnauthorized
	}
	if err != nil {
		return authz.Actor{}, err
	}
	actor.ID = "producer_client:" + clientID
	actor.Role = authz.RoleDeveloper
	_, _ = s.pool.Exec(ctx, `UPDATE producer_access_tokens SET last_used_at=now() WHERE token_hash=$1`, tokenHash)
	return actor, nil
}

func (s *Store) CreateProducerMTLSIdentity(ctx context.Context, tenantID, actorID string, identity domain.ProducerMTLSIdentity) (domain.ProducerMTLSIdentity, error) {
	if identity.ID == "" {
		identity.ID = mustID("pmi")
	}
	if identity.State == "" {
		identity.State = domain.StateActive
	}
	identity.TenantID = tenantID
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, "INSERT INTO tenants(id, name) VALUES($1, $1) ON CONFLICT (id) DO NOTHING", tenantID); err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	if identity.SourceID != "" {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sources WHERE tenant_id=$1 AND id=$2)`, tenantID, identity.SourceID).Scan(&exists); err != nil {
			return domain.ProducerMTLSIdentity{}, err
		}
		if !exists {
			return domain.ProducerMTLSIdentity{}, app.ErrNotFound
		}
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO producer_mtls_identities(id, tenant_id, name, source_id, certificate_fingerprint_sha256, cert_subject, dns_sans, uri_sans, email_sans, not_before, not_after, state, created_by)
		VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING created_at, updated_at`,
		identity.ID, tenantID, identity.Name, identity.SourceID, identity.CertificateFingerprintSHA256, identity.CertSubject, identity.DNSSANs, identity.URISANs, identity.EmailSANs, identity.NotBefore, identity.NotAfter, identity.State, actorID,
	).Scan(&identity.CreatedAt, &identity.UpdatedAt)
	if err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "producer_mtls_identity.created", Resource: "producer_mtls_identity", ResourceID: identity.ID, Reason: identity.Name}); err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	return identity, nil
}

func (s *Store) ListProducerMTLSIdentities(ctx context.Context, tenantID string, limit int) ([]domain.ProducerMTLSIdentity, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, COALESCE(source_id,''), certificate_fingerprint_sha256, cert_subject, dns_sans, uri_sans, email_sans, not_before, not_after, state, created_by, created_at, updated_at, COALESCE(disabled_at, 'epoch'::timestamptz)
		FROM producer_mtls_identities
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ProducerMTLSIdentity
	for rows.Next() {
		item, err := scanProducerMTLSIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetProducerMTLSIdentity(ctx context.Context, tenantID, identityID string) (domain.ProducerMTLSIdentity, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, COALESCE(source_id,''), certificate_fingerprint_sha256, cert_subject, dns_sans, uri_sans, email_sans, not_before, not_after, state, created_by, created_at, updated_at, COALESCE(disabled_at, 'epoch'::timestamptz)
		FROM producer_mtls_identities
		WHERE tenant_id=$1 AND id=$2`, tenantID, identityID)
	item, err := scanProducerMTLSIdentity(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProducerMTLSIdentity{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateProducerMTLSIdentity(ctx context.Context, tenantID, identityID, actorID string, req app.UpdateProducerMTLSIdentityRequest) (domain.ProducerMTLSIdentity, error) {
	current, err := s.GetProducerMTLSIdentity(ctx, tenantID, identityID)
	if err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.SourceID != nil {
		current.SourceID = *req.SourceID
	}
	if req.State != nil {
		current.State = *req.State
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	defer rollback(ctx, tx)
	if current.SourceID != "" {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sources WHERE tenant_id=$1 AND id=$2)`, tenantID, current.SourceID).Scan(&exists); err != nil {
			return domain.ProducerMTLSIdentity{}, err
		}
		if !exists {
			return domain.ProducerMTLSIdentity{}, app.ErrNotFound
		}
	}
	err = tx.QueryRow(ctx, `
		UPDATE producer_mtls_identities
		SET name=$3, source_id=NULLIF($4,''), state=$5, updated_at=now(), disabled_at=CASE WHEN $5='disabled' THEN COALESCE(disabled_at, now()) ELSE NULL END
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, COALESCE(source_id,''), certificate_fingerprint_sha256, cert_subject, dns_sans, uri_sans, email_sans, not_before, not_after, state, created_by, created_at, updated_at, COALESCE(disabled_at, 'epoch'::timestamptz)`,
		tenantID, identityID, current.Name, current.SourceID, current.State,
	).Scan(&current.ID, &current.TenantID, &current.Name, &current.SourceID, &current.CertificateFingerprintSHA256, &current.CertSubject, &current.DNSSANs, &current.URISANs, &current.EmailSANs, &current.NotBefore, &current.NotAfter, &current.State, &current.CreatedBy, &current.CreatedAt, &current.UpdatedAt, &current.DisabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProducerMTLSIdentity{}, app.ErrNotFound
	}
	if err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	if current.DisabledAt.Equal(time.Unix(0, 0).UTC()) {
		current.DisabledAt = time.Time{}
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "producer_mtls_identity.updated", Resource: "producer_mtls_identity", ResourceID: identityID, Reason: req.Reason}); err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	return current, nil
}

func (s *Store) DeleteProducerMTLSIdentity(ctx context.Context, tenantID, identityID, actorID, reason string) (domain.ProducerMTLSIdentity, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	defer rollback(ctx, tx)
	var item domain.ProducerMTLSIdentity
	err = tx.QueryRow(ctx, `
		UPDATE producer_mtls_identities
		SET state='disabled', disabled_at=COALESCE(disabled_at, now()), updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, COALESCE(source_id,''), certificate_fingerprint_sha256, cert_subject, dns_sans, uri_sans, email_sans, not_before, not_after, state, created_by, created_at, updated_at, COALESCE(disabled_at, 'epoch'::timestamptz)`,
		tenantID, identityID,
	).Scan(&item.ID, &item.TenantID, &item.Name, &item.SourceID, &item.CertificateFingerprintSHA256, &item.CertSubject, &item.DNSSANs, &item.URISANs, &item.EmailSANs, &item.NotBefore, &item.NotAfter, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt, &item.DisabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProducerMTLSIdentity{}, app.ErrNotFound
	}
	if err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	if item.DisabledAt.Equal(time.Unix(0, 0).UTC()) {
		item.DisabledAt = time.Time{}
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "producer_mtls_identity.disabled", Resource: "producer_mtls_identity", ResourceID: identityID, Reason: reason}); err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ProducerMTLSIdentity{}, err
	}
	return item, nil
}

func (s *Store) AuthenticateProducerMTLSIdentity(ctx context.Context, fingerprintSHA256 string) (authz.Actor, error) {
	var actor authz.Actor
	var identityID string
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, COALESCE(source_id,'')
		FROM producer_mtls_identities
		WHERE certificate_fingerprint_sha256=$1
		  AND state='active'
		  AND not_before <= now()
		  AND not_after > now()`,
		fingerprintSHA256,
	).Scan(&identityID, &actor.TenantID, &actor.SourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Actor{}, app.ErrUnauthorized
	}
	if err != nil {
		return authz.Actor{}, err
	}
	actor.ID = "producer_mtls:" + identityID
	actor.Role = authz.RoleDeveloper
	actor.Scopes = []string{"events:write"}
	return actor, nil
}

func (s *Store) CreateSource(ctx context.Context, source domain.Source) (domain.Source, error) {
	if source.ID == "" {
		source.ID = mustID("src")
	}
	if source.State == "" {
		source.State = domain.StateActive
	}
	encrypted, err := s.encryptSecret(ctx, source.TenantID, "source_verification_secret", source.VerificationSecret)
	if err != nil {
		return domain.Source{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Source{}, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, "INSERT INTO tenants(id, name) VALUES($1, $1) ON CONFLICT (id) DO NOTHING", source.TenantID); err != nil {
		return domain.Source{}, err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO sources(id, tenant_id, name, provider, adapter, state, encrypted_secret)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING created_at`,
		source.ID, source.TenantID, source.Name, source.Provider, source.Adapter, source.State, encrypted,
	).Scan(&source.CreatedAt)
	if err != nil {
		return domain.Source{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO source_secret_versions(id, tenant_id, source_id, version, encrypted_secret, state)
		VALUES($1,$2,$3,1,$4,'active')
		ON CONFLICT (tenant_id, source_id, version) DO NOTHING`,
		mustID("ssv"), source.TenantID, source.ID, encrypted,
	); err != nil {
		return domain.Source{}, err
	}
	if _, err := s.insertConfigVersion(ctx, tx, source.TenantID, domain.ConfigResourceSource, source.ID, 1, map[string]any{
		"id":       source.ID,
		"name":     source.Name,
		"provider": source.Provider,
		"adapter":  source.Adapter,
		"state":    source.State,
	}, source.CreatedBy); err != nil {
		return domain.Source{}, err
	}
	if source.CreatedBy != "" {
		if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: source.TenantID, ActorID: source.CreatedBy, Action: "source.created", Resource: "source", ResourceID: source.ID, Reason: source.Name}); err != nil {
			return domain.Source{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Source{}, err
	}
	source.VerificationSecret = nil
	return source, nil
}

func (s *Store) ListSources(ctx context.Context, tenantID string, limit int) ([]domain.Source, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, provider, adapter, state, created_at FROM sources WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Source
	for rows.Next() {
		var item domain.Source
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.Provider, &item.Adapter, &item.State, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetSource(ctx context.Context, tenantID, sourceID string) (domain.Source, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, tenant_id, name, provider, adapter, state, created_at FROM sources WHERE tenant_id=$1 AND id=$2`, tenantID, sourceID)
	item, err := scanSource(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Source{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateSource(ctx context.Context, tenantID, sourceID, actorID string, req app.UpdateSourceRequest) (domain.Source, error) {
	return s.updateSource(ctx, tenantID, sourceID, actorID, req, "source.updated")
}

func (s *Store) DeleteSource(ctx context.Context, tenantID, sourceID, actorID, reason string) (domain.Source, error) {
	state := domain.StateDisabled
	return s.updateSource(ctx, tenantID, sourceID, actorID, app.UpdateSourceRequest{State: &state, Reason: reason}, "source.disabled")
}

func (s *Store) updateSource(ctx context.Context, tenantID, sourceID, actorID string, req app.UpdateSourceRequest, action string) (domain.Source, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Source{}, err
	}
	defer rollback(ctx, tx)
	current, err := scanSource(tx.QueryRow(ctx, `SELECT id, tenant_id, name, provider, adapter, state, created_at FROM sources WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, sourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Source{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Source{}, err
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.State != nil {
		current.State = *req.State
	}
	if err := tx.QueryRow(ctx, `
		UPDATE sources
		SET name=$3, state=$4
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, provider, adapter, state, created_at`,
		tenantID, sourceID, current.Name, current.State,
	).Scan(&current.ID, &current.TenantID, &current.Name, &current.Provider, &current.Adapter, &current.State, &current.CreatedAt); err != nil {
		return domain.Source{}, err
	}
	version, err := s.nextConfigVersion(ctx, tx, tenantID, domain.ConfigResourceSource, sourceID)
	if err != nil {
		return domain.Source{}, err
	}
	if _, err := s.insertConfigVersion(ctx, tx, tenantID, domain.ConfigResourceSource, sourceID, version, map[string]any{
		"id":       current.ID,
		"name":     current.Name,
		"provider": current.Provider,
		"adapter":  current.Adapter,
		"state":    current.State,
	}, actorID); err != nil {
		return domain.Source{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: action, Resource: "source", ResourceID: sourceID, Reason: req.Reason}); err != nil {
		return domain.Source{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Source{}, err
	}
	return current, nil
}

func (s *Store) FindSource(ctx context.Context, tenantID, sourceID string) (domain.Source, error) {
	return s.findSource(ctx, `WHERE tenant_id=$1 AND id=$2`, tenantID, sourceID)
}

func (s *Store) FindSourceByProviderPath(ctx context.Context, provider, sourceID string) (domain.Source, error) {
	return s.findSource(ctx, `WHERE provider=$1 AND id=$2`, provider, sourceID)
}

func (s *Store) findSource(ctx context.Context, where string, args ...any) (domain.Source, error) {
	query := `SELECT id, tenant_id, name, provider, adapter, state, encrypted_secret, created_at FROM sources ` + where
	var item domain.Source
	var encrypted []byte
	err := s.pool.QueryRow(ctx, query, args...).Scan(&item.ID, &item.TenantID, &item.Name, &item.Provider, &item.Adapter, &item.State, &encrypted, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Source{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Source{}, err
	}
	secrets, err := s.sourceVerificationSecrets(ctx, item.TenantID, item.ID, encrypted)
	if err != nil {
		return domain.Source{}, err
	}
	if len(secrets) > 0 {
		item.VerificationSecret = secrets[0]
		item.VerificationSecrets = secrets
	}
	return item, nil
}

func (s *Store) sourceVerificationSecrets(ctx context.Context, tenantID, sourceID string, fallbackEncrypted []byte) ([][]byte, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT encrypted_secret
		FROM source_secret_versions
		WHERE tenant_id=$1
		  AND source_id=$2
		  AND (state='active' OR (state='previous' AND (expires_at IS NULL OR expires_at > now())))
		ORDER BY CASE WHEN state='active' THEN 0 ELSE 1 END, version DESC`,
		tenantID, sourceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var secrets [][]byte
	for rows.Next() {
		var encrypted []byte
		if err := rows.Scan(&encrypted); err != nil {
			return nil, err
		}
		plain, err := s.decryptSecret(ctx, tenantID, "source_verification_secret", encrypted)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, plain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(secrets) == 0 && len(fallbackEncrypted) > 0 {
		plain, err := s.decryptSecret(ctx, tenantID, "source_verification_secret", fallbackEncrypted)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, plain)
	}
	return secrets, nil
}

func (s *Store) CreateEndpoint(ctx context.Context, endpoint domain.Endpoint) (domain.Endpoint, error) {
	if endpoint.ID == "" {
		endpoint.ID = mustID("end")
	}
	if endpoint.State == "" {
		endpoint.State = domain.StateActive
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Endpoint{}, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, "INSERT INTO tenants(id, name) VALUES($1, $1) ON CONFLICT (id) DO NOTHING", endpoint.TenantID); err != nil {
		return domain.Endpoint{}, err
	}
	var encryptedMTLSCert, encryptedMTLSKey []byte
	if endpoint.MTLSEnabled {
		encryptedMTLSCert, err = s.encryptSecret(ctx, endpoint.TenantID, "endpoint_mtls_client_cert", endpoint.MTLSClientCertPEM)
		if err != nil {
			return domain.Endpoint{}, err
		}
		encryptedMTLSKey, err = s.encryptSecret(ctx, endpoint.TenantID, "endpoint_mtls_client_key", endpoint.MTLSClientKeyPEM)
		if err != nil {
			return domain.Endpoint{}, err
		}
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO endpoints(id, tenant_id, name, url, state, retry_policy_id, mtls_enabled, mtls_cert_subject, encrypted_mtls_client_cert, encrypted_mtls_client_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING created_at`,
		endpoint.ID, endpoint.TenantID, endpoint.Name, endpoint.URL, endpoint.State, endpoint.RetryPolicyID, endpoint.MTLSEnabled, endpoint.MTLSCertSubject, encryptedMTLSCert, encryptedMTLSKey,
	).Scan(&endpoint.CreatedAt)
	if err != nil {
		return domain.Endpoint{}, err
	}
	secret, err := random.Token("whsec_out", 32)
	if err != nil {
		return domain.Endpoint{}, err
	}
	encrypted, err := s.encryptSecret(ctx, endpoint.TenantID, "endpoint_signing_secret", []byte(secret))
	if err != nil {
		return domain.Endpoint{}, err
	}
	secretID := mustID("esec")
	if _, err := tx.Exec(ctx, `INSERT INTO endpoint_secrets(id, tenant_id, endpoint_id, encrypted_secret, version, state) VALUES($1,$2,$3,$4,1,'active')`, secretID, endpoint.TenantID, endpoint.ID, encrypted); err != nil {
		return domain.Endpoint{}, err
	}
	if _, err := s.insertConfigVersion(ctx, tx, endpoint.TenantID, domain.ConfigResourceEndpoint, endpoint.ID, 1, map[string]any{
		"id":              endpoint.ID,
		"name":            endpoint.Name,
		"url":             endpoint.URL,
		"state":           endpoint.State,
		"retry_policy_id": endpoint.RetryPolicyID,
		"signing_key_id":  secretID,
		"signing_version": 1,
		"mtls_enabled":    endpoint.MTLSEnabled,
		"mtls_subject":    endpoint.MTLSCertSubject,
	}, endpoint.CreatedBy); err != nil {
		return domain.Endpoint{}, err
	}
	if endpoint.CreatedBy != "" {
		if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: endpoint.TenantID, ActorID: endpoint.CreatedBy, Action: "endpoint.created", Resource: "endpoint", ResourceID: endpoint.ID, Reason: endpoint.Name}); err != nil {
			return domain.Endpoint{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Endpoint{}, err
	}
	return endpoint, nil
}

func (s *Store) ListEndpoints(ctx context.Context, tenantID string, limit int) ([]domain.Endpoint, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, url, state, COALESCE(retry_policy_id, ''), mtls_enabled, mtls_cert_subject, circuit_state, failure_count, COALESCE(disabled_until, 'epoch'::timestamptz), created_at FROM endpoints WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Endpoint
	for rows.Next() {
		item, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetEndpoint(ctx context.Context, tenantID, endpointID string) (domain.Endpoint, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, tenant_id, name, url, state, COALESCE(retry_policy_id, ''), mtls_enabled, mtls_cert_subject, circuit_state, failure_count, COALESCE(disabled_until, 'epoch'::timestamptz), created_at FROM endpoints WHERE tenant_id=$1 AND id=$2`, tenantID, endpointID)
	item, err := scanEndpoint(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Endpoint{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateEndpoint(ctx context.Context, tenantID, endpointID, actorID string, req app.UpdateEndpointRequest) (domain.Endpoint, error) {
	return s.updateEndpoint(ctx, tenantID, endpointID, actorID, req, "endpoint.updated")
}

func (s *Store) DeleteEndpoint(ctx context.Context, tenantID, endpointID, actorID, reason string) (domain.Endpoint, error) {
	state := domain.StateDisabled
	return s.updateEndpoint(ctx, tenantID, endpointID, actorID, app.UpdateEndpointRequest{State: &state, Reason: reason}, "endpoint.disabled")
}

func (s *Store) updateEndpoint(ctx context.Context, tenantID, endpointID, actorID string, req app.UpdateEndpointRequest, action string) (domain.Endpoint, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Endpoint{}, err
	}
	defer rollback(ctx, tx)
	current, err := scanEndpoint(tx.QueryRow(ctx, `SELECT id, tenant_id, name, url, state, COALESCE(retry_policy_id, ''), mtls_enabled, mtls_cert_subject, circuit_state, failure_count, COALESCE(disabled_until, 'epoch'::timestamptz), created_at FROM endpoints WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, endpointID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Endpoint{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Endpoint{}, err
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.URL != nil {
		current.URL = *req.URL
	}
	if req.State != nil {
		current.State = *req.State
	}
	if req.RetryPolicyID != nil {
		current.RetryPolicyID = *req.RetryPolicyID
	}
	if err := tx.QueryRow(ctx, `
		UPDATE endpoints
		SET name=$3, url=$4, state=$5, retry_policy_id=$6
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, url, state, COALESCE(retry_policy_id, ''), mtls_enabled, mtls_cert_subject, circuit_state, failure_count, COALESCE(disabled_until, 'epoch'::timestamptz), created_at`,
		tenantID, endpointID, current.Name, current.URL, current.State, current.RetryPolicyID,
	).Scan(&current.ID, &current.TenantID, &current.Name, &current.URL, &current.State, &current.RetryPolicyID, &current.MTLSEnabled, &current.MTLSCertSubject, &current.CircuitState, &current.FailureCount, &current.DisabledUntil, &current.CreatedAt); err != nil {
		return domain.Endpoint{}, err
	}
	version, err := s.nextConfigVersion(ctx, tx, tenantID, domain.ConfigResourceEndpoint, endpointID)
	if err != nil {
		return domain.Endpoint{}, err
	}
	if _, err := s.insertConfigVersion(ctx, tx, tenantID, domain.ConfigResourceEndpoint, endpointID, version, map[string]any{
		"id":                current.ID,
		"name":              current.Name,
		"url":               current.URL,
		"state":             current.State,
		"retry_policy_id":   current.RetryPolicyID,
		"mtls_enabled":      current.MTLSEnabled,
		"mtls_cert_subject": current.MTLSCertSubject,
	}, actorID); err != nil {
		return domain.Endpoint{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: action, Resource: "endpoint", ResourceID: endpointID, Reason: req.Reason}); err != nil {
		return domain.Endpoint{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Endpoint{}, err
	}
	return current, nil
}

func (s *Store) TestEndpoint(ctx context.Context, tenantID, endpointID, actorID, reason string) (domain.Delivery, error) {
	eventID := mustID("evt")
	rawID := mustID("raw")
	deliveryID := mustID("del")
	sourceID := "src_endpoint_test_" + tenantID
	body, err := json.Marshal(map[string]any{
		"id":          eventID,
		"type":        "webhookery.endpoint.test",
		"endpoint_id": endpointID,
		"reason":      reason,
	})
	if err != nil {
		return domain.Delivery{}, err
	}
	encrypted, err := s.encryptSecret(ctx, tenantID, "endpoint_test_source_secret", nil)
	if err != nil {
		return domain.Delivery{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Delivery{}, err
	}
	defer rollback(ctx, tx)
	var endpointExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM endpoints WHERE tenant_id=$1 AND id=$2)`, tenantID, endpointID).Scan(&endpointExists); err != nil {
		return domain.Delivery{}, err
	}
	if !endpointExists {
		return domain.Delivery{}, app.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `INSERT INTO sources(id, tenant_id, name, provider, adapter, state, encrypted_secret) VALUES($1,$2,'Endpoint test','internal','internal','active',$3) ON CONFLICT (id) DO NOTHING`, sourceID, tenantID, encrypted); err != nil {
		return domain.Delivery{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO raw_payloads(id, tenant_id, event_id, sha256, content_type, size_bytes, body) VALUES($1,$2,$3,$4,'application/json',$5,$6)`, rawID, tenantID, eventID, domain.HashSHA256(body), len(body), body); err != nil {
		return domain.Delivery{}, err
	}
	dedupeKey := "endpoint-test:" + deliveryID
	if _, err := tx.Exec(ctx, `
		INSERT INTO events(id, tenant_id, source_id, provider, type, provider_event_id, raw_payload_id, raw_payload_hash,
			signature_verified, verification_reason, dedupe_key, dedupe_status, received_at, trace_id)
		VALUES($1,$2,$3,'internal','webhookery.endpoint.test',$1,$4,$5,true,'ok',$6,$7,now(),'')`,
		eventID, tenantID, sourceID, rawID, domain.HashSHA256(body), dedupeKey, domain.DedupeUnique,
	); err != nil {
		return domain.Delivery{}, err
	}
	retrySeed := deliveryRetrySeed(tenantID, deliveryID, eventID, endpointID)
	if _, err := tx.Exec(ctx, `INSERT INTO deliveries(id, tenant_id, event_id, endpoint_id, retry_seed, state, next_attempt_at) VALUES($1,$2,$3,$4,$5,'scheduled',now())`, deliveryID, tenantID, eventID, endpointID, retrySeed); err != nil {
		return domain.Delivery{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO dedupe_records(tenant_id, source_id, dedupe_key, first_event_id, status) VALUES($1,$2,$3,$4,$5) ON CONFLICT (tenant_id, dedupe_key) DO UPDATE SET last_seen_at=now(), status=EXCLUDED.status`, tenantID, sourceID, dedupeKey, eventID, domain.DedupeUnique); err != nil {
		return domain.Delivery{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "endpoint.test_requested", Resource: "endpoint", ResourceID: endpointID, Reason: reason}); err != nil {
		return domain.Delivery{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Delivery{}, err
	}
	return domain.Delivery{ID: deliveryID, TenantID: tenantID, EventID: eventID, EndpointID: endpointID, RetrySeed: retrySeed, State: "scheduled", NextAttemptAt: time.Now().UTC()}, nil
}

func (s *Store) CreateSubscription(ctx context.Context, subscription domain.Subscription) (domain.Subscription, error) {
	if subscription.ID == "" {
		subscription.ID = mustID("sub")
	}
	if subscription.State == "" {
		subscription.State = domain.StateActive
	}
	if subscription.PayloadFormat == "" {
		subscription.PayloadFormat = "canonical_json"
	}
	if subscription.Version == 0 {
		subscription.Version = 1
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Subscription{}, err
	}
	defer rollback(ctx, tx)
	if err := s.requireActiveEndpoint(ctx, tx, subscription.TenantID, subscription.EndpointID); err != nil {
		return domain.Subscription{}, err
	}
	if subscription.TransformationID != "" {
		versionID, err := s.activeTransformationVersionID(ctx, tx, subscription.TenantID, subscription.TransformationID)
		if err != nil {
			return domain.Subscription{}, err
		}
		subscription.TransformationVersionID = versionID
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO subscriptions(id, tenant_id, endpoint_id, event_types, payload_format, transformation_id, transformation_version_id, state, version)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING created_at`,
		subscription.ID, subscription.TenantID, subscription.EndpointID, subscription.EventTypes, subscription.PayloadFormat,
		subscription.TransformationID, subscription.TransformationVersionID, subscription.State, subscription.Version,
	).Scan(&subscription.CreatedAt)
	if err != nil {
		return domain.Subscription{}, err
	}
	version, err := s.insertSubscriptionVersion(ctx, tx, subscription, "")
	if err != nil {
		return domain.Subscription{}, err
	}
	subscription.ActiveVersionID = version.ID
	if _, err := tx.Exec(ctx, `UPDATE subscriptions SET active_version_id=$1 WHERE tenant_id=$2 AND id=$3`, version.ID, subscription.TenantID, subscription.ID); err != nil {
		return domain.Subscription{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Subscription{}, err
	}
	return subscription, nil
}

func (s *Store) ListSubscriptions(ctx context.Context, tenantID string, limit int) ([]domain.Subscription, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, endpoint_id, event_types, payload_format, transformation_id, transformation_version_id, state, version, active_version_id, created_at FROM subscriptions WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Subscription
	for rows.Next() {
		item, err := scanSubscription(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetSubscription(ctx context.Context, tenantID, subscriptionID string) (domain.Subscription, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, tenant_id, endpoint_id, event_types, payload_format, transformation_id, transformation_version_id, state, version, active_version_id, created_at FROM subscriptions WHERE tenant_id=$1 AND id=$2`, tenantID, subscriptionID)
	item, err := scanSubscription(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Subscription{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateSubscription(ctx context.Context, tenantID, subscriptionID, actorID string, req app.UpdateSubscriptionRequest) (domain.Subscription, error) {
	return s.updateSubscription(ctx, tenantID, subscriptionID, actorID, req, "subscription.updated")
}

func (s *Store) DeleteSubscription(ctx context.Context, tenantID, subscriptionID, actorID, reason string) (domain.Subscription, error) {
	state := domain.StateDisabled
	return s.updateSubscription(ctx, tenantID, subscriptionID, actorID, app.UpdateSubscriptionRequest{State: &state, Reason: reason}, "subscription.disabled")
}

func (s *Store) updateSubscription(ctx context.Context, tenantID, subscriptionID, actorID string, req app.UpdateSubscriptionRequest, action string) (domain.Subscription, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Subscription{}, err
	}
	defer rollback(ctx, tx)
	current, err := scanSubscription(tx.QueryRow(ctx, `SELECT id, tenant_id, endpoint_id, event_types, payload_format, transformation_id, transformation_version_id, state, version, active_version_id, created_at FROM subscriptions WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, subscriptionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Subscription{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Subscription{}, err
	}
	if req.EndpointID != nil {
		if err := s.requireActiveEndpoint(ctx, tx, tenantID, *req.EndpointID); err != nil {
			return domain.Subscription{}, err
		}
		current.EndpointID = *req.EndpointID
	}
	if req.EventTypes != nil {
		current.EventTypes = req.EventTypes
	}
	if req.PayloadFormat != nil {
		current.PayloadFormat = *req.PayloadFormat
	}
	if req.TransformationID != nil {
		current.TransformationID = *req.TransformationID
		current.TransformationVersionID = ""
		if current.TransformationID != "" {
			versionID, err := s.activeTransformationVersionID(ctx, tx, tenantID, current.TransformationID)
			if err != nil {
				return domain.Subscription{}, err
			}
			current.TransformationVersionID = versionID
		}
	}
	if req.State != nil {
		current.State = *req.State
	}
	err = tx.QueryRow(ctx, `
		UPDATE subscriptions
		SET endpoint_id=$3, event_types=$4, payload_format=$5, transformation_id=$6, transformation_version_id=$7, state=$8, version=version+1
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, endpoint_id, event_types, payload_format, transformation_id, transformation_version_id, state, version, active_version_id, created_at`,
		tenantID, subscriptionID, current.EndpointID, current.EventTypes, current.PayloadFormat, current.TransformationID, current.TransformationVersionID, current.State,
	).Scan(&current.ID, &current.TenantID, &current.EndpointID, &current.EventTypes, &current.PayloadFormat, &current.TransformationID, &current.TransformationVersionID, &current.State, &current.Version, &current.ActiveVersionID, &current.CreatedAt)
	if err != nil {
		return domain.Subscription{}, err
	}
	version, err := s.insertSubscriptionVersion(ctx, tx, current, actorID)
	if err != nil {
		return domain.Subscription{}, err
	}
	current.ActiveVersionID = version.ID
	if _, err := tx.Exec(ctx, `UPDATE subscriptions SET active_version_id=$1 WHERE tenant_id=$2 AND id=$3`, version.ID, tenantID, subscriptionID); err != nil {
		return domain.Subscription{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: action, Resource: "subscription", ResourceID: subscriptionID, Reason: req.Reason}); err != nil {
		return domain.Subscription{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Subscription{}, err
	}
	return current, nil
}

func (s *Store) CreateRoute(ctx context.Context, route domain.Route) (domain.Route, error) {
	if route.ID == "" {
		route.ID = mustID("rte")
	}
	if route.State == "" {
		route.State = "draft"
	}
	if route.Priority == 0 {
		route.Priority = 100
	}
	if route.Version == 0 {
		route.Version = 1
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Route{}, err
	}
	defer rollback(ctx, tx)
	if err := s.requireActiveSource(ctx, tx, route.TenantID, route.SourceID); err != nil {
		return domain.Route{}, err
	}
	if err := s.requireActiveEndpoint(ctx, tx, route.TenantID, route.EndpointID); err != nil {
		return domain.Route{}, err
	}
	if route.TransformationID != "" {
		versionID, err := s.activeTransformationVersionID(ctx, tx, route.TenantID, route.TransformationID)
		if err != nil {
			return domain.Route{}, err
		}
		route.TransformationVersionID = versionID
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO routes(id, tenant_id, source_id, name, priority, event_types, endpoint_id, state, version, retry_policy_id, transformation_id, transformation_version_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING created_at`,
		route.ID, route.TenantID, route.SourceID, route.Name, route.Priority, route.EventTypes, route.EndpointID,
		route.State, route.Version, route.RetryPolicyID, route.TransformationID, route.TransformationVersionID,
	).Scan(&route.CreatedAt)
	if err != nil {
		return domain.Route{}, err
	}
	version, err := s.insertRouteVersion(ctx, tx, route, route.CreatedBy)
	if err != nil {
		return domain.Route{}, err
	}
	route.ActiveVersionID = version.ID
	if _, err := tx.Exec(ctx, `UPDATE routes SET active_version_id=$1 WHERE tenant_id=$2 AND id=$3`, version.ID, route.TenantID, route.ID); err != nil {
		return domain.Route{}, err
	}
	if route.CreatedBy != "" {
		if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: route.TenantID, ActorID: route.CreatedBy, Action: "route.created", Resource: "route", ResourceID: route.ID, Reason: route.Name}); err != nil {
			return domain.Route{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Route{}, err
	}
	return route, nil
}

func (s *Store) ListRoutes(ctx context.Context, tenantID string, limit int) ([]domain.Route, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, source_id, name, priority, event_types, endpoint_id, state, version, active_version_id, retry_policy_id, transformation_id, transformation_version_id, created_at FROM routes WHERE tenant_id=$1 ORDER BY priority ASC, created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Route
	for rows.Next() {
		item, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetRoute(ctx context.Context, tenantID, routeID string) (domain.Route, error) {
	return s.getRoute(ctx, tenantID, routeID)
}

func (s *Store) UpdateRoute(ctx context.Context, tenantID, routeID, actorID string, req app.UpdateRouteRequest) (domain.Route, error) {
	return s.updateRoute(ctx, tenantID, routeID, actorID, req, "route.updated")
}

func (s *Store) DeleteRoute(ctx context.Context, tenantID, routeID, actorID, reason string) (domain.Route, error) {
	state := domain.StateInactive
	return s.updateRoute(ctx, tenantID, routeID, actorID, app.UpdateRouteRequest{State: &state, Reason: reason}, "route.inactivated")
}

func (s *Store) updateRoute(ctx context.Context, tenantID, routeID, actorID string, req app.UpdateRouteRequest, action string) (domain.Route, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Route{}, err
	}
	defer rollback(ctx, tx)
	current, err := scanRoute(tx.QueryRow(ctx, `SELECT id, tenant_id, source_id, name, priority, event_types, endpoint_id, state, version, active_version_id, retry_policy_id, transformation_id, transformation_version_id, created_at FROM routes WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, routeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Route{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Route{}, err
	}
	if req.SourceID != nil {
		if err := s.requireActiveSource(ctx, tx, tenantID, *req.SourceID); err != nil {
			return domain.Route{}, err
		}
		current.SourceID = *req.SourceID
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.Priority != nil {
		current.Priority = *req.Priority
	}
	if req.EventTypes != nil {
		current.EventTypes = req.EventTypes
	}
	if req.EndpointID != nil {
		if err := s.requireActiveEndpoint(ctx, tx, tenantID, *req.EndpointID); err != nil {
			return domain.Route{}, err
		}
		current.EndpointID = *req.EndpointID
	}
	if req.RetryPolicyID != nil {
		current.RetryPolicyID = *req.RetryPolicyID
	}
	if req.TransformationID != nil {
		current.TransformationID = *req.TransformationID
		current.TransformationVersionID = ""
		if current.TransformationID != "" {
			versionID, err := s.activeTransformationVersionID(ctx, tx, tenantID, current.TransformationID)
			if err != nil {
				return domain.Route{}, err
			}
			current.TransformationVersionID = versionID
		}
	}
	if req.State != nil {
		current.State = *req.State
	}
	err = tx.QueryRow(ctx, `
		UPDATE routes
		SET source_id=$3, name=$4, priority=$5, event_types=$6, endpoint_id=$7, state=$8, retry_policy_id=$9, transformation_id=$10, transformation_version_id=$11, version=version+1
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, source_id, name, priority, event_types, endpoint_id, state, version, active_version_id, retry_policy_id, transformation_id, transformation_version_id, created_at`,
		tenantID, routeID, current.SourceID, current.Name, current.Priority, current.EventTypes, current.EndpointID,
		current.State, current.RetryPolicyID, current.TransformationID, current.TransformationVersionID,
	).Scan(&current.ID, &current.TenantID, &current.SourceID, &current.Name, &current.Priority, &current.EventTypes, &current.EndpointID, &current.State, &current.Version, &current.ActiveVersionID, &current.RetryPolicyID, &current.TransformationID, &current.TransformationVersionID, &current.CreatedAt)
	if err != nil {
		return domain.Route{}, err
	}
	version, err := s.insertRouteVersion(ctx, tx, current, actorID)
	if err != nil {
		return domain.Route{}, err
	}
	current.ActiveVersionID = version.ID
	if _, err := tx.Exec(ctx, `UPDATE routes SET active_version_id=$1 WHERE tenant_id=$2 AND id=$3`, version.ID, tenantID, routeID); err != nil {
		return domain.Route{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: action, Resource: "route", ResourceID: routeID, Reason: req.Reason}); err != nil {
		return domain.Route{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Route{}, err
	}
	return current, nil
}

func (s *Store) ListRouteVersions(ctx context.Context, tenantID, routeID string, limit int) ([]domain.RouteVersion, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, route_id, version, config_hash, source_id, name, priority, event_types, endpoint_id, retry_policy_id, transformation_id, transformation_version_id, state, created_by, created_at
		FROM route_versions
		WHERE tenant_id=$1 AND route_id=$2
		ORDER BY version DESC
		LIMIT $3`, tenantID, routeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.RouteVersion
	for rows.Next() {
		item, err := scanRouteVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ActivateRoute(ctx context.Context, tenantID, routeID, actorID, reason string) (domain.Route, error) {
	var route domain.Route
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Route{}, err
	}
	defer rollback(ctx, tx)
	err = tx.QueryRow(ctx, `UPDATE routes SET state='active', version=version+1 WHERE tenant_id=$1 AND id=$2 RETURNING id, tenant_id, source_id, name, priority, event_types, endpoint_id, state, version, active_version_id, retry_policy_id, transformation_id, transformation_version_id, created_at`, tenantID, routeID).Scan(&route.ID, &route.TenantID, &route.SourceID, &route.Name, &route.Priority, &route.EventTypes, &route.EndpointID, &route.State, &route.Version, &route.ActiveVersionID, &route.RetryPolicyID, &route.TransformationID, &route.TransformationVersionID, &route.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Route{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Route{}, err
	}
	version, err := s.insertRouteVersion(ctx, tx, route, actorID)
	if err != nil {
		return domain.Route{}, err
	}
	route.ActiveVersionID = version.ID
	if _, err := tx.Exec(ctx, `UPDATE routes SET active_version_id=$1 WHERE tenant_id=$2 AND id=$3`, version.ID, tenantID, routeID); err != nil {
		return domain.Route{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "route.activated", Resource: "route", ResourceID: routeID, Reason: reason}); err != nil {
		return domain.Route{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Route{}, err
	}
	return route, nil
}

func (s *Store) DryRunRoute(ctx context.Context, tenantID, routeID, eventID string) (app.RouteDryRun, error) {
	route, err := s.getRoute(ctx, tenantID, routeID)
	if err != nil {
		return app.RouteDryRun{}, err
	}
	event, err := s.GetEvent(ctx, tenantID, eventID)
	if err != nil {
		return app.RouteDryRun{}, err
	}
	matched := route.SourceID == event.SourceID && containsString(route.EventTypes, event.Type)
	out := app.RouteDryRun{
		Matched: matched,
		Explanation: []map[string]any{
			{"name": "source_id", "expected": route.SourceID, "actual": event.SourceID, "result": route.SourceID == event.SourceID},
			{"name": "event_type", "expected": route.EventTypes, "actual": event.Type, "result": containsString(route.EventTypes, event.Type)},
		},
	}
	if matched {
		out.WouldCreateDeliveries = append(out.WouldCreateDeliveries, map[string]any{"endpoint_id": route.EndpointID, "route_id": route.ID, "route_version_id": route.ActiveVersionID, "retry_policy_id": route.RetryPolicyID, "transformation_id": route.TransformationID, "transformation_version_id": route.TransformationVersionID})
	}
	return out, nil
}

func (s *Store) CreateRetryPolicy(ctx context.Context, tenantID, actorID string, req app.CreateRetryPolicyRequest) (domain.RetryPolicy, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.RetryPolicy{}, err
	}
	defer rollback(ctx, tx)
	var version int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1 FROM retry_policies WHERE tenant_id=$1 AND name=$2`, tenantID, req.Name).Scan(&version); err != nil {
		return domain.RetryPolicy{}, err
	}
	item := domain.RetryPolicy{
		ID:                  mustID("rtp"),
		TenantID:            tenantID,
		Name:                req.Name,
		Version:             version,
		State:               req.State,
		MaxAttempts:         req.MaxAttempts,
		MaxDurationSeconds:  req.MaxDurationSeconds,
		InitialDelaySeconds: req.InitialDelaySeconds,
		MaxDelaySeconds:     req.MaxDelaySeconds,
		RateLimitPerMinute:  req.RateLimitPerMinute,
		CreatedBy:           actorID,
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO retry_policies(id, tenant_id, name, version, state, max_attempts, max_duration_seconds, initial_delay_seconds, max_delay_seconds, rate_limit_per_minute, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING created_at`,
		item.ID, item.TenantID, item.Name, item.Version, item.State, item.MaxAttempts, item.MaxDurationSeconds,
		item.InitialDelaySeconds, item.MaxDelaySeconds, item.RateLimitPerMinute, item.CreatedBy,
	).Scan(&item.CreatedAt)
	if err != nil {
		return domain.RetryPolicy{}, err
	}
	if _, err := s.insertConfigVersion(ctx, tx, tenantID, domain.ConfigResourceRetryPolicy, item.ID, item.Version, item, actorID); err != nil {
		return domain.RetryPolicy{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "retry_policy.created", Resource: "retry_policy", ResourceID: item.ID, Reason: item.Name}); err != nil {
		return domain.RetryPolicy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.RetryPolicy{}, err
	}
	return item, nil
}

func (s *Store) ListRetryPolicies(ctx context.Context, tenantID string, limit int) ([]domain.RetryPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, version, state, max_attempts, max_duration_seconds, initial_delay_seconds, max_delay_seconds, rate_limit_per_minute, created_by, created_at
		FROM retry_policies
		WHERE tenant_id=$1
		ORDER BY name ASC, version DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.RetryPolicy
	for rows.Next() {
		item, err := scanRetryPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetRetryPolicy(ctx context.Context, tenantID, retryPolicyID string) (domain.RetryPolicy, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, version, state, max_attempts, max_duration_seconds, initial_delay_seconds, max_delay_seconds, rate_limit_per_minute, created_by, created_at
		FROM retry_policies
		WHERE tenant_id=$1 AND id=$2`, tenantID, retryPolicyID)
	item, err := scanRetryPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RetryPolicy{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateRetryPolicy(ctx context.Context, tenantID, retryPolicyID, actorID string, req app.UpdateRetryPolicyRequest) (domain.RetryPolicy, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.RetryPolicy{}, err
	}
	defer rollback(ctx, tx)
	current, err := scanRetryPolicy(tx.QueryRow(ctx, `
		SELECT id, tenant_id, name, version, state, max_attempts, max_duration_seconds, initial_delay_seconds, max_delay_seconds, rate_limit_per_minute, created_by, created_at
		FROM retry_policies
		WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, retryPolicyID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RetryPolicy{}, app.ErrNotFound
	}
	if err != nil {
		return domain.RetryPolicy{}, err
	}
	item := current
	item.ID = mustID("rtp")
	item.CreatedBy = actorID
	if req.Name != nil {
		item.Name = *req.Name
	}
	if req.MaxAttempts != nil {
		item.MaxAttempts = *req.MaxAttempts
	}
	if req.MaxDurationSeconds != nil {
		item.MaxDurationSeconds = *req.MaxDurationSeconds
	}
	if req.InitialDelaySeconds != nil {
		item.InitialDelaySeconds = *req.InitialDelaySeconds
	}
	if req.MaxDelaySeconds != nil {
		item.MaxDelaySeconds = *req.MaxDelaySeconds
	}
	if req.RateLimitPerMinute != nil {
		item.RateLimitPerMinute = *req.RateLimitPerMinute
	}
	if req.State != nil {
		item.State = *req.State
	}
	if item.InitialDelaySeconds > item.MaxDelaySeconds {
		return domain.RetryPolicy{}, fmt.Errorf("%w: initial_delay_seconds must be no greater than max_delay_seconds", app.ErrInvalidInput)
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1 FROM retry_policies WHERE tenant_id=$1 AND name=$2`, tenantID, item.Name).Scan(&item.Version); err != nil {
		return domain.RetryPolicy{}, err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO retry_policies(id, tenant_id, name, version, state, max_attempts, max_duration_seconds, initial_delay_seconds, max_delay_seconds, rate_limit_per_minute, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING created_at`,
		item.ID, item.TenantID, item.Name, item.Version, item.State, item.MaxAttempts, item.MaxDurationSeconds,
		item.InitialDelaySeconds, item.MaxDelaySeconds, item.RateLimitPerMinute, item.CreatedBy,
	).Scan(&item.CreatedAt)
	if err != nil {
		return domain.RetryPolicy{}, err
	}
	if _, err := s.insertConfigVersion(ctx, tx, tenantID, domain.ConfigResourceRetryPolicy, item.ID, item.Version, item, actorID); err != nil {
		return domain.RetryPolicy{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "retry_policy.updated", Resource: "retry_policy", ResourceID: item.ID, Reason: req.Reason}); err != nil {
		return domain.RetryPolicy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.RetryPolicy{}, err
	}
	return item, nil
}

func (s *Store) DeleteRetryPolicy(ctx context.Context, tenantID, retryPolicyID, actorID, reason string) (domain.RetryPolicy, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.RetryPolicy{}, err
	}
	defer rollback(ctx, tx)
	item, err := scanRetryPolicy(tx.QueryRow(ctx, `
		UPDATE retry_policies
		SET state='disabled'
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, version, state, max_attempts, max_duration_seconds, initial_delay_seconds, max_delay_seconds, rate_limit_per_minute, created_by, created_at`,
		tenantID, retryPolicyID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RetryPolicy{}, app.ErrNotFound
	}
	if err != nil {
		return domain.RetryPolicy{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "retry_policy.disabled", Resource: "retry_policy", ResourceID: retryPolicyID, Reason: reason}); err != nil {
		return domain.RetryPolicy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.RetryPolicy{}, err
	}
	return item, nil
}

func (s *Store) CreateTransformation(ctx context.Context, tenantID, actorID string, req app.CreateTransformationRequest) (domain.Transformation, error) {
	item := domain.Transformation{
		ID:        mustID("trn"),
		TenantID:  tenantID,
		Name:      strings.TrimSpace(req.Name),
		State:     domain.StateActive,
		CreatedBy: actorID,
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Transformation{}, err
	}
	defer rollback(ctx, tx)
	err = tx.QueryRow(ctx, `
		INSERT INTO transformations(id, tenant_id, name, state, created_by)
		VALUES($1,$2,$3,$4,$5)
		RETURNING created_at, updated_at`,
		item.ID, item.TenantID, item.Name, item.State, item.CreatedBy,
	).Scan(&item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.Transformation{}, err
	}
	if len(req.Operations) != 0 {
		version, err := s.insertTransformationVersion(ctx, tx, tenantID, item.ID, actorID, req.Operations, domain.StateActive)
		if err != nil {
			return domain.Transformation{}, err
		}
		item.ActiveVersionID = version.ID
		if _, err := tx.Exec(ctx, `UPDATE transformations SET active_version_id=$1, updated_at=now() WHERE tenant_id=$2 AND id=$3`, version.ID, tenantID, item.ID); err != nil {
			return domain.Transformation{}, err
		}
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "transformation.created", Resource: "transformation", ResourceID: item.ID, Reason: item.Name}); err != nil {
		return domain.Transformation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Transformation{}, err
	}
	return item, nil
}

func (s *Store) ListTransformations(ctx context.Context, tenantID string, limit int) ([]domain.Transformation, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, state, active_version_id, created_by, created_at, updated_at FROM transformations WHERE tenant_id=$1 ORDER BY updated_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Transformation
	for rows.Next() {
		item, err := scanTransformation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetTransformation(ctx context.Context, tenantID, transformationID string) (domain.Transformation, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, tenant_id, name, state, active_version_id, created_by, created_at, updated_at FROM transformations WHERE tenant_id=$1 AND id=$2`, tenantID, transformationID)
	item, err := scanTransformation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Transformation{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) CreateTransformationVersion(ctx context.Context, tenantID, transformationID, actorID string, req app.CreateTransformationVersionRequest) (domain.TransformationVersion, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.TransformationVersion{}, err
	}
	defer rollback(ctx, tx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM transformations WHERE tenant_id=$1 AND id=$2)`, tenantID, transformationID).Scan(&exists); err != nil {
		return domain.TransformationVersion{}, err
	}
	if !exists {
		return domain.TransformationVersion{}, app.ErrNotFound
	}
	item, err := s.insertTransformationVersion(ctx, tx, tenantID, transformationID, actorID, req.Operations, "draft")
	if err != nil {
		return domain.TransformationVersion{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE transformations SET updated_at=now() WHERE tenant_id=$1 AND id=$2`, tenantID, transformationID); err != nil {
		return domain.TransformationVersion{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "transformation_version.created", Resource: "transformation", ResourceID: transformationID, Reason: item.ConfigHash}); err != nil {
		return domain.TransformationVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.TransformationVersion{}, err
	}
	return item, nil
}

func (s *Store) ListTransformationVersions(ctx context.Context, tenantID, transformationID string, limit int) ([]domain.TransformationVersion, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, transformation_id, version, config_hash, operations_json, state, created_by, created_at
		FROM transformation_versions
		WHERE tenant_id=$1 AND transformation_id=$2
		ORDER BY version DESC
		LIMIT $3`, tenantID, transformationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.TransformationVersion
	for rows.Next() {
		item, err := scanTransformationVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ActivateTransformationVersion(ctx context.Context, tenantID, transformationID, versionID, actorID, reason string) (domain.TransformationVersion, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.TransformationVersion{}, err
	}
	defer rollback(ctx, tx)
	var item domain.TransformationVersion
	err = tx.QueryRow(ctx, `
		UPDATE transformation_versions
		SET state='active'
		WHERE tenant_id=$1 AND transformation_id=$2 AND id=$3
		RETURNING id, tenant_id, transformation_id, version, config_hash, operations_json, state, created_by, created_at`,
		tenantID, transformationID, versionID,
	).Scan(&item.ID, &item.TenantID, &item.TransformationID, &item.Version, &item.ConfigHash, &item.Operations, &item.State, &item.CreatedBy, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TransformationVersion{}, app.ErrNotFound
	}
	if err != nil {
		return domain.TransformationVersion{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE transformation_versions SET state='inactive' WHERE tenant_id=$1 AND transformation_id=$2 AND id<>$3 AND state='active'`, tenantID, transformationID, versionID); err != nil {
		return domain.TransformationVersion{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE transformations SET active_version_id=$1, updated_at=now() WHERE tenant_id=$2 AND id=$3`, versionID, tenantID, transformationID); err != nil {
		return domain.TransformationVersion{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "transformation_version.activated", Resource: "transformation", ResourceID: transformationID, Reason: reason}); err != nil {
		return domain.TransformationVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.TransformationVersion{}, err
	}
	return item, nil
}

func (s *Store) CreateEventType(ctx context.Context, eventType domain.EventType) (domain.EventType, error) {
	if eventType.State == "" {
		eventType.State = domain.StateActive
	}
	err := s.pool.QueryRow(ctx, `INSERT INTO event_types(tenant_id, name, description, state) VALUES($1,$2,$3,$4) RETURNING created_at`, eventType.TenantID, eventType.Name, eventType.Description, eventType.State).Scan(&eventType.CreatedAt)
	return eventType, err
}

func (s *Store) ListEventTypes(ctx context.Context, tenantID string, limit int) ([]domain.EventType, error) {
	rows, err := s.pool.Query(ctx, `SELECT tenant_id, name, description, state, created_at FROM event_types WHERE tenant_id=$1 ORDER BY name ASC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.EventType
	for rows.Next() {
		var item domain.EventType
		if err := rows.Scan(&item.TenantID, &item.Name, &item.Description, &item.State, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetEventType(ctx context.Context, tenantID, eventType string) (domain.EventType, error) {
	item, err := scanEventType(s.pool.QueryRow(ctx, `SELECT tenant_id, name, description, state, created_at FROM event_types WHERE tenant_id=$1 AND name=$2`, tenantID, eventType))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.EventType{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateEventType(ctx context.Context, tenantID, eventType, actorID string, req app.UpdateEventTypeRequest) (domain.EventType, error) {
	return s.updateEventType(ctx, tenantID, eventType, actorID, req, "event_type.updated")
}

func (s *Store) DeleteEventType(ctx context.Context, tenantID, eventType, actorID, reason string) (domain.EventType, error) {
	state := domain.StateDisabled
	return s.updateEventType(ctx, tenantID, eventType, actorID, app.UpdateEventTypeRequest{State: &state, Reason: reason}, "event_type.disabled")
}

func (s *Store) updateEventType(ctx context.Context, tenantID, eventType, actorID string, req app.UpdateEventTypeRequest, action string) (domain.EventType, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.EventType{}, err
	}
	defer rollback(ctx, tx)
	current, err := scanEventType(tx.QueryRow(ctx, `SELECT tenant_id, name, description, state, created_at FROM event_types WHERE tenant_id=$1 AND name=$2 FOR UPDATE`, tenantID, eventType))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.EventType{}, app.ErrNotFound
	}
	if err != nil {
		return domain.EventType{}, err
	}
	if req.Description != nil {
		current.Description = *req.Description
	}
	if req.State != nil {
		current.State = *req.State
	}
	current, err = scanEventType(tx.QueryRow(ctx, `
		UPDATE event_types
		SET description=$3, state=$4
		WHERE tenant_id=$1 AND name=$2
		RETURNING tenant_id, name, description, state, created_at`,
		tenantID, eventType, current.Description, current.State,
	))
	if err != nil {
		return domain.EventType{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: action, Resource: "event_type", ResourceID: eventType, Reason: req.Reason}); err != nil {
		return domain.EventType{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.EventType{}, err
	}
	return current, nil
}

func (s *Store) CreateEventSchema(ctx context.Context, schema domain.EventSchema) (domain.EventSchema, error) {
	if schema.ID == "" {
		schema.ID = mustID("sch")
	}
	if schema.State == "" {
		schema.State = domain.StateActive
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.EventSchema{}, err
	}
	defer rollback(ctx, tx)
	err = tx.QueryRow(ctx, `INSERT INTO event_schemas(id, tenant_id, event_type, version, schema_json, state) VALUES($1,$2,$3,$4,$5,$6) RETURNING created_at`, schema.ID, schema.TenantID, schema.EventType, schema.Version, schema.Schema, schema.State).Scan(&schema.CreatedAt)
	if err != nil {
		return domain.EventSchema{}, err
	}
	configVersion := 1
	if parsed, parseErr := strconv.Atoi(schema.Version); parseErr == nil && parsed > 0 {
		configVersion = parsed
	}
	if _, err := s.insertConfigVersion(ctx, tx, schema.TenantID, domain.ConfigResourceSchema, schema.ID, configVersion, map[string]any{
		"id":         schema.ID,
		"event_type": schema.EventType,
		"version":    schema.Version,
		"schema":     schema.Schema,
		"state":      schema.State,
	}, ""); err != nil {
		return domain.EventSchema{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.EventSchema{}, err
	}
	return schema, nil
}

func (s *Store) ListEventSchemas(ctx context.Context, tenantID, eventType string, limit int) ([]domain.EventSchema, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, event_type, version, schema_json, state, created_at FROM event_schemas WHERE tenant_id=$1 AND event_type=$2 ORDER BY created_at DESC LIMIT $3`, tenantID, eventType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.EventSchema
	for rows.Next() {
		item, err := scanEventSchema(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetEventSchema(ctx context.Context, tenantID, eventType, version string) (domain.EventSchema, error) {
	item, err := scanEventSchema(s.pool.QueryRow(ctx, `SELECT id, tenant_id, event_type, version, schema_json, state, created_at FROM event_schemas WHERE tenant_id=$1 AND event_type=$2 AND version=$3`, tenantID, eventType, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.EventSchema{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateEventSchema(ctx context.Context, tenantID, eventType, version, actorID string, req app.UpdateEventSchemaRequest) (domain.EventSchema, error) {
	return s.updateEventSchema(ctx, tenantID, eventType, version, actorID, req, "event_schema.updated")
}

func (s *Store) DeleteEventSchema(ctx context.Context, tenantID, eventType, version, actorID, reason string) (domain.EventSchema, error) {
	state := domain.StateRetired
	return s.updateEventSchema(ctx, tenantID, eventType, version, actorID, app.UpdateEventSchemaRequest{State: &state, Reason: reason}, "event_schema.retired")
}

func (s *Store) updateEventSchema(ctx context.Context, tenantID, eventType, version, actorID string, req app.UpdateEventSchemaRequest, action string) (domain.EventSchema, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.EventSchema{}, err
	}
	defer rollback(ctx, tx)
	current, err := scanEventSchema(tx.QueryRow(ctx, `SELECT id, tenant_id, event_type, version, schema_json, state, created_at FROM event_schemas WHERE tenant_id=$1 AND event_type=$2 AND version=$3 FOR UPDATE`, tenantID, eventType, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.EventSchema{}, app.ErrNotFound
	}
	if err != nil {
		return domain.EventSchema{}, err
	}
	if req.State != nil {
		current.State = *req.State
	}
	current, err = scanEventSchema(tx.QueryRow(ctx, `
		UPDATE event_schemas
		SET state=$4
		WHERE tenant_id=$1 AND event_type=$2 AND version=$3
		RETURNING id, tenant_id, event_type, version, schema_json, state, created_at`,
		tenantID, eventType, version, current.State,
	))
	if err != nil {
		return domain.EventSchema{}, err
	}
	configVersion, err := s.nextConfigVersion(ctx, tx, tenantID, domain.ConfigResourceSchema, current.ID)
	if err != nil {
		return domain.EventSchema{}, err
	}
	if _, err := s.insertConfigVersion(ctx, tx, tenantID, domain.ConfigResourceSchema, current.ID, configVersion, map[string]any{
		"id":         current.ID,
		"event_type": current.EventType,
		"version":    current.Version,
		"schema":     current.Schema,
		"state":      current.State,
	}, actorID); err != nil {
		return domain.EventSchema{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: action, Resource: "event_schema", ResourceID: current.ID, Reason: req.Reason}); err != nil {
		return domain.EventSchema{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.EventSchema{}, err
	}
	return current, nil
}

func (s *Store) RotateSourceSecret(ctx context.Context, tenantID, sourceID, actorID string, req app.RotateSourceSecretRequest) (domain.SourceSecretVersion, error) {
	encrypted, err := s.encryptSecret(ctx, tenantID, "source_verification_secret", []byte(req.NewSecret))
	if err != nil {
		return domain.SourceSecretVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.SourceSecretVersion{}, err
	}
	defer rollback(ctx, tx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sources WHERE tenant_id=$1 AND id=$2)`, tenantID, sourceID).Scan(&exists); err != nil {
		return domain.SourceSecretVersion{}, err
	}
	if !exists {
		return domain.SourceSecretVersion{}, app.ErrNotFound
	}
	version, graceUntil, err := nextSecretVersion(ctx, tx, "source_secret_versions", tenantID, sourceID, req.GracePeriodHours)
	if err != nil {
		return domain.SourceSecretVersion{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE source_secret_versions
		SET state='previous', expires_at=$3
		WHERE tenant_id=$1 AND source_id=$2 AND state='active'`,
		tenantID, sourceID, graceUntil,
	); err != nil {
		return domain.SourceSecretVersion{}, err
	}
	id := mustID("ssv")
	var item domain.SourceSecretVersion
	err = tx.QueryRow(ctx, `
		INSERT INTO source_secret_versions(id, tenant_id, source_id, version, encrypted_secret, state, active_at, created_by)
		VALUES($1,$2,$3,$4,$5,'active',now(),$6)
		RETURNING id, tenant_id, source_id, version, state, active_at, COALESCE(expires_at, 'epoch'::timestamptz), created_by, created_at, COALESCE(revoked_at, 'epoch'::timestamptz)`,
		id, tenantID, sourceID, version, encrypted, actorID,
	).Scan(&item.ID, &item.TenantID, &item.SourceID, &item.Version, &item.State, &item.ActiveAt, &item.ExpiresAt, &item.CreatedBy, &item.CreatedAt, &item.RevokedAt)
	if err != nil {
		return domain.SourceSecretVersion{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE sources SET encrypted_secret=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, sourceID, encrypted); err != nil {
		return domain.SourceSecretVersion{}, err
	}
	if _, err := s.insertConfigVersion(ctx, tx, tenantID, domain.ConfigResourceSource, sourceID, version, map[string]any{
		"source_id":         sourceID,
		"secret_version_id": id,
		"secret_version":    version,
		"state":             item.State,
	}, actorID); err != nil {
		return domain.SourceSecretVersion{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "source_secret.rotated", Resource: "source", ResourceID: sourceID, Reason: req.Reason}); err != nil {
		return domain.SourceSecretVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.SourceSecretVersion{}, err
	}
	return normalizeSourceSecretVersion(item), nil
}

func (s *Store) RotateEndpointSecret(ctx context.Context, tenantID, endpointID, actorID string, req app.RotateEndpointSecretRequest) (domain.EndpointSecretVersion, error) {
	secret, err := random.Token("whsec_out", 32)
	if err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	encrypted, err := s.encryptSecret(ctx, tenantID, "endpoint_signing_secret", []byte(secret))
	if err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	defer rollback(ctx, tx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM endpoints WHERE tenant_id=$1 AND id=$2)`, tenantID, endpointID).Scan(&exists); err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	if !exists {
		return domain.EndpointSecretVersion{}, app.ErrNotFound
	}
	version, graceUntil, err := nextSecretVersion(ctx, tx, "endpoint_secrets", tenantID, endpointID, req.GracePeriodHours)
	if err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE endpoint_secrets
		SET state='previous', expires_at=$3
		WHERE tenant_id=$1 AND endpoint_id=$2 AND state='active'`,
		tenantID, endpointID, graceUntil,
	); err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	id := mustID("esec")
	var item domain.EndpointSecretVersion
	err = tx.QueryRow(ctx, `
		INSERT INTO endpoint_secrets(id, tenant_id, endpoint_id, encrypted_secret, algorithm, state, version, active_at, created_by)
		VALUES($1,$2,$3,$4,'hmac_sha256','active',$5,now(),$6)
		RETURNING id, tenant_id, endpoint_id, version, algorithm, state, active_at, COALESCE(expires_at, 'epoch'::timestamptz), created_by, created_at, COALESCE(revoked_at, 'epoch'::timestamptz)`,
		id, tenantID, endpointID, encrypted, version, actorID,
	).Scan(&item.ID, &item.TenantID, &item.EndpointID, &item.Version, &item.Algorithm, &item.State, &item.ActiveAt, &item.ExpiresAt, &item.CreatedBy, &item.CreatedAt, &item.RevokedAt)
	if err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	if _, err := s.insertConfigVersion(ctx, tx, tenantID, domain.ConfigResourceEndpoint, endpointID, version, map[string]any{
		"endpoint_id":       endpointID,
		"secret_version_id": id,
		"secret_version":    version,
		"algorithm":         item.Algorithm,
		"state":             item.State,
	}, actorID); err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "endpoint_secret.rotated", Resource: "endpoint", ResourceID: endpointID, Reason: req.Reason}); err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	return normalizeEndpointSecretVersion(item), nil
}

type rawPayloadStorage struct {
	backend string
	bucket  string
	key     string
}

func (s *Store) prepareRawPayloadStorage(ctx context.Context, tenantID, rawID string, raw domain.RawPayload) (rawPayloadStorage, []byte, error) {
	if s.rawStorageMode != domain.RawStorageS3 {
		return rawPayloadStorage{backend: domain.RawStoragePostgres}, raw.Body, nil
	}
	key := blobstore.RawPayloadKey(tenantID, rawID, raw.SHA256)
	object := blobstore.Object{
		Bucket:      s.objectBucket,
		Key:         key,
		ContentType: raw.ContentType,
		SHA256:      raw.SHA256,
		SizeBytes:   raw.SizeBytes,
	}
	if err := s.objectStore.Put(ctx, object, raw.Body); err != nil {
		return rawPayloadStorage{}, nil, storageOperationError{operation: "raw payload object write", err: err}
	}
	return rawPayloadStorage{backend: domain.RawStorageS3, bucket: s.objectBucket, key: key}, []byte{}, nil
}

type storageOperationError struct {
	operation string
	err       error
}

func (e storageOperationError) Error() string {
	return e.operation + " failed"
}

func (e storageOperationError) Unwrap() error {
	return e.err
}

func (s *Store) lookupAdapterVersionID(ctx context.Context, tx pgx.Tx, adapter string) (string, error) {
	adapter = strings.ToLower(strings.TrimSpace(adapter))
	if adapter == "" {
		return "", nil
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM adapter_versions WHERE name=$1 AND state='active' ORDER BY created_at DESC LIMIT 1`, adapter).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func (s *Store) activeTransformationVersionID(ctx context.Context, tx pgx.Tx, tenantID, transformationID string) (string, error) {
	var versionID string
	err := tx.QueryRow(ctx, `
		SELECT tv.id
		FROM transformations t
		JOIN transformation_versions tv ON tv.tenant_id=t.tenant_id AND tv.id=t.active_version_id
		WHERE t.tenant_id=$1 AND t.id=$2 AND t.state='active' AND tv.state='active'`,
		tenantID, transformationID,
	).Scan(&versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", app.ErrNotFound
	}
	return versionID, err
}

func (s *Store) requireActiveEndpoint(ctx context.Context, tx pgx.Tx, tenantID, endpointID string) error {
	var state string
	err := tx.QueryRow(ctx, `SELECT state FROM endpoints WHERE tenant_id=$1 AND id=$2`, tenantID, endpointID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return err
	}
	if state != domain.StateActive {
		return fmt.Errorf("%w: endpoint disabled", app.ErrInvalidInput)
	}
	return nil
}

func (s *Store) requireActiveSource(ctx context.Context, tx pgx.Tx, tenantID, sourceID string) error {
	var state string
	err := tx.QueryRow(ctx, `SELECT state FROM sources WHERE tenant_id=$1 AND id=$2`, tenantID, sourceID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return err
	}
	if state != domain.StateActive {
		return fmt.Errorf("%w: source disabled", app.ErrInvalidInput)
	}
	return nil
}

func (s *Store) ListEvents(ctx context.Context, tenantID string, limit int) ([]domain.Event, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, source_id, provider, type, provider_event_id, raw_payload_id, raw_payload_hash, signature_verified, verification_reason, dedupe_key, dedupe_status, received_at, trace_id FROM events WHERE tenant_id=$1 ORDER BY received_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Event
	for rows.Next() {
		item, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetEvent(ctx context.Context, tenantID, eventID string) (domain.Event, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, tenant_id, source_id, provider, type, provider_event_id, raw_payload_id, raw_payload_hash, signature_verified, verification_reason, dedupe_key, dedupe_status, received_at, trace_id FROM events WHERE tenant_id=$1 AND id=$2`, tenantID, eventID)
	item, err := scanEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Event{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) GetRawPayload(ctx context.Context, tenantID, eventID, actorID string) (domain.RawPayload, error) {
	var raw domain.RawPayload
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, event_id, sha256, content_type, size_bytes, body,
			storage_backend, object_bucket, object_key, storage_status,
			COALESCE(storage_deleted_at, 'epoch'::timestamptz), created_at
		FROM raw_payloads
		WHERE tenant_id=$1 AND event_id=$2
		ORDER BY created_at ASC
		LIMIT 1`, tenantID, eventID).
		Scan(&raw.ID, &raw.TenantID, &raw.EventID, &raw.SHA256, &raw.ContentType, &raw.SizeBytes, &raw.Body,
			&raw.StorageBackend, &raw.ObjectBucket, &raw.ObjectKey, &raw.StorageStatus, &raw.StorageDeletedAt, &raw.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RawPayload{}, app.ErrNotFound
	}
	if err != nil {
		return domain.RawPayload{}, err
	}
	if raw.StorageStatus == domain.StorageStatusDeleted {
		return domain.RawPayload{}, app.ErrGone
	}
	if raw.StorageBackend == domain.RawStorageS3 {
		if s.objectStore == nil {
			return domain.RawPayload{}, errors.New("object store is not configured")
		}
		body, err := s.objectStore.Get(ctx, raw.ObjectBucket, raw.ObjectKey)
		if err != nil {
			if errors.Is(err, blobstore.ErrNotFound) {
				return domain.RawPayload{}, app.ErrGone
			}
			return domain.RawPayload{}, errObjectStoreReadFailed
		}
		if domain.HashSHA256(body) != raw.SHA256 {
			return domain.RawPayload{}, errors.New("raw payload object hash mismatch")
		}
		raw.Body = body
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "raw_payload.read", Resource: "event", ResourceID: eventID})
	return raw, nil
}

func (s *Store) GetNormalizedEvent(ctx context.Context, tenantID, eventID, actorID string, includeData bool) (domain.NormalizedEnvelope, error) {
	var item domain.NormalizedEnvelope
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, event_id, adapter_version_id, provider, provider_event_id, type, source, subject,
			envelope_json, data_json, metadata_json, envelope_sha256, data_sha256, metadata_sha256,
			storage_status, COALESCE(storage_deleted_at, 'epoch'::timestamptz), created_at
		FROM normalized_envelopes
		WHERE tenant_id=$1 AND event_id=$2`,
		tenantID, eventID,
	).Scan(&item.ID, &item.TenantID, &item.EventID, &item.AdapterVersionID, &item.Provider, &item.ProviderEventID,
		&item.Type, &item.Source, &item.Subject, &item.Envelope, &item.Data, &item.Metadata, &item.EnvelopeSHA256,
		&item.DataSHA256, &item.MetadataSHA256, &item.StorageStatus, &item.StorageDeletedAt, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.NormalizedEnvelope{}, app.ErrNotFound
	}
	if err != nil {
		return domain.NormalizedEnvelope{}, err
	}
	if includeData {
		if item.StorageStatus == domain.StorageStatusDeleted {
			return domain.NormalizedEnvelope{}, app.ErrGone
		}
		_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "normalized_envelope.data_read", Resource: "event", ResourceID: eventID})
	} else {
		item.Data = nil
	}
	return item, nil
}

func (s *Store) ListEventTimeline(ctx context.Context, tenantID, eventID string, limit int) ([]app.EventTimelineEntry, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM events WHERE tenant_id=$1 AND id=$2)`, tenantID, eventID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, app.ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `
		SELECT 'webhookery.event_timeline.v1' AS schema_version, kind, ref_id, state, detail, occurred_at FROM (
			SELECT 'event' AS kind, id AS ref_id, dedupe_status AS state, verification_reason AS detail, received_at AS occurred_at
			FROM events WHERE tenant_id=$1 AND id=$2
			UNION ALL
			SELECT 'receipt' AS kind, id AS ref_id, CASE WHEN verification_ok THEN 'verified' ELSE 'rejected' END AS state, verification_reason AS detail, received_at AS occurred_at
			FROM provider_receipts WHERE tenant_id=$1 AND event_id=$2
			UNION ALL
			SELECT 'raw_payload' AS kind, rp.id AS ref_id, rp.storage_status AS state,
			       'sha256=' || rp.sha256 ||
			       ' size_bytes=' || rp.size_bytes::text ||
			       ' receipts=' || COALESCE(NULLIF(receipts.receipt_ids,''),'none') AS detail,
			       rp.created_at AS occurred_at
			FROM raw_payloads rp
			LEFT JOIN LATERAL (
				SELECT string_agg(pr.id, ',' ORDER BY pr.received_at ASC, pr.id ASC) AS receipt_ids
				FROM provider_receipts pr
				WHERE pr.tenant_id=rp.tenant_id AND pr.raw_payload_id=rp.id
			) receipts ON true
			WHERE rp.tenant_id=$1 AND rp.event_id=$2
			UNION ALL
			SELECT 'normalized' AS kind, id AS ref_id, storage_status AS state,
			       'adapter_version=' || COALESCE(NULLIF(adapter_version_id,''),'none') ||
			       ' envelope_sha256=' || envelope_sha256 ||
			       ' data_sha256=' || data_sha256 AS detail,
			       created_at AS occurred_at
			FROM normalized_envelopes WHERE tenant_id=$1 AND event_id=$2
			UNION ALL
			SELECT 'delivery' AS kind, id AS ref_id, state,
			       endpoint_id ||
			       ' route_version=' || COALESCE(NULLIF(route_version_id,''),'none') ||
			       ' subscription_version=' || COALESCE(NULLIF(subscription_version_id,''),'none') ||
			       ' retry_policy=' || COALESCE(NULLIF(retry_policy_id,''),'default') ||
			       ' adapter_version=' || COALESCE(NULLIF(adapter_version_id,''),'none') ||
			       ' normalized_envelope=' || COALESCE(NULLIF(normalized_envelope_id,''),'none') ||
			       ' transformation_version=' || COALESCE(NULLIF(transformation_version_id,''),'identity') ||
			       ' delivery_payload=' || COALESCE(NULLIF(delivery_payload_id,''),'none') ||
			       ' replay_job=' || COALESCE(NULLIF(replay_job_id,''),'none') AS detail,
			       created_at AS occurred_at
			FROM deliveries WHERE tenant_id=$1 AND event_id=$2
			UNION ALL
			SELECT 'delivery_payload' AS kind, id AS ref_id, storage_status AS state,
			       'delivery=' || delivery_id ||
			       ' transformation_version=' || COALESCE(NULLIF(transformation_version_id,''),'identity') ||
			       ' sha256=' || sha256 AS detail,
			       created_at AS occurred_at
			FROM delivery_payloads WHERE tenant_id=$1 AND event_id=$2
			UNION ALL
			SELECT 'attempt' AS kind, id AS ref_id, state,
			       failure_class ||
			       ' retryable=' || retryable::text ||
			       ' retry_delay_ms=' || retry_delay_ms::text AS detail,
			       COALESCE(completed_at, started_at) AS occurred_at
			FROM delivery_attempts WHERE tenant_id=$1 AND event_id=$2
			UNION ALL
			SELECT 'reconciliation' AS kind, id AS ref_id, outcome AS state,
			       'job=' || job_id ||
			       ' provider_object=' || provider_object_id ||
			       ' evidence=' || COALESCE(NULLIF(provider_api_evidence_id,''),'none') AS detail,
			       created_at AS occurred_at
			FROM reconciliation_items
			WHERE tenant_id=$1 AND (local_event_id=$2 OR recovered_event_id=$2)
			UNION ALL
			SELECT 'replay' AS kind, r.id AS ref_id, r.state,
			       'reason_code=' || COALESCE(NULLIF(r.reason_code,''),'operator_requested') ||
			       ' reason=' || r.reason ||
			       ' config_mode=' || COALESCE(NULLIF(r.config_mode,''),'current') ||
			       ' event_id=' || COALESCE(NULLIF(r.scope_json->>'event_id',''),'none') ||
			       ' delivery_id=' || COALESCE(NULLIF(r.scope_json->>'delivery_id',''),'none') ||
			       ' endpoint_id=' || COALESCE(NULLIF(r.scope_json->>'endpoint_id',''),'none') ||
			       ' approval_required=' || r.approval_required::text AS detail,
			       r.created_at AS occurred_at
			FROM replay_jobs r
			WHERE r.tenant_id=$1
			  AND (
				r.scope_json->>'event_id'=$2
				OR EXISTS (
					SELECT 1 FROM deliveries d
					WHERE d.tenant_id=r.tenant_id AND d.id=r.scope_json->>'delivery_id' AND d.event_id=$2
				)
				OR EXISTS (
					SELECT 1 FROM replay_items ri
					WHERE ri.tenant_id=r.tenant_id AND ri.replay_job_id=r.id AND ri.event_id=$2
				)
			  )
			UNION ALL
			SELECT 'audit' AS kind, id AS ref_id, action AS state, reason AS detail, occurred_at
			FROM audit_events WHERE tenant_id=$1 AND resource_id=$2
		) timeline
		ORDER BY occurred_at ASC
		LIMIT $3`, tenantID, eventID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.EventTimelineEntry
	sequence := 1
	for rows.Next() {
		var item app.EventTimelineEntry
		if err := rows.Scan(&item.SchemaVersion, &item.Kind, &item.RefID, &item.State, &item.Detail, &item.OccurredAt); err != nil {
			return nil, err
		}
		item.Sequence = sequence
		sequence++
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ListDeliveries(ctx context.Context, tenantID string, limit int) ([]domain.Delivery, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT d.id, d.tenant_id, d.event_id, d.endpoint_id, COALESCE(d.route_id,''), COALESCE(d.route_version_id,''), COALESCE(d.subscription_id,''), COALESCE(d.subscription_version_id,''), COALESCE(d.retry_policy_id,''), COALESCE(d.replay_job_id,''), COALESCE(d.adapter_version_id,''), COALESCE(d.normalized_envelope_id,''), COALESCE(d.transformation_version_id,''), COALESCE(d.delivery_payload_id,''), COALESCE(p.sha256,''), COALESCE(d.retry_seed,''), d.state, d.attempt_count, COALESCE(d.next_attempt_at, 'epoch'::timestamptz)
		FROM deliveries d
		LEFT JOIN delivery_payloads p ON p.tenant_id=d.tenant_id AND p.id=d.delivery_payload_id
		WHERE d.tenant_id=$1
		ORDER BY d.created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Delivery
	for rows.Next() {
		item, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ListDeliveryAttempts(ctx context.Context, tenantID, deliveryID string, limit int) ([]domain.DeliveryAttempt, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, delivery_id, event_id, endpoint_id, request_sha256, response_sha256, attempt_no, state, COALESCE(response_status, 0), response_body_truncated, failure_class, retryable, retry_delay_ms, COALESCE(next_retry_at, 'epoch'::timestamptz), started_at, COALESCE(completed_at, started_at) FROM delivery_attempts WHERE tenant_id=$1 AND delivery_id=$2 ORDER BY attempt_no DESC LIMIT $3`, tenantID, deliveryID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.DeliveryAttempt
	for rows.Next() {
		item, err := scanDeliveryAttempt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetDeliveryAttempt(ctx context.Context, tenantID, attemptID string) (domain.DeliveryAttempt, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, tenant_id, delivery_id, event_id, endpoint_id, request_sha256, response_sha256, attempt_no, state, COALESCE(response_status, 0), response_body_truncated, failure_class, retryable, retry_delay_ms, COALESCE(next_retry_at, 'epoch'::timestamptz), started_at, COALESCE(completed_at, started_at) FROM delivery_attempts WHERE tenant_id=$1 AND id=$2`, tenantID, attemptID)
	item, err := scanDeliveryAttempt(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.DeliveryAttempt{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) RetryDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.Delivery, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Delivery{}, err
	}
	defer rollback(ctx, tx)
	row := tx.QueryRow(ctx, `UPDATE deliveries SET state='scheduled', next_attempt_at=now(), locked_by=NULL, lock_expires_at=NULL WHERE tenant_id=$1 AND id=$2 RETURNING id, tenant_id, event_id, endpoint_id, COALESCE(route_id,''), COALESCE(route_version_id,''), COALESCE(subscription_id,''), COALESCE(subscription_version_id,''), COALESCE(retry_policy_id,''), COALESCE(replay_job_id,''), COALESCE(adapter_version_id,''), COALESCE(normalized_envelope_id,''), COALESCE(transformation_version_id,''), COALESCE(delivery_payload_id,''), COALESCE((SELECT p.sha256 FROM delivery_payloads p WHERE p.tenant_id=deliveries.tenant_id AND p.id=deliveries.delivery_payload_id), ''), COALESCE(retry_seed,''), state, attempt_count, COALESCE(next_attempt_at, 'epoch'::timestamptz)`, tenantID, deliveryID)
	item, err := scanDelivery(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Delivery{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Delivery{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "delivery.retry_requested", Resource: "delivery", ResourceID: deliveryID, Reason: reason}); err != nil {
		return domain.Delivery{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Delivery{}, err
	}
	return item, nil
}

func (s *Store) CancelDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.Delivery, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Delivery{}, err
	}
	defer rollback(ctx, tx)
	row := tx.QueryRow(ctx, `UPDATE deliveries SET state='canceled', locked_by=NULL, lock_expires_at=NULL WHERE tenant_id=$1 AND id=$2 AND state NOT IN ('succeeded','dead_lettered','canceled') RETURNING id, tenant_id, event_id, endpoint_id, COALESCE(route_id,''), COALESCE(route_version_id,''), COALESCE(subscription_id,''), COALESCE(subscription_version_id,''), COALESCE(retry_policy_id,''), COALESCE(replay_job_id,''), COALESCE(adapter_version_id,''), COALESCE(normalized_envelope_id,''), COALESCE(transformation_version_id,''), COALESCE(delivery_payload_id,''), COALESCE((SELECT p.sha256 FROM delivery_payloads p WHERE p.tenant_id=deliveries.tenant_id AND p.id=deliveries.delivery_payload_id), ''), COALESCE(retry_seed,''), state, attempt_count, COALESCE(next_attempt_at, 'epoch'::timestamptz)`, tenantID, deliveryID)
	item, err := scanDelivery(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Delivery{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Delivery{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "delivery.canceled", Resource: "delivery", ResourceID: deliveryID, Reason: reason}); err != nil {
		return domain.Delivery{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Delivery{}, err
	}
	return item, nil
}

func (s *Store) ListEndpointHealth(ctx context.Context, tenantID string, limit int) ([]domain.EndpointHealth, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT e.id, e.tenant_id, e.url, e.state, e.circuit_state, e.failure_count, COALESCE(e.disabled_until, 'epoch'::timestamptz),
		       COALESCE(max(a.completed_at), 'epoch'::timestamptz),
		       COALESCE((array_agg(a.response_status ORDER BY a.completed_at DESC))[1], 0),
		       COALESCE((array_agg(a.failure_class ORDER BY a.completed_at DESC))[1], ''),
		       COUNT(*) FILTER (WHERE a.state='succeeded' AND a.completed_at >= now() - interval '24 hours'),
		       COUNT(*) FILTER (WHERE a.state='failed' AND a.completed_at >= now() - interval '24 hours')
		FROM endpoints e
		LEFT JOIN delivery_attempts a ON a.tenant_id=e.tenant_id AND a.endpoint_id=e.id
		WHERE e.tenant_id=$1
		GROUP BY e.id, e.tenant_id, e.url, e.state, e.circuit_state, e.failure_count, e.disabled_until
		ORDER BY e.created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.EndpointHealth
	for rows.Next() {
		var item domain.EndpointHealth
		if err := rows.Scan(&item.EndpointID, &item.TenantID, &item.URL, &item.State, &item.CircuitState, &item.FailureCount, &item.DisabledUntil, &item.LastAttemptAt, &item.LastStatus, &item.LastFailure, &item.Successes24h, &item.Failures24h); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) OpsMetrics(ctx context.Context, tenantID string) (domain.OpsMetrics, error) {
	metrics := domain.OpsMetrics{
		DeliveriesByState:            map[string]int64{},
		ReplayJobsByState:            map[string]int64{},
		ReconciliationJobsByState:    map[string]int64{},
		ReconciliationItemsByOutcome: map[string]int64{},
	}
	predicate, args := tenantPredicate(tenantID)
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM events"+predicate, args...).Scan(&metrics.EventsTotal); err != nil {
		return metrics, err
	}
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE state='pending'"+tenantAnd(tenantID), args...).Scan(&metrics.OutboxPending); err != nil {
		return metrics, err
	}
	var oldestAge float64
	if err := s.pool.QueryRow(ctx, "SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(available_at)),0) FROM outbox WHERE state='pending'"+tenantAnd(tenantID), args...).Scan(&oldestAge); err != nil {
		return metrics, err
	}
	metrics.OldestOutboxAgeSec = int64(oldestAge)
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM dead_letter_entries WHERE state='open'"+tenantAnd(tenantID), args...).Scan(&metrics.DeadLetterOpen); err != nil {
		return metrics, err
	}
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM quarantine_entries WHERE state='open'"+tenantAnd(tenantID), args...).Scan(&metrics.QuarantineOpen); err != nil {
		return metrics, err
	}
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM endpoints WHERE circuit_state='open'"+tenantAnd(tenantID), args...).Scan(&metrics.EndpointCircuitOpen); err != nil {
		return metrics, err
	}
	if tenantID == "" {
		if err := s.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM audit_events a
			WHERE NOT EXISTS (
				SELECT 1 FROM audit_chain_entries c
				WHERE c.tenant_id=a.tenant_id AND c.audit_event_id=a.id
			)`).Scan(&metrics.AuditChainUnchainedEvents); err != nil {
			return metrics, err
		}
		if err := s.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM audit_chain_entries c
			LEFT JOIN audit_events a ON a.tenant_id=c.tenant_id AND a.id=c.audit_event_id
			WHERE c.state<>$1 AND a.id IS NULL`, domain.AuditChainEntryStateRetained).
			Scan(&metrics.AuditChainVerificationFailures); err != nil {
			return metrics, err
		}
		if err := s.pool.QueryRow(ctx, `
			SELECT COALESCE(EXTRACT(EPOCH FROM now() - max(created_at)),0)
			FROM audit_chain_anchors`).Scan(&oldestAge); err != nil {
			return metrics, err
		}
	} else {
		if err := s.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM audit_events a
			WHERE a.tenant_id=$1
			  AND NOT EXISTS (
				SELECT 1 FROM audit_chain_entries c
				WHERE c.tenant_id=a.tenant_id AND c.audit_event_id=a.id
			  )`, tenantID).Scan(&metrics.AuditChainUnchainedEvents); err != nil {
			return metrics, err
		}
		if err := s.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM audit_chain_entries c
			LEFT JOIN audit_events a ON a.tenant_id=c.tenant_id AND a.id=c.audit_event_id
			WHERE c.tenant_id=$1 AND c.state<>$2 AND a.id IS NULL`, tenantID, domain.AuditChainEntryStateRetained).
			Scan(&metrics.AuditChainVerificationFailures); err != nil {
			return metrics, err
		}
		if err := s.pool.QueryRow(ctx, `
			SELECT COALESCE(EXTRACT(EPOCH FROM now() - max(created_at)),0)
			FROM audit_chain_anchors
			WHERE tenant_id=$1`, tenantID).Scan(&oldestAge); err != nil {
			return metrics, err
		}
	}
	metrics.AuditChainLastAnchorAgeSec = int64(oldestAge)
	if err := scanCounts(ctx, s.pool, "SELECT state, count(*) FROM deliveries"+predicate+" GROUP BY state", args, metrics.DeliveriesByState); err != nil {
		return metrics, err
	}
	if err := scanCounts(ctx, s.pool, "SELECT state, count(*) FROM replay_jobs"+predicate+" GROUP BY state", args, metrics.ReplayJobsByState); err != nil {
		return metrics, err
	}
	if err := scanCounts(ctx, s.pool, "SELECT state, count(*) FROM reconciliation_jobs"+predicate+" GROUP BY state", args, metrics.ReconciliationJobsByState); err != nil {
		return metrics, err
	}
	if err := scanCounts(ctx, s.pool, "SELECT outcome, count(*) FROM reconciliation_items"+predicate+" GROUP BY outcome", args, metrics.ReconciliationItemsByOutcome); err != nil {
		return metrics, err
	}
	return metrics, nil
}

func (s *Store) ListWorkers(ctx context.Context, tenantID string, limit int) ([]domain.WorkerStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT worker_id,
		       CASE WHEN expires_at > now() THEN 'active' ELSE 'expired' END AS state,
		       updated_at,
		       expires_at
		FROM worker_leases
		ORDER BY updated_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.WorkerStatus
	for rows.Next() {
		item, err := scanWorkerStatus(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetWorker(ctx context.Context, tenantID, workerID string) (domain.WorkerStatus, error) {
	item, err := scanWorkerStatus(s.pool.QueryRow(ctx, `
		SELECT worker_id,
		       CASE WHEN expires_at > now() THEN 'active' ELSE 'expired' END AS state,
		       updated_at,
		       expires_at
		FROM worker_leases
		WHERE worker_id=$1`, workerID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.WorkerStatus{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) ListQueues(ctx context.Context, tenantID string) ([]domain.QueueStats, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT kind,
		       count(*) FILTER (WHERE state='pending')::bigint,
		       count(*) FILTER (WHERE state='in_progress')::bigint,
		       count(*) FILTER (WHERE state='completed')::bigint,
		       0::bigint,
		       count(*) FILTER (WHERE state='pending' AND available_at <= now())::bigint,
		       COALESCE(EXTRACT(EPOCH FROM now() - min(available_at) FILTER (WHERE state='pending')),0),
		       COALESCE(min(available_at) FILTER (WHERE state='pending' AND available_at > now()), 'epoch'::timestamptz)
		FROM outbox
		WHERE tenant_id=$1
		GROUP BY kind
		ORDER BY kind`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.QueueStats{}
	for rows.Next() {
		item, err := scanQueueStats(rows, tenantID)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	item, err := scanQueueStats(s.pool.QueryRow(ctx, `
		SELECT 'deliveries',
		       count(*) FILTER (WHERE state='scheduled')::bigint,
		       count(*) FILTER (WHERE state='in_progress')::bigint,
		       0::bigint,
		       count(*) FILTER (WHERE state IN ('succeeded','dead_lettered','canceled'))::bigint,
		       count(*) FILTER (WHERE state='scheduled' AND COALESCE(next_attempt_at, now()) <= now())::bigint,
		       COALESCE(EXTRACT(EPOCH FROM now() - min(next_attempt_at) FILTER (WHERE state='scheduled')),0),
		       COALESCE(min(next_attempt_at) FILTER (WHERE state='scheduled' AND next_attempt_at > now()), 'epoch'::timestamptz)
		FROM deliveries
		WHERE tenant_id=$1`, tenantID), tenantID)
	if err != nil {
		return nil, err
	}
	out = append(out, item)
	return out, nil
}

func (s *Store) OpsStorage(ctx context.Context, tenantID string) (domain.OpsStorageStatus, error) {
	predicate, args := tenantPredicate(tenantID)
	status := domain.OpsStorageStatus{
		TenantID:                    tenantID,
		RawStorageMode:              s.rawStorageMode,
		ObjectStorageConfigured:     s.objectStore != nil && strings.TrimSpace(s.objectBucket) != "",
		RawPayloadsByStatus:         map[string]int64{},
		RawPayloadsByBackend:        map[string]int64{},
		NormalizedEnvelopesByStatus: map[string]int64{},
		DeliveryPayloadsByStatus:    map[string]int64{},
		ProviderAPIEvidenceByStatus: map[string]int64{},
		EvidenceExportsByState:      map[string]int64{},
		EvidenceExportsByBackend:    map[string]int64{},
	}
	if err := scanCounts(ctx, s.pool, "SELECT storage_status, count(*) FROM raw_payloads"+predicate+" GROUP BY storage_status", args, status.RawPayloadsByStatus); err != nil {
		return status, err
	}
	if err := scanCounts(ctx, s.pool, "SELECT storage_backend, count(*) FROM raw_payloads"+predicate+" GROUP BY storage_backend", args, status.RawPayloadsByBackend); err != nil {
		return status, err
	}
	if err := s.pool.QueryRow(ctx, "SELECT COALESCE(sum(size_bytes) FILTER (WHERE storage_status='stored'),0) FROM raw_payloads"+predicate, args...).Scan(&status.RawPayloadStoredBytes); err != nil {
		return status, err
	}
	if err := scanCounts(ctx, s.pool, "SELECT storage_status, count(*) FROM normalized_envelopes"+predicate+" GROUP BY storage_status", args, status.NormalizedEnvelopesByStatus); err != nil {
		return status, err
	}
	if err := scanCounts(ctx, s.pool, "SELECT storage_status, count(*) FROM delivery_payloads"+predicate+" GROUP BY storage_status", args, status.DeliveryPayloadsByStatus); err != nil {
		return status, err
	}
	if err := scanCounts(ctx, s.pool, "SELECT storage_status, count(*) FROM provider_api_evidence"+predicate+" GROUP BY storage_status", args, status.ProviderAPIEvidenceByStatus); err != nil {
		return status, err
	}
	if err := scanCounts(ctx, s.pool, "SELECT state, count(*) FROM evidence_exports"+predicate+" GROUP BY state", args, status.EvidenceExportsByState); err != nil {
		return status, err
	}
	if err := scanCounts(ctx, s.pool, "SELECT storage_backend, count(*) FROM evidence_exports"+predicate+" GROUP BY storage_backend", args, status.EvidenceExportsByBackend); err != nil {
		return status, err
	}
	return status, nil
}

func (s *Store) ListMetricRollups(ctx context.Context, tenantID, metricName string, limit int) ([]domain.MetricRollup, error) {
	query := `
		SELECT id, tenant_id, metric_name, bucket_start, bucket_seconds, dimensions, dimensions_hash, value, source, created_at, updated_at
		FROM metrics_rollups
		WHERE tenant_id=$1`
	args := []any{tenantID}
	if strings.TrimSpace(metricName) != "" {
		query += " AND metric_name=$2"
		args = append(args, strings.TrimSpace(metricName))
	}
	query += " ORDER BY bucket_start DESC, metric_name ASC LIMIT $" + strconv.Itoa(len(args)+1)
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.MetricRollup
	for rows.Next() {
		item, err := scanMetricRollup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateAlertRule(ctx context.Context, tenantID, actorID string, req app.CreateAlertRuleRequest) (domain.AlertRule, error) {
	id := mustID("alr")
	dimensions, err := json.Marshal(req.Dimensions)
	if err != nil {
		return domain.AlertRule{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AlertRule{}, err
	}
	defer rollback(ctx, tx)
	if err := s.requireActiveNotificationChannels(ctx, tx, tenantID, req.ChannelIDs); err != nil {
		return domain.AlertRule{}, err
	}
	item, err := scanAlertRule(tx.QueryRow(ctx, `
		INSERT INTO alert_rules(id, tenant_id, name, rule_type, metric_name, threshold, comparator, window_seconds, dimensions, state, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id, tenant_id, name, rule_type, metric_name, threshold, comparator, window_seconds, dimensions, state, created_by, created_at, updated_at`,
		id, tenantID, req.Name, req.RuleType, req.MetricName, req.Threshold, req.Comparator, req.WindowSeconds, dimensions, req.State, actorID))
	if err != nil {
		return domain.AlertRule{}, err
	}
	if err := s.setAlertRuleChannelsTx(ctx, tx, tenantID, item.ID, req.ChannelIDs); err != nil {
		return domain.AlertRule{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "alert_rule.created", Resource: "alert_rule", ResourceID: item.ID, Reason: item.Name}); err != nil {
		return domain.AlertRule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.AlertRule{}, err
	}
	item.ChannelIDs = req.ChannelIDs
	return item, nil
}

func (s *Store) ListAlertRules(ctx context.Context, tenantID string, limit int) ([]domain.AlertRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, rule_type, metric_name, threshold, comparator, window_seconds, dimensions, state, created_by, created_at, updated_at
		FROM alert_rules
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AlertRule
	for rows.Next() {
		item, err := scanAlertRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return s.attachAlertRuleChannels(ctx, tenantID, out)
}

func (s *Store) GetAlertRule(ctx context.Context, tenantID, alertID string) (domain.AlertRule, error) {
	item, err := scanAlertRule(s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, rule_type, metric_name, threshold, comparator, window_seconds, dimensions, state, created_by, created_at, updated_at
		FROM alert_rules
		WHERE tenant_id=$1 AND id=$2`, tenantID, alertID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AlertRule{}, app.ErrNotFound
	}
	if err != nil {
		return domain.AlertRule{}, err
	}
	item.ChannelIDs, err = s.listAlertRuleChannelIDs(ctx, tenantID, alertID)
	return item, err
}

func (s *Store) UpdateAlertRule(ctx context.Context, tenantID, alertID, actorID string, req app.UpdateAlertRuleRequest) (domain.AlertRule, error) {
	current, err := s.GetAlertRule(ctx, tenantID, alertID)
	if err != nil {
		return domain.AlertRule{}, err
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.Threshold != nil {
		current.Threshold = *req.Threshold
	}
	if req.Comparator != nil {
		current.Comparator = *req.Comparator
	}
	if req.WindowSeconds != nil {
		current.WindowSeconds = *req.WindowSeconds
	}
	if req.Dimensions != nil {
		current.Dimensions = req.Dimensions
	}
	if req.State != nil {
		current.State = *req.State
	}
	dimensions, err := json.Marshal(current.Dimensions)
	if err != nil {
		return domain.AlertRule{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AlertRule{}, err
	}
	defer rollback(ctx, tx)
	if req.ChannelIDs != nil {
		if err := s.requireActiveNotificationChannels(ctx, tx, tenantID, *req.ChannelIDs); err != nil {
			return domain.AlertRule{}, err
		}
	}
	item, err := scanAlertRule(tx.QueryRow(ctx, `
		UPDATE alert_rules
		SET name=$3, threshold=$4, comparator=$5, window_seconds=$6, dimensions=$7, state=$8, updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, rule_type, metric_name, threshold, comparator, window_seconds, dimensions, state, created_by, created_at, updated_at`,
		tenantID, alertID, current.Name, current.Threshold, current.Comparator, current.WindowSeconds, dimensions, current.State))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AlertRule{}, app.ErrNotFound
	}
	if err != nil {
		return domain.AlertRule{}, err
	}
	if req.ChannelIDs != nil {
		if err := s.setAlertRuleChannelsTx(ctx, tx, tenantID, alertID, *req.ChannelIDs); err != nil {
			return domain.AlertRule{}, err
		}
		item.ChannelIDs = *req.ChannelIDs
	} else {
		item.ChannelIDs = current.ChannelIDs
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "alert_rule.updated", Resource: "alert_rule", ResourceID: alertID, Reason: req.Reason}); err != nil {
		return domain.AlertRule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.AlertRule{}, err
	}
	return item, nil
}

func (s *Store) DeleteAlertRule(ctx context.Context, tenantID, alertID, actorID, reason string) (domain.AlertRule, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AlertRule{}, err
	}
	defer rollback(ctx, tx)
	item, err := scanAlertRule(tx.QueryRow(ctx, `
		UPDATE alert_rules
		SET state='disabled', updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, rule_type, metric_name, threshold, comparator, window_seconds, dimensions, state, created_by, created_at, updated_at`,
		tenantID, alertID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AlertRule{}, app.ErrNotFound
	}
	if err != nil {
		return domain.AlertRule{}, err
	}
	if item.ChannelIDs, err = s.listAlertRuleChannelIDsTx(ctx, tx, tenantID, alertID); err != nil {
		return domain.AlertRule{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "alert_rule.disabled", Resource: "alert_rule", ResourceID: alertID, Reason: reason}); err != nil {
		return domain.AlertRule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.AlertRule{}, err
	}
	return item, nil
}

func (s *Store) ListAlertFirings(ctx context.Context, tenantID, state string, limit int) ([]domain.AlertFiring, error) {
	query := `
		SELECT id, tenant_id, rule_id, state, observed_value, threshold, reason, started_at, last_evaluated_at,
		       acknowledged_by, COALESCE(acknowledged_at, 'epoch'::timestamptz), COALESCE(resolved_at, 'epoch'::timestamptz), updated_at
		FROM alert_firings
		WHERE tenant_id=$1`
	args := []any{tenantID}
	if strings.TrimSpace(state) != "" {
		query += " AND state=$2"
		args = append(args, strings.TrimSpace(state))
	}
	query += " ORDER BY started_at DESC LIMIT $" + strconv.Itoa(len(args)+1)
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AlertFiring
	for rows.Next() {
		item, err := scanAlertFiring(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, normalizeAlertFiring(item))
	}
	return out, rows.Err()
}

func (s *Store) GetAlertFiring(ctx context.Context, tenantID, firingID string) (domain.AlertFiring, error) {
	item, err := scanAlertFiring(s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, rule_id, state, observed_value, threshold, reason, started_at, last_evaluated_at,
		       acknowledged_by, COALESCE(acknowledged_at, 'epoch'::timestamptz), COALESCE(resolved_at, 'epoch'::timestamptz), updated_at
		FROM alert_firings
		WHERE tenant_id=$1 AND id=$2`, tenantID, firingID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AlertFiring{}, app.ErrNotFound
	}
	return normalizeAlertFiring(item), err
}

func (s *Store) AcknowledgeAlertFiring(ctx context.Context, tenantID, firingID, actorID, reason string) (domain.AlertFiring, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AlertFiring{}, err
	}
	defer rollback(ctx, tx)
	item, err := scanAlertFiring(tx.QueryRow(ctx, `
		UPDATE alert_firings
		SET state='acknowledged', acknowledged_by=$3, acknowledged_at=now(), reason=$4, updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND state='open'
		RETURNING id, tenant_id, rule_id, state, observed_value, threshold, reason, started_at, last_evaluated_at,
		       acknowledged_by, COALESCE(acknowledged_at, 'epoch'::timestamptz), COALESCE(resolved_at, 'epoch'::timestamptz), updated_at`,
		tenantID, firingID, actorID, reason))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AlertFiring{}, app.ErrNotFound
	}
	if err != nil {
		return domain.AlertFiring{}, err
	}
	item = normalizeAlertFiring(item)
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "alert_firing.acknowledged", Resource: "alert_firing", ResourceID: firingID, Reason: reason}); err != nil {
		return domain.AlertFiring{}, err
	}
	if err := s.enqueueNotificationDeliveriesTx(ctx, tx, item, domain.AlertFiringAcknowledged, reason); err != nil {
		return domain.AlertFiring{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.AlertFiring{}, err
	}
	return item, nil
}

func (s *Store) CreateNotificationChannel(ctx context.Context, tenantID, actorID string, req app.CreateNotificationChannelRequest) (domain.NotificationChannel, error) {
	encrypted, err := s.encryptSecret(ctx, tenantID, "notification_channel_signing_secret", []byte(req.SigningSecret))
	if err != nil {
		return domain.NotificationChannel{}, err
	}
	item, err := scanNotificationChannel(s.pool.QueryRow(ctx, `
		INSERT INTO notification_channels(id, tenant_id, name, channel_type, url, state, encrypted_secret, secret_hint, created_by)
		VALUES($1,$2,$3,$4,$5,'active',$6,'configured',$7)
		RETURNING id, tenant_id, name, channel_type, url, state, secret_hint, created_by, created_at, updated_at`,
		mustID("nch"), tenantID, req.Name, req.ChannelType, req.URL, encrypted, actorID))
	if err != nil {
		return domain.NotificationChannel{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "notification_channel.created", Resource: "notification_channel", ResourceID: item.ID, Reason: item.Name})
	return item, nil
}

func (s *Store) ListNotificationChannels(ctx context.Context, tenantID string, limit int) ([]domain.NotificationChannel, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, channel_type, url, state, secret_hint, created_by, created_at, updated_at
		FROM notification_channels
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.NotificationChannel
	for rows.Next() {
		item, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetNotificationChannel(ctx context.Context, tenantID, channelID string) (domain.NotificationChannel, error) {
	item, err := scanNotificationChannel(s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, channel_type, url, state, secret_hint, created_by, created_at, updated_at
		FROM notification_channels
		WHERE tenant_id=$1 AND id=$2`, tenantID, channelID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.NotificationChannel{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateNotificationChannel(ctx context.Context, tenantID, channelID, actorID string, req app.UpdateNotificationChannelRequest) (domain.NotificationChannel, error) {
	current, err := s.GetNotificationChannel(ctx, tenantID, channelID)
	if err != nil {
		return domain.NotificationChannel{}, err
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.URL != nil {
		current.URL = *req.URL
	}
	if req.State != nil {
		current.State = *req.State
	}
	var encrypted []byte
	updateSecret := req.SigningSecret != nil
	if updateSecret {
		encrypted, err = s.encryptSecret(ctx, tenantID, "notification_channel_signing_secret", []byte(*req.SigningSecret))
		if err != nil {
			return domain.NotificationChannel{}, err
		}
	}
	query := `
		UPDATE notification_channels
		SET name=$3, url=$4, state=$5, updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, channel_type, url, state, secret_hint, created_by, created_at, updated_at`
	args := []any{tenantID, channelID, current.Name, current.URL, current.State}
	if updateSecret {
		query = `
			UPDATE notification_channels
			SET name=$3, url=$4, state=$5, encrypted_secret=$6, secret_hint='configured', updated_at=now()
			WHERE tenant_id=$1 AND id=$2
			RETURNING id, tenant_id, name, channel_type, url, state, secret_hint, created_by, created_at, updated_at`
		args = append(args, encrypted)
	}
	item, err := scanNotificationChannel(s.pool.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.NotificationChannel{}, app.ErrNotFound
	}
	if err != nil {
		return domain.NotificationChannel{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "notification_channel.updated", Resource: "notification_channel", ResourceID: channelID, Reason: req.Reason})
	return item, nil
}

func (s *Store) DeleteNotificationChannel(ctx context.Context, tenantID, channelID, actorID, reason string) (domain.NotificationChannel, error) {
	item, err := scanNotificationChannel(s.pool.QueryRow(ctx, `
		UPDATE notification_channels
		SET state='disabled', updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, channel_type, url, state, secret_hint, created_by, created_at, updated_at`, tenantID, channelID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.NotificationChannel{}, app.ErrNotFound
	}
	if err != nil {
		return domain.NotificationChannel{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "notification_channel.disabled", Resource: "notification_channel", ResourceID: channelID, Reason: reason})
	return item, nil
}

func (s *Store) TestNotificationChannel(ctx context.Context, tenantID, channelID, actorID, reason string) (domain.NotificationDelivery, error) {
	channel, err := s.GetNotificationChannel(ctx, tenantID, channelID)
	if err != nil {
		return domain.NotificationDelivery{}, err
	}
	if channel.State != domain.StateActive {
		return domain.NotificationDelivery{}, fmt.Errorf("%w: notification channel disabled", app.ErrInvalidInput)
	}
	payload := map[string]any{
		"type":       "notification_channel.test",
		"tenant_id":  tenantID,
		"channel_id": channelID,
		"reason":     reason,
		"created_at": time.Now().UTC(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return domain.NotificationDelivery{}, err
	}
	item, err := s.insertNotificationDelivery(ctx, tenantID, channelID, "", "test", body)
	if err != nil {
		return domain.NotificationDelivery{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "notification_channel.test_requested", Resource: "notification_channel", ResourceID: channelID, Reason: reason})
	return item, nil
}

func (s *Store) ListNotificationDeliveries(ctx context.Context, tenantID, state string, limit int) ([]domain.NotificationDelivery, error) {
	query := `
		SELECT id, tenant_id, channel_id, firing_id, transition, state, body_sha256, attempt_count,
		       next_attempt_at, COALESCE(last_attempt_at, 'epoch'::timestamptz), created_at, updated_at
		FROM notification_deliveries
		WHERE tenant_id=$1`
	args := []any{tenantID}
	if strings.TrimSpace(state) != "" {
		query += " AND state=$2"
		args = append(args, strings.TrimSpace(state))
	}
	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(len(args)+1)
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.NotificationDelivery
	for rows.Next() {
		item, err := scanNotificationDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, normalizeNotificationDelivery(item))
	}
	return out, rows.Err()
}

func (s *Store) ListNotificationDeliveryAttempts(ctx context.Context, tenantID, deliveryID string, limit int) ([]domain.NotificationDeliveryAttempt, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, delivery_id, status_code, failure_class, response_body, response_truncated, error, created_at
		FROM notification_delivery_attempts
		WHERE tenant_id=$1 AND delivery_id=$2
		ORDER BY created_at DESC
		LIMIT $3`, tenantID, deliveryID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.NotificationDeliveryAttempt
	for rows.Next() {
		item, err := scanNotificationDeliveryAttempt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) RetryNotificationDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.NotificationDelivery, error) {
	item, err := scanNotificationDelivery(s.pool.QueryRow(ctx, `
		UPDATE notification_deliveries
		SET state='scheduled', next_attempt_at=now(), worker_id='', updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND state <> 'succeeded'
		RETURNING id, tenant_id, channel_id, firing_id, transition, state, body_sha256, attempt_count,
		          next_attempt_at, COALESCE(last_attempt_at, 'epoch'::timestamptz), created_at, updated_at`,
		tenantID, deliveryID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.NotificationDelivery{}, app.ErrNotFound
	}
	if err != nil {
		return domain.NotificationDelivery{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "notification_delivery.retry_requested", Resource: "notification_delivery", ResourceID: deliveryID, Reason: reason})
	return normalizeNotificationDelivery(item), nil
}

func (s *Store) CreateSIEMSink(ctx context.Context, tenantID, actorID string, req app.CreateSIEMSinkRequest) (domain.SIEMSink, error) {
	encrypted, err := s.encryptSecret(ctx, tenantID, "siem_sink_signing_secret", []byte(req.SigningSecret))
	if err != nil {
		return domain.SIEMSink{}, err
	}
	item, err := scanSIEMSink(s.pool.QueryRow(ctx, `
		INSERT INTO siem_sinks(id, tenant_id, name, sink_type, url, state, encrypted_secret, secret_hint, created_by)
		VALUES($1,$2,$3,$4,$5,'active',$6,'configured',$7)
		RETURNING id, tenant_id, name, sink_type, url, state, secret_hint, cursor_sequence, created_by, created_at, updated_at`,
		mustID("snk"), tenantID, req.Name, req.SinkType, req.URL, encrypted, actorID))
	if err != nil {
		return domain.SIEMSink{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "siem_sink.created", Resource: "siem_sink", ResourceID: item.ID, Reason: item.Name})
	return item, nil
}

func (s *Store) ListSIEMSinks(ctx context.Context, tenantID string, limit int) ([]domain.SIEMSink, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, sink_type, url, state, secret_hint, cursor_sequence, created_by, created_at, updated_at
		FROM siem_sinks
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.SIEMSink
	for rows.Next() {
		item, err := scanSIEMSink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetSIEMSink(ctx context.Context, tenantID, sinkID string) (domain.SIEMSink, error) {
	item, err := scanSIEMSink(s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, sink_type, url, state, secret_hint, cursor_sequence, created_by, created_at, updated_at
		FROM siem_sinks
		WHERE tenant_id=$1 AND id=$2`, tenantID, sinkID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.SIEMSink{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) UpdateSIEMSink(ctx context.Context, tenantID, sinkID, actorID string, req app.UpdateSIEMSinkRequest) (domain.SIEMSink, error) {
	current, err := s.GetSIEMSink(ctx, tenantID, sinkID)
	if err != nil {
		return domain.SIEMSink{}, err
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.URL != nil {
		current.URL = *req.URL
	}
	if req.State != nil {
		current.State = *req.State
	}
	var encrypted []byte
	updateSecret := req.SigningSecret != nil
	if updateSecret {
		encrypted, err = s.encryptSecret(ctx, tenantID, "siem_sink_signing_secret", []byte(*req.SigningSecret))
		if err != nil {
			return domain.SIEMSink{}, err
		}
	}
	query := `
		UPDATE siem_sinks
		SET name=$3, url=$4, state=$5, updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, sink_type, url, state, secret_hint, cursor_sequence, created_by, created_at, updated_at`
	args := []any{tenantID, sinkID, current.Name, current.URL, current.State}
	if updateSecret {
		query = `
			UPDATE siem_sinks
			SET name=$3, url=$4, state=$5, encrypted_secret=$6, secret_hint='configured', updated_at=now()
			WHERE tenant_id=$1 AND id=$2
			RETURNING id, tenant_id, name, sink_type, url, state, secret_hint, cursor_sequence, created_by, created_at, updated_at`
		args = append(args, encrypted)
	}
	item, err := scanSIEMSink(s.pool.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.SIEMSink{}, app.ErrNotFound
	}
	if err != nil {
		return domain.SIEMSink{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "siem_sink.updated", Resource: "siem_sink", ResourceID: sinkID, Reason: req.Reason})
	return item, nil
}

func (s *Store) DeleteSIEMSink(ctx context.Context, tenantID, sinkID, actorID, reason string) (domain.SIEMSink, error) {
	item, err := scanSIEMSink(s.pool.QueryRow(ctx, `
		UPDATE siem_sinks
		SET state='disabled', updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, name, sink_type, url, state, secret_hint, cursor_sequence, created_by, created_at, updated_at`, tenantID, sinkID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.SIEMSink{}, app.ErrNotFound
	}
	if err != nil {
		return domain.SIEMSink{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "siem_sink.disabled", Resource: "siem_sink", ResourceID: sinkID, Reason: reason})
	return item, nil
}

func (s *Store) TestSIEMSink(ctx context.Context, tenantID, sinkID, actorID, reason string) (domain.SIEMDelivery, error) {
	sink, err := s.GetSIEMSink(ctx, tenantID, sinkID)
	if err != nil {
		return domain.SIEMDelivery{}, err
	}
	if sink.State != domain.StateActive {
		return domain.SIEMDelivery{}, fmt.Errorf("%w: SIEM sink disabled", app.ErrInvalidInput)
	}
	body, err := json.Marshal(map[string]any{
		"type":       "siem_sink.test",
		"tenant_id":  tenantID,
		"sink_id":    sinkID,
		"reason":     reason,
		"created_at": time.Now().UTC(),
	})
	if err != nil {
		return domain.SIEMDelivery{}, err
	}
	item, err := s.insertSIEMDelivery(ctx, tenantID, sinkID, 0, 0, body)
	if err != nil {
		return domain.SIEMDelivery{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "siem_sink.test_requested", Resource: "siem_sink", ResourceID: sinkID, Reason: reason})
	return item, nil
}

func (s *Store) ListSIEMDeliveries(ctx context.Context, tenantID, state string, limit int) ([]domain.SIEMDelivery, error) {
	query := `
		SELECT id, tenant_id, sink_id, from_sequence, to_sequence, state, body_sha256, attempt_count,
		       next_attempt_at, COALESCE(last_attempt_at, 'epoch'::timestamptz), created_at, updated_at
		FROM siem_deliveries
		WHERE tenant_id=$1`
	args := []any{tenantID}
	if strings.TrimSpace(state) != "" {
		query += " AND state=$2"
		args = append(args, strings.TrimSpace(state))
	}
	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(len(args)+1)
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.SIEMDelivery
	for rows.Next() {
		item, err := scanSIEMDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, normalizeSIEMDelivery(item))
	}
	return out, rows.Err()
}

func (s *Store) ListSIEMDeliveryAttempts(ctx context.Context, tenantID, deliveryID string, limit int) ([]domain.SIEMDeliveryAttempt, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, delivery_id, status_code, failure_class, response_body, response_truncated, error, created_at
		FROM siem_delivery_attempts
		WHERE tenant_id=$1 AND delivery_id=$2
		ORDER BY created_at DESC
		LIMIT $3`, tenantID, deliveryID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.SIEMDeliveryAttempt
	for rows.Next() {
		item, err := scanSIEMDeliveryAttempt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) RetrySIEMDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.SIEMDelivery, error) {
	item, err := scanSIEMDelivery(s.pool.QueryRow(ctx, `
		UPDATE siem_deliveries
		SET state='scheduled', next_attempt_at=now(), worker_id='', updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND state <> 'succeeded'
		RETURNING id, tenant_id, sink_id, from_sequence, to_sequence, state, body_sha256, attempt_count,
		          next_attempt_at, COALESCE(last_attempt_at, 'epoch'::timestamptz), created_at, updated_at`,
		tenantID, deliveryID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.SIEMDelivery{}, app.ErrNotFound
	}
	if err != nil {
		return domain.SIEMDelivery{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "siem_delivery.retry_requested", Resource: "siem_delivery", ResourceID: deliveryID, Reason: reason})
	return normalizeSIEMDelivery(item), nil
}

func (s *Store) EvaluateAlertRules(ctx context.Context, workerID string, limit int) error {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, rule_type, metric_name, threshold, comparator, window_seconds, dimensions, state, created_by, created_at, updated_at
		FROM alert_rules
		WHERE state='active'
		ORDER BY updated_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	var rules []domain.AlertRule
	for rows.Next() {
		rule, err := scanAlertRule(rows)
		if err != nil {
			return err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, rule := range rules {
		observed, err := s.alertObservedValue(ctx, rule)
		if err != nil {
			return err
		}
		if compareAlertValue(observed, rule.Comparator, rule.Threshold) {
			if err := s.openOrUpdateAlertFiring(ctx, rule, observed, workerID); err != nil {
				return err
			}
		} else if err := s.resolveAlertFirings(ctx, rule, observed, workerID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) alertObservedValue(ctx context.Context, rule domain.AlertRule) (float64, error) {
	dimensions, err := json.Marshal(rule.Dimensions)
	if err != nil {
		return 0, err
	}
	var value float64
	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(max(value), 0)
		FROM metrics_rollups
		WHERE tenant_id=$1
		  AND metric_name=$2
		  AND bucket_start >= now() - ($3::text || ' seconds')::interval
		  AND dimensions @> $4::jsonb`,
		rule.TenantID, rule.MetricName, rule.WindowSeconds, string(dimensions)).Scan(&value); err != nil {
		return 0, err
	}
	return value, nil
}

func compareAlertValue(observed float64, comparator string, threshold float64) bool {
	switch comparator {
	case ">":
		return observed > threshold
	case ">=":
		return observed >= threshold
	case "<":
		return observed < threshold
	case "<=":
		return observed <= threshold
	case "==":
		return observed == threshold
	default:
		return false
	}
}

func (s *Store) openOrUpdateAlertFiring(ctx context.Context, rule domain.AlertRule, observed float64, workerID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO alert_firings(id, tenant_id, rule_id, state, observed_value, threshold, reason)
		SELECT $1,$2,$3,'open',$4,$5,$6
		WHERE NOT EXISTS (
			SELECT 1 FROM alert_firings
			WHERE tenant_id=$2 AND rule_id=$3 AND state IN ('open', 'acknowledged')
		)
		RETURNING id`, mustID("alf"), rule.TenantID, rule.ID, observed, rule.Threshold, "threshold breached").Scan(&id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if id != "" {
		firing := domain.AlertFiring{ID: id, TenantID: rule.TenantID, RuleID: rule.ID, State: domain.AlertFiringOpen, ObservedValue: observed, Threshold: rule.Threshold, Reason: "threshold breached", StartedAt: time.Now().UTC(), LastEvaluatedAt: time.Now().UTC()}
		if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: rule.TenantID, ActorID: workerID, Action: "alert_firing.opened", Resource: "alert_firing", ResourceID: id, Reason: rule.Name}); err != nil {
			return err
		}
		if err := s.enqueueNotificationDeliveriesTx(ctx, tx, firing, domain.AlertFiringOpen, rule.Name); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `
		UPDATE alert_firings
		SET observed_value=$3, threshold=$4, last_evaluated_at=now(), updated_at=now()
		WHERE tenant_id=$1 AND rule_id=$2 AND state IN ('open', 'acknowledged')`,
		rule.TenantID, rule.ID, observed, rule.Threshold)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) resolveAlertFirings(ctx context.Context, rule domain.AlertRule, observed float64, workerID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	rows, err := tx.Query(ctx, `
		UPDATE alert_firings
		SET state='resolved', observed_value=$3, last_evaluated_at=now(), resolved_at=now(), updated_at=now()
		WHERE tenant_id=$1 AND rule_id=$2 AND state IN ('open', 'acknowledged')
		RETURNING id, tenant_id, rule_id, state, observed_value, threshold, reason, started_at, last_evaluated_at,
		          acknowledged_by, COALESCE(acknowledged_at, 'epoch'::timestamptz), COALESCE(resolved_at, 'epoch'::timestamptz), updated_at`,
		rule.TenantID, rule.ID, observed)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		firing, err := scanAlertFiring(rows)
		if err != nil {
			return err
		}
		firing = normalizeAlertFiring(firing)
		if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: rule.TenantID, ActorID: workerID, Action: "alert_firing.resolved", Resource: "alert_firing", ResourceID: firing.ID, Reason: rule.Name}); err != nil {
			return err
		}
		if err := s.enqueueNotificationDeliveriesTx(ctx, tx, firing, domain.AlertFiringResolved, rule.Name); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) requireActiveNotificationChannels(ctx context.Context, tx pgx.Tx, tenantID string, channelIDs []string) error {
	if len(channelIDs) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id
		FROM notification_channels
		WHERE tenant_id=$1 AND state='active' AND id = ANY($2)`, tenantID, channelIDs)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		seen[id] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range channelIDs {
		if !seen[id] {
			return fmt.Errorf("%w: notification channel is missing, disabled, or belongs to another tenant", app.ErrInvalidInput)
		}
	}
	return nil
}

func (s *Store) setAlertRuleChannelsTx(ctx context.Context, tx pgx.Tx, tenantID, alertRuleID string, channelIDs []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM alert_rule_channels WHERE tenant_id=$1 AND alert_rule_id=$2`, tenantID, alertRuleID); err != nil {
		return err
	}
	for _, channelID := range channelIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO alert_rule_channels(tenant_id, alert_rule_id, channel_id)
			VALUES($1,$2,$3)
			ON CONFLICT DO NOTHING`, tenantID, alertRuleID, channelID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) attachAlertRuleChannels(ctx context.Context, tenantID string, rules []domain.AlertRule) ([]domain.AlertRule, error) {
	for i := range rules {
		channelIDs, err := s.listAlertRuleChannelIDs(ctx, tenantID, rules[i].ID)
		if err != nil {
			return nil, err
		}
		rules[i].ChannelIDs = channelIDs
	}
	return rules, nil
}

func (s *Store) listAlertRuleChannelIDs(ctx context.Context, tenantID, alertRuleID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT channel_id
		FROM alert_rule_channels
		WHERE tenant_id=$1 AND alert_rule_id=$2
		ORDER BY channel_id`, tenantID, alertRuleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) listAlertRuleChannelIDsTx(ctx context.Context, tx pgx.Tx, tenantID, alertRuleID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT channel_id
		FROM alert_rule_channels
		WHERE tenant_id=$1 AND alert_rule_id=$2
		ORDER BY channel_id`, tenantID, alertRuleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) enqueueNotificationDeliveriesTx(ctx context.Context, tx pgx.Tx, firing domain.AlertFiring, transition, reason string) error {
	rows, err := tx.Query(ctx, `
		SELECT c.id
		FROM alert_rule_channels arc
		JOIN notification_channels c ON c.tenant_id=arc.tenant_id AND c.id=arc.channel_id
		WHERE arc.tenant_id=$1 AND arc.alert_rule_id=$2 AND c.state='active'
		ORDER BY c.id`, firing.TenantID, firing.RuleID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var channelID string
		if err := rows.Scan(&channelID); err != nil {
			return err
		}
		body, err := notificationPayload(firing, transition, reason)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO notification_deliveries(id, tenant_id, channel_id, firing_id, transition, state, body, body_sha256)
			VALUES($1,$2,$3,$4,$5,'scheduled',$6,$7)
			ON CONFLICT (tenant_id, channel_id, firing_id, transition) WHERE firing_id <> '' DO NOTHING`,
			mustID("ndel"), firing.TenantID, channelID, firing.ID, transition, body, domain.HashSHA256(body)); err != nil {
			return err
		}
	}
	return rows.Err()
}

func notificationPayload(firing domain.AlertFiring, transition, reason string) ([]byte, error) {
	payload := map[string]any{
		"type":           "alert." + transition,
		"tenant_id":      firing.TenantID,
		"firing_id":      firing.ID,
		"alert_rule_id":  firing.RuleID,
		"transition":     transition,
		"state":          firing.State,
		"observed_value": firing.ObservedValue,
		"threshold":      firing.Threshold,
		"reason":         reason,
		"occurred_at":    time.Now().UTC(),
	}
	return json.Marshal(payload)
}

func (s *Store) insertNotificationDelivery(ctx context.Context, tenantID, channelID, firingID, transition string, body []byte) (domain.NotificationDelivery, error) {
	item, err := scanNotificationDelivery(s.pool.QueryRow(ctx, `
		INSERT INTO notification_deliveries(id, tenant_id, channel_id, firing_id, transition, state, body, body_sha256)
		VALUES($1,$2,$3,$4,$5,'scheduled',$6,$7)
		RETURNING id, tenant_id, channel_id, firing_id, transition, state, body_sha256, attempt_count,
		          next_attempt_at, COALESCE(last_attempt_at, 'epoch'::timestamptz), created_at, updated_at`,
		mustID("ndel"), tenantID, channelID, firingID, transition, body, domain.HashSHA256(body)))
	if err != nil {
		return domain.NotificationDelivery{}, err
	}
	return normalizeNotificationDelivery(item), nil
}

func (s *Store) insertSIEMDelivery(ctx context.Context, tenantID, sinkID string, fromSequence, toSequence int64, body []byte) (domain.SIEMDelivery, error) {
	item, err := scanSIEMDelivery(s.pool.QueryRow(ctx, `
		INSERT INTO siem_deliveries(id, tenant_id, sink_id, from_sequence, to_sequence, state, body, body_sha256)
		VALUES($1,$2,$3,$4,$5,'scheduled',$6,$7)
		ON CONFLICT (tenant_id, sink_id, from_sequence, to_sequence) WHERE (from_sequence > 0 OR to_sequence > 0)
		DO UPDATE SET updated_at=siem_deliveries.updated_at
		RETURNING id, tenant_id, sink_id, from_sequence, to_sequence, state, body_sha256, attempt_count,
		          next_attempt_at, COALESCE(last_attempt_at, 'epoch'::timestamptz), created_at, updated_at`,
		mustID("sdel"), tenantID, sinkID, fromSequence, toSequence, body, domain.HashSHA256(body)))
	if err != nil {
		return domain.SIEMDelivery{}, err
	}
	return normalizeSIEMDelivery(item), nil
}

func (s *Store) RefreshMetricsRollups(ctx context.Context, workerID string, limit int) error {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `SELECT id FROM tenants WHERE state='active' ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return err
		}
		tenants = append(tenants, tenantID)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	bucketStart := time.Now().UTC().Truncate(time.Minute)
	for _, tenantID := range tenants {
		if err := s.refreshTenantMetricsRollups(ctx, tenantID, workerID, bucketStart); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) refreshTenantMetricsRollups(ctx context.Context, tenantID, workerID string, bucketStart time.Time) error {
	metrics, err := s.OpsMetrics(ctx, tenantID)
	if err != nil {
		return err
	}
	rollups := []domain.MetricRollup{}
	addRollup := func(name string, value float64, dimensions map[string]string) {
		if dimensions == nil {
			dimensions = map[string]string{}
		}
		rollups = append(rollups, domain.MetricRollup{
			ID:             mustID("mru"),
			TenantID:       tenantID,
			MetricName:     name,
			BucketStart:    bucketStart,
			BucketSeconds:  60,
			Dimensions:     dimensions,
			DimensionsHash: domain.MetricDimensionsHash(dimensions),
			Value:          value,
			Source:         "scheduler:" + workerID,
		})
	}
	addRollup("events.total", float64(metrics.EventsTotal), nil)
	addRollup("outbox.pending", float64(metrics.OutboxPending), nil)
	addRollup("outbox.oldest_age_seconds", float64(metrics.OldestOutboxAgeSec), nil)
	addRollup("dead_letter.open", float64(metrics.DeadLetterOpen), nil)
	addRollup("quarantine.open", float64(metrics.QuarantineOpen), nil)
	addRollup("endpoint.circuit_open", float64(metrics.EndpointCircuitOpen), nil)
	addRollup("audit_chain.unchained_events", float64(metrics.AuditChainUnchainedEvents), nil)
	addRollup("audit_chain.verification_failures", float64(metrics.AuditChainVerificationFailures), nil)
	addRollup("audit_chain.last_anchor_age_seconds", float64(metrics.AuditChainLastAnchorAgeSec), nil)
	addRollup("reconciliation.failed_items", float64(metrics.ReconciliationItemsByOutcome[domain.ReconciliationOutcomeFailed]+metrics.ReconciliationItemsByOutcome[domain.ReconciliationOutcomeUnrecoverable]), nil)
	var expiredWorkers int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM worker_leases WHERE expires_at <= now()`).Scan(&expiredWorkers); err != nil {
		return err
	}
	addRollup("worker.expired_leases", float64(expiredWorkers), nil)
	for state, count := range metrics.DeliveriesByState {
		addRollup("deliveries.by_state", float64(count), map[string]string{"state": state})
	}
	for state, count := range metrics.ReplayJobsByState {
		addRollup("replay_jobs.by_state", float64(count), map[string]string{"state": state})
	}
	for state, count := range metrics.ReconciliationJobsByState {
		addRollup("reconciliation_jobs.by_state", float64(count), map[string]string{"state": state})
	}
	for outcome, count := range metrics.ReconciliationItemsByOutcome {
		addRollup("reconciliation_items.by_outcome", float64(count), map[string]string{"outcome": outcome})
	}
	queues, err := s.ListQueues(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, queue := range queues {
		dimensions := map[string]string{"queue": queue.Name}
		addRollup("queue.pending", float64(queue.Pending), dimensions)
		addRollup("queue.in_progress", float64(queue.InProgress), dimensions)
		addRollup("queue.due_now", float64(queue.DueNow), dimensions)
		addRollup("queue.oldest_pending_age_seconds", float64(queue.OldestPendingAgeSec), dimensions)
	}
	health, err := s.ListEndpointHealth(ctx, tenantID, 100)
	if err != nil {
		return err
	}
	for _, endpoint := range health {
		dimensions := map[string]string{"endpoint_id": endpoint.EndpointID}
		addRollup("endpoint.successes_24h", float64(endpoint.Successes24h), dimensions)
		addRollup("endpoint.failures_24h", float64(endpoint.Failures24h), dimensions)
		total := endpoint.Successes24h + endpoint.Failures24h
		if total > 0 {
			addRollup("endpoint.failure_rate_24h", float64(endpoint.Failures24h)/float64(total), dimensions)
		}
	}
	for _, rollup := range rollups {
		if err := s.upsertMetricRollup(ctx, rollup); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) upsertMetricRollup(ctx context.Context, item domain.MetricRollup) error {
	dimensions, err := json.Marshal(item.Dimensions)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO metrics_rollups(id, tenant_id, metric_name, bucket_start, bucket_seconds, dimensions, dimensions_hash, value, source)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (tenant_id, metric_name, bucket_start, dimensions_hash)
		DO UPDATE SET value=EXCLUDED.value, source=EXCLUDED.source, updated_at=now()`,
		item.ID, item.TenantID, item.MetricName, item.BucketStart, item.BucketSeconds, dimensions, item.DimensionsHash, item.Value, item.Source)
	return err
}

func (s *Store) ListAuditEvents(ctx context.Context, tenantID string, limit int) ([]domain.AuditEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, actor_id, action, resource, resource_id, reason, occurred_at FROM audit_events WHERE tenant_id=$1 ORDER BY occurred_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuditEvent
	for rows.Next() {
		var item domain.AuditEvent
		if err := rows.Scan(&item.ID, &item.TenantID, &item.ActorID, &item.Action, &item.Resource, &item.ResourceID, &item.Reason, &item.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetAuditChainHead(ctx context.Context, tenantID string) (domain.AuditChainHead, error) {
	var head domain.AuditChainHead
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, sequence, chain_hash, last_audit_event_id, updated_at
		FROM audit_chain_heads
		WHERE tenant_id=$1`, tenantID).
		Scan(&head.TenantID, &head.Sequence, &head.ChainHash, &head.LastAuditEventID, &head.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		head.TenantID = tenantID
	} else if err != nil {
		return domain.AuditChainHead{}, err
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM audit_events a
		WHERE a.tenant_id=$1
		  AND NOT EXISTS (
		      SELECT 1 FROM audit_chain_entries c
		      WHERE c.tenant_id=a.tenant_id AND c.audit_event_id=a.id
		  )`, tenantID).Scan(&head.UnchainedEvents); err != nil {
		return domain.AuditChainHead{}, err
	}
	anchor := s.pool.QueryRow(ctx, `
		SELECT id, to_sequence, created_at
		FROM audit_chain_anchors
		WHERE tenant_id=$1
		ORDER BY to_sequence DESC, created_at DESC
		LIMIT 1`, tenantID)
	if err := anchor.Scan(&head.LastAnchorID, &head.LastAnchorSequence, &head.LastAnchoredAt); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return domain.AuditChainHead{}, err
	}
	return head, nil
}

func (s *Store) VerifyAuditChain(ctx context.Context, tenantID string, req app.AuditChainVerifyRequest) (domain.AuditChainVerification, error) {
	head, err := s.GetAuditChainHead(ctx, tenantID)
	if err != nil {
		return domain.AuditChainVerification{}, err
	}
	from := req.FromSequence
	if from <= 0 {
		from = 1
	}
	to := req.ToSequence
	if to <= 0 || to > head.Sequence {
		to = head.Sequence
	}
	result := domain.AuditChainVerification{
		TenantID:       tenantID,
		Valid:          true,
		FromSequence:   from,
		ToSequence:     to,
		VerifiedAt:     time.Now().UTC(),
		StartChainHash: "",
	}
	if head.Sequence == 0 || from > to {
		result.ToSequence = 0
		return result, nil
	}
	expectedPrevious := ""
	if from > 1 {
		if err := s.pool.QueryRow(ctx, `SELECT chain_hash FROM audit_chain_entries WHERE tenant_id=$1 AND sequence=$2`, tenantID, from-1).Scan(&expectedPrevious); err != nil {
			result.Valid = false
			result.Failures = append(result.Failures, domain.AuditChainFailure{Sequence: from - 1, Kind: "missing_previous_entry", Detail: err.Error()})
			expectedPrevious = ""
		}
		result.StartChainHash = expectedPrevious
	}
	rows, err := s.pool.Query(ctx, `
		SELECT c.sequence, c.audit_event_id, c.event_hash, c.previous_chain_hash, c.chain_hash,
		       c.canonicalization_version, c.state, COALESCE(c.audit_event_deleted_at, 'epoch'::timestamptz), c.tombstone_reason,
		       COALESCE(a.id,''), COALESCE(a.tenant_id,''), COALESCE(a.actor_id,''), COALESCE(a.action,''),
		       COALESCE(a.resource,''), COALESCE(a.resource_id,''), COALESCE(a.reason,''), COALESCE(a.occurred_at, 'epoch'::timestamptz)
		FROM audit_chain_entries c
		LEFT JOIN audit_events a ON a.tenant_id=c.tenant_id AND a.id=c.audit_event_id
		WHERE c.tenant_id=$1 AND c.sequence BETWEEN $2 AND $3
		ORDER BY c.sequence ASC`, tenantID, from, to)
	if err != nil {
		return domain.AuditChainVerification{}, err
	}
	defer rows.Close()
	expectedSequence := from
	for rows.Next() {
		var sequence int64
		var auditEventID, eventHash, previousHash, chainHash, version, state, tombstoneReason string
		var deletedAt time.Time
		var event domain.AuditEvent
		if err := rows.Scan(&sequence, &auditEventID, &eventHash, &previousHash, &chainHash, &version, &state, &deletedAt, &tombstoneReason,
			&event.ID, &event.TenantID, &event.ActorID, &event.Action, &event.Resource, &event.ResourceID, &event.Reason, &event.OccurredAt); err != nil {
			return domain.AuditChainVerification{}, err
		}
		for expectedSequence < sequence {
			result.Valid = false
			result.Failures = append(result.Failures, domain.AuditChainFailure{Sequence: expectedSequence, Kind: "missing_entry"})
			expectedSequence++
		}
		result.CheckedEntries++
		if version != auditchain.CanonicalizationVersion {
			result.Valid = false
			result.Failures = append(result.Failures, domain.AuditChainFailure{Sequence: sequence, AuditEventID: auditEventID, Kind: "unsupported_canonicalization_version", Detail: version})
		}
		if previousHash != expectedPrevious {
			result.Valid = false
			result.Failures = append(result.Failures, domain.AuditChainFailure{Sequence: sequence, AuditEventID: auditEventID, Kind: "previous_hash_mismatch"})
		}
		if event.ID == "" {
			if state == domain.AuditChainEntryStateRetained {
				result.RetainedEntries++
			} else {
				result.Valid = false
				result.Failures = append(result.Failures, domain.AuditChainFailure{Sequence: sequence, AuditEventID: auditEventID, Kind: "missing_audit_event"})
			}
		} else {
			recomputed, err := auditchain.EventHash(event)
			if err != nil {
				return domain.AuditChainVerification{}, err
			}
			if recomputed != eventHash {
				result.Valid = false
				result.Failures = append(result.Failures, domain.AuditChainFailure{Sequence: sequence, AuditEventID: auditEventID, Kind: "event_hash_mismatch"})
			}
		}
		expectedChainHash := auditchain.ChainHash(expectedPrevious, eventHash)
		if expectedChainHash != chainHash {
			result.Valid = false
			result.Failures = append(result.Failures, domain.AuditChainFailure{Sequence: sequence, AuditEventID: auditEventID, Kind: "chain_hash_mismatch"})
		}
		expectedPrevious = chainHash
		result.EndChainHash = chainHash
		expectedSequence = sequence + 1
		_ = deletedAt
		_ = tombstoneReason
	}
	if err := rows.Err(); err != nil {
		return domain.AuditChainVerification{}, err
	}
	for expectedSequence <= to {
		result.Valid = false
		result.Failures = append(result.Failures, domain.AuditChainFailure{Sequence: expectedSequence, Kind: "missing_entry"})
		expectedSequence++
	}
	return result, nil
}

func (s *Store) CreateAuditChainAnchor(ctx context.Context, tenantID, actorID string, req app.AuditChainAnchorRequest) (domain.AuditChainAnchor, error) {
	verification, err := s.VerifyAuditChain(ctx, tenantID, app.AuditChainVerifyRequest{FromSequence: req.FromSequence, ToSequence: req.ToSequence})
	if err != nil {
		return domain.AuditChainAnchor{}, err
	}
	if !verification.Valid || verification.CheckedEntries == 0 {
		return domain.AuditChainAnchor{}, fmt.Errorf("%w: audit chain range is not verifiable", app.ErrInvalidInput)
	}
	id := mustID("aca")
	now := time.Now().UTC()
	manifest := map[string]any{
		"id":             id,
		"tenant_id":      tenantID,
		"from_sequence":  verification.FromSequence,
		"to_sequence":    verification.ToSequence,
		"chain_hash":     verification.EndChainHash,
		"created_at":     now,
		"created_by":     actorID,
		"reason":         req.Reason,
		"canonical_json": "audit-chain-anchor-v1",
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return domain.AuditChainAnchor{}, err
	}
	storageBackend := domain.RawStoragePostgres
	objectBucket := ""
	objectKey := ""
	objectWritten := false
	if s.rawStorageMode == domain.RawStorageS3 && s.objectStore != nil {
		storageBackend = domain.RawStorageS3
		objectBucket = s.objectBucket
		objectKey = blobstore.AuditAnchorKey(tenantID, id)
		if err := s.objectStore.Put(ctx, blobstore.Object{Bucket: objectBucket, Key: objectKey, ContentType: "application/json", SHA256: evidence.SHA256(manifestBytes), SizeBytes: int64(len(manifestBytes))}, manifestBytes); err != nil {
			return domain.AuditChainAnchor{}, err
		}
		objectWritten = true
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.AuditChainAnchor{}, err
	}
	defer rollback(ctx, tx)
	var out domain.AuditChainAnchor
	err = tx.QueryRow(ctx, `
		INSERT INTO audit_chain_anchors(id, tenant_id, from_sequence, to_sequence, chain_hash, manifest_sha256,
			storage_backend, object_bucket, object_key, manifest, created_by, reason, created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)
		RETURNING id, tenant_id, from_sequence, to_sequence, chain_hash, manifest_sha256, storage_backend, object_bucket, object_key, created_by, reason, created_at`,
		id, tenantID, verification.FromSequence, verification.ToSequence, verification.EndChainHash, evidence.SHA256(manifestBytes),
		storageBackend, objectBucket, objectKey, string(manifestBytes), actorID, req.Reason, now).
		Scan(&out.ID, &out.TenantID, &out.FromSequence, &out.ToSequence, &out.ChainHash, &out.ManifestSHA256,
			&out.StorageBackend, &out.ObjectBucket, &out.ObjectKey, &out.CreatedBy, &out.Reason, &out.CreatedAt)
	if err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.AuditChainAnchor{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "audit_chain.anchored", Resource: "audit_chain_anchor", ResourceID: id, Reason: req.Reason}); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.AuditChainAnchor{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.AuditChainAnchor{}, err
	}
	return out, nil
}

func (s *Store) ListAuditChainAnchors(ctx context.Context, tenantID string, limit int) ([]domain.AuditChainAnchor, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, from_sequence, to_sequence, chain_hash, manifest_sha256, storage_backend, object_bucket, object_key, created_by, reason, created_at
		FROM audit_chain_anchors
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuditChainAnchor
	for rows.Next() {
		item, err := scanAuditChainAnchor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetAuditChainAnchor(ctx context.Context, tenantID, anchorID string) (domain.AuditChainAnchor, error) {
	item, err := scanAuditChainAnchor(s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, from_sequence, to_sequence, chain_hash, manifest_sha256, storage_backend, object_bucket, object_key, created_by, reason, created_at
		FROM audit_chain_anchors
		WHERE tenant_id=$1 AND id=$2`, tenantID, anchorID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AuditChainAnchor{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) ListRetentionPolicies(ctx context.Context, tenantID string, limit int) ([]domain.RetentionPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, resource_type, source_id, retention_days, state, legal_hold, hold_reason, created_by, created_at, updated_at
		FROM retention_policies
		WHERE tenant_id=$1
		ORDER BY updated_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.RetentionPolicy
	for rows.Next() {
		item, err := scanRetentionPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateRetentionPolicy(ctx context.Context, tenantID, actorID string, req app.CreateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	id := mustID("ret")
	var item domain.RetentionPolicy
	err := s.pool.QueryRow(ctx, `
		INSERT INTO retention_policies(id, tenant_id, resource_type, source_id, retention_days, state, legal_hold, hold_reason, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (tenant_id, resource_type, source_id) DO UPDATE
		SET retention_days=EXCLUDED.retention_days, state=EXCLUDED.state, legal_hold=EXCLUDED.legal_hold, hold_reason=EXCLUDED.hold_reason, updated_at=now()
		RETURNING id, tenant_id, resource_type, source_id, retention_days, state, legal_hold, hold_reason, created_by, created_at, updated_at`,
		id, tenantID, req.ResourceType, req.SourceID, req.RetentionDays, req.State, req.LegalHold, req.HoldReason, actorID,
	).Scan(&item.ID, &item.TenantID, &item.ResourceType, &item.SourceID, &item.RetentionDays, &item.State, &item.LegalHold, &item.HoldReason, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.RetentionPolicy{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "retention_policy.upserted", Resource: "retention_policy", ResourceID: item.ID, Reason: item.ResourceType})
	return item, nil
}

func (s *Store) UpdateRetentionPolicy(ctx context.Context, tenantID, policyID, actorID string, req app.UpdateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	var existing domain.RetentionPolicy
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, resource_type, source_id, retention_days, state, legal_hold, hold_reason, created_by, created_at, updated_at
		FROM retention_policies
		WHERE tenant_id=$1 AND id=$2`, tenantID, policyID).
		Scan(&existing.ID, &existing.TenantID, &existing.ResourceType, &existing.SourceID, &existing.RetentionDays, &existing.State, &existing.LegalHold, &existing.HoldReason, &existing.CreatedBy, &existing.CreatedAt, &existing.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RetentionPolicy{}, app.ErrNotFound
	}
	if err != nil {
		return domain.RetentionPolicy{}, err
	}
	if req.RetentionDays != nil {
		existing.RetentionDays = *req.RetentionDays
	}
	if req.State != "" {
		existing.State = req.State
	}
	if req.SourceID != nil {
		existing.SourceID = *req.SourceID
	}
	if req.LegalHold != nil {
		existing.LegalHold = *req.LegalHold
	}
	if req.HoldReason != nil {
		existing.HoldReason = *req.HoldReason
	}
	err = s.pool.QueryRow(ctx, `
		UPDATE retention_policies
		SET source_id=$1, retention_days=$2, state=$3, legal_hold=$4, hold_reason=$5, updated_at=now()
		WHERE tenant_id=$6 AND id=$7
		RETURNING id, tenant_id, resource_type, source_id, retention_days, state, legal_hold, hold_reason, created_by, created_at, updated_at`,
		existing.SourceID, existing.RetentionDays, existing.State, existing.LegalHold, existing.HoldReason, tenantID, policyID,
	).Scan(&existing.ID, &existing.TenantID, &existing.ResourceType, &existing.SourceID, &existing.RetentionDays, &existing.State, &existing.LegalHold, &existing.HoldReason, &existing.CreatedBy, &existing.CreatedAt, &existing.UpdatedAt)
	if err != nil {
		return domain.RetentionPolicy{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "retention_policy.updated", Resource: "retention_policy", ResourceID: policyID, Reason: existing.ResourceType})
	return existing, nil
}

func (s *Store) CreateProviderAdapter(ctx context.Context, tenantID, actorID string, req app.CreateProviderAdapterRequest) (domain.ProviderAdapter, error) {
	item, err := scanProviderAdapter(s.pool.QueryRow(ctx, `
		INSERT INTO provider_adapters(id, tenant_id, name, kind, description, risk_level, state, provenance_url, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, COALESCE(tenant_id,''), name, kind, description, risk_level, state, provenance_url, created_by, created_at, updated_at, COALESCE(retired_at, 'epoch'::timestamptz)`,
		mustID("pad"), tenantID, req.Name, req.Kind, req.Description, req.RiskLevel, domain.AdapterStateDraft, req.ProvenanceURL, actorID,
	))
	if err != nil {
		return domain.ProviderAdapter{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "adapter.created", Resource: "provider_adapter", ResourceID: item.ID, Reason: item.Name})
	return normalizeProviderAdapter(item), nil
}

func (s *Store) ListProviderAdapters(ctx context.Context, tenantID string, limit int) ([]domain.ProviderAdapter, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, COALESCE(tenant_id,''), name, kind, description, risk_level, state, provenance_url, created_by, created_at, updated_at, COALESCE(retired_at, 'epoch'::timestamptz)
		FROM provider_adapters
		WHERE tenant_id IS NULL OR tenant_id=$1
		ORDER BY tenant_id NULLS FIRST, name
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ProviderAdapter
	for rows.Next() {
		item, err := scanProviderAdapter(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, normalizeProviderAdapter(item))
	}
	return out, rows.Err()
}

func (s *Store) GetProviderAdapter(ctx context.Context, tenantID, adapterID string) (domain.ProviderAdapter, error) {
	item, err := scanProviderAdapter(s.pool.QueryRow(ctx, `
		SELECT id, COALESCE(tenant_id,''), name, kind, description, risk_level, state, provenance_url, created_by, created_at, updated_at, COALESCE(retired_at, 'epoch'::timestamptz)
		FROM provider_adapters
		WHERE id=$2 AND (tenant_id IS NULL OR tenant_id=$1)`, tenantID, adapterID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProviderAdapter{}, app.ErrNotFound
	}
	return normalizeProviderAdapter(item), err
}

func (s *Store) CreateAdapterVersion(ctx context.Context, tenantID, adapterID, actorID string, req app.CreateAdapterVersionRequest) (domain.AdapterVersion, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AdapterVersion{}, err
	}
	defer rollback(ctx, tx)

	adapter, err := scanProviderAdapter(tx.QueryRow(ctx, `
		SELECT id, COALESCE(tenant_id,''), name, kind, description, risk_level, state, provenance_url, created_by, created_at, updated_at, COALESCE(retired_at, 'epoch'::timestamptz)
		FROM provider_adapters
		WHERE tenant_id=$1 AND id=$2 AND state <> 'retired'
		FOR UPDATE`, tenantID, adapterID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AdapterVersion{}, app.ErrNotFound
	}
	if err != nil {
		return domain.AdapterVersion{}, err
	}
	definition := req.Definition
	if len(definition) == 0 {
		definition = json.RawMessage(`{}`)
	}
	definitionHash := domain.HashSHA256(definition)
	configHash := definitionHash
	if adapter.Kind == domain.AdapterKindPlugin {
		if strings.TrimSpace(req.PackageSHA256) == "" || strings.TrimSpace(req.PackageSignature) == "" || strings.TrimSpace(req.SBOMSHA256) == "" {
			return domain.AdapterVersion{}, fmt.Errorf("%w: plugin package_sha256, package_signature, and sbom_sha256 are required", app.ErrInvalidInput)
		}
		configHash = req.PackageSHA256
	} else if adapter.Kind == domain.AdapterKindDeclarative && string(definition) == "{}" {
		return domain.AdapterVersion{}, fmt.Errorf("%w: declarative adapter definition is required", app.ErrInvalidInput)
	}

	id := mustID("adv")
	item, err := scanAdapterVersion(tx.QueryRow(ctx, `
		INSERT INTO adapter_versions(id, tenant_id, adapter_id, name, version, kind, config_hash, definition_json, definition_sha256,
			package_sha256, package_signature, sbom_sha256, provenance_url, risk_level, state, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING `+adapterVersionColumns(),
		id, tenantID, adapter.ID, adapter.Name, req.Version, adapter.Kind, configHash, string(definition), definitionHash,
		req.PackageSHA256, req.PackageSignature, req.SBOMSHA256, firstNonEmpty(req.ProvenanceURL, adapter.ProvenanceURL), req.RiskLevel, domain.AdapterStateDraft, actorID,
	))
	if err != nil {
		return domain.AdapterVersion{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "adapter_version.created", Resource: "adapter_version", ResourceID: id, Reason: req.Reason}); err != nil {
		return domain.AdapterVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.AdapterVersion{}, err
	}
	return normalizeAdapterVersion(item), nil
}

func (s *Store) ListAdapterVersions(ctx context.Context, tenantID, adapterID string, limit int) ([]domain.AdapterVersion, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+adapterVersionColumns()+`
		FROM adapter_versions
		WHERE adapter_id=$2 AND (tenant_id IS NULL OR tenant_id=$1)
		ORDER BY created_at DESC
		LIMIT $3`, tenantID, adapterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AdapterVersion
	for rows.Next() {
		item, err := scanAdapterVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, normalizeAdapterVersion(item))
	}
	return out, rows.Err()
}

func (s *Store) ActiveDeclarativeAdapterVersion(ctx context.Context, tenantID, adapterName string) (domain.AdapterVersion, error) {
	item, err := scanAdapterVersion(s.pool.QueryRow(ctx, `
		SELECT `+adapterVersionColumns()+`
		FROM adapter_versions
		WHERE tenant_id=$1 AND name=$2 AND kind='declarative' AND state='active'
		ORDER BY activated_at DESC NULLS LAST, created_at DESC
		LIMIT 1`, tenantID, strings.ToLower(strings.TrimSpace(adapterName))))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AdapterVersion{}, app.ErrNotFound
	}
	return normalizeAdapterVersion(item), err
}

func (s *Store) CreateAdapterTestVector(ctx context.Context, tenantID, adapterID, versionID, actorID string, req app.CreateAdapterTestVectorRequest) (domain.AdapterTestVector, error) {
	if err := s.ensureTenantAdapterVersion(ctx, tenantID, adapterID, versionID); err != nil {
		return domain.AdapterTestVector{}, err
	}
	id := mustID("atv")
	item, err := scanAdapterTestVector(s.pool.QueryRow(ctx, `
		INSERT INTO adapter_test_vectors(id, tenant_id, adapter_version_id, name, purpose, request_json, expected_json, request_sha256, expected_sha256, created_by)
		VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9,$10)
		RETURNING id, tenant_id, adapter_version_id, name, purpose, request_json, expected_json, request_sha256, expected_sha256, state, created_by, created_at, updated_at`,
		id, tenantID, versionID, req.Name, req.Purpose, string(req.Request), string(req.Expected), domain.HashSHA256(req.Request), domain.HashSHA256(req.Expected), actorID,
	))
	if err != nil {
		return domain.AdapterTestVector{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "adapter_test_vector.created", Resource: "adapter_version", ResourceID: versionID, Reason: req.Name})
	return item, nil
}

func (s *Store) TransitionAdapterVersion(ctx context.Context, tenantID, adapterID, versionID, actorID string, req app.AdapterVersionTransitionRequest) (domain.AdapterVersion, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AdapterVersion{}, err
	}
	defer rollback(ctx, tx)
	current, err := scanAdapterVersion(tx.QueryRow(ctx, `
		SELECT `+adapterVersionColumns()+`
		FROM adapter_versions
		WHERE tenant_id=$1 AND adapter_id=$2 AND id=$3
		FOR UPDATE`, tenantID, adapterID, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AdapterVersion{}, app.ErrNotFound
	}
	if err != nil {
		return domain.AdapterVersion{}, err
	}
	nextState, err := adapterVersionNextState(current.State, req.Action)
	if err != nil {
		return domain.AdapterVersion{}, err
	}
	if req.Action == "activate" {
		if _, err := tx.Exec(ctx, `UPDATE adapter_versions SET state='deprecated', deprecated_at=now() WHERE tenant_id=$1 AND adapter_id=$2 AND state='active' AND id<>$3`, tenantID, adapterID, versionID); err != nil {
			return domain.AdapterVersion{}, err
		}
	}
	item, err := scanAdapterVersion(tx.QueryRow(ctx, `
		UPDATE adapter_versions
		SET state=$1,
		    test_results_json=CASE WHEN $2::jsonb IS NULL THEN test_results_json ELSE $2::jsonb END,
		    review_notes=CASE WHEN $3='' THEN review_notes ELSE $3 END,
		    reviewed_by=CASE WHEN $4 THEN $5 ELSE reviewed_by END,
		    activated_by=CASE WHEN $6 THEN $5 ELSE activated_by END,
		    reviewed_at=CASE WHEN $4 THEN now() ELSE reviewed_at END,
		    activated_at=CASE WHEN $6 THEN now() ELSE activated_at END,
		    deprecated_at=CASE WHEN $7 THEN now() ELSE deprecated_at END,
		    retired_at=CASE WHEN $8 THEN now() ELSE retired_at END
		WHERE tenant_id=$9 AND adapter_id=$10 AND id=$11
		RETURNING `+adapterVersionColumns(),
		nextState, nullableJSON(req.TestResults), strings.TrimSpace(req.ReviewNotes), req.Action == "approve_staging", actorID,
		req.Action == "activate", req.Action == "deprecate", req.Action == "retire", tenantID, adapterID, versionID,
	))
	if err != nil {
		return domain.AdapterVersion{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO adapter_version_reviews(id, tenant_id, adapter_version_id, action, from_state, to_state, actor_id, reason)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		mustID("avr"), tenantID, versionID, req.Action, current.State, nextState, actorID, strings.TrimSpace(req.Reason),
	); err != nil {
		return domain.AdapterVersion{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "adapter_version." + req.Action, Resource: "adapter_version", ResourceID: versionID, Reason: req.Reason}); err != nil {
		return domain.AdapterVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.AdapterVersion{}, err
	}
	return normalizeAdapterVersion(item), nil
}

func (s *Store) CreateProviderConnection(ctx context.Context, tenantID, actorID string, req app.CreateProviderConnectionRequest) (domain.ProviderConnection, error) {
	id := mustID("pcn")
	encrypted, err := s.encryptSecret(ctx, tenantID, "provider_connection_credential", []byte(req.Credential))
	if err != nil {
		return domain.ProviderConnection{}, err
	}
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		return domain.ProviderConnection{}, err
	}
	var item domain.ProviderConnection
	err = s.pool.QueryRow(ctx, `
		INSERT INTO provider_connections(id, tenant_id, name, provider, state, credential_type, credential_hint, encrypted_credential, config_json, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)
		RETURNING id, tenant_id, name, provider, state, credential_type, credential_hint, config_json,
			COALESCE(verified_at, 'epoch'::timestamptz), COALESCE(revoked_at, 'epoch'::timestamptz), created_by, created_at, updated_at`,
		id, tenantID, req.Name, req.Provider, domain.ProviderConnectionStateActive, req.CredentialType,
		reconcile.RedactCredential(req.Credential), encrypted, string(configJSON), actorID,
	).Scan(&item.ID, &item.TenantID, &item.Name, &item.Provider, &item.State, &item.CredentialType, &item.CredentialHint, &item.Config,
		&item.VerifiedAt, &item.RevokedAt, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.ProviderConnection{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "provider_connection.created", Resource: "provider_connection", ResourceID: id, Reason: req.Provider})
	return normalizeProviderConnection(item), nil
}

func (s *Store) ListProviderConnections(ctx context.Context, tenantID string, limit int) ([]domain.ProviderConnection, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, provider, state, credential_type, credential_hint, config_json,
			COALESCE(verified_at, 'epoch'::timestamptz), COALESCE(revoked_at, 'epoch'::timestamptz), created_by, created_at, updated_at
		FROM provider_connections
		WHERE tenant_id=$1
		ORDER BY updated_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ProviderConnection
	for rows.Next() {
		item, err := scanProviderConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, normalizeProviderConnection(item))
	}
	return out, rows.Err()
}

func (s *Store) GetProviderConnection(ctx context.Context, tenantID, connectionID string) (domain.ProviderConnection, error) {
	item, err := s.getProviderConnectionPublic(ctx, tenantID, connectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProviderConnection{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) VerifyProviderConnection(ctx context.Context, tenantID, connectionID, actorID, reason string) (domain.ProviderConnection, error) {
	conn, credential, err := s.getProviderConnectionSecret(ctx, tenantID, connectionID)
	if err != nil {
		return domain.ProviderConnection{}, err
	}
	adapter, ok := reconcile.BuiltInRegistry(nil).Adapter(conn.Provider)
	if !ok {
		return domain.ProviderConnection{}, app.ErrInvalidInput
	}
	if err := adapter.ValidateConnection(ctx, reconcile.Connection{
		ID:             conn.ID,
		Provider:       conn.Provider,
		CredentialType: conn.CredentialType,
		Credential:     credential,
		Config:         conn.Config,
	}); err != nil {
		return domain.ProviderConnection{}, fmt.Errorf("%w: provider connection verification failed", app.ErrInvalidInput)
	}
	var out domain.ProviderConnection
	err = s.pool.QueryRow(ctx, `
		UPDATE provider_connections
		SET verified_at=now(), updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND state='active'
		RETURNING id, tenant_id, name, provider, state, credential_type, credential_hint, config_json,
			COALESCE(verified_at, 'epoch'::timestamptz), COALESCE(revoked_at, 'epoch'::timestamptz), created_by, created_at, updated_at`,
		tenantID, connectionID,
	).Scan(&out.ID, &out.TenantID, &out.Name, &out.Provider, &out.State, &out.CredentialType, &out.CredentialHint, &out.Config,
		&out.VerifiedAt, &out.RevokedAt, &out.CreatedBy, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProviderConnection{}, app.ErrNotFound
	}
	if err != nil {
		return domain.ProviderConnection{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "provider_connection.verified", Resource: "provider_connection", ResourceID: connectionID, Reason: reason})
	return normalizeProviderConnection(out), nil
}

func (s *Store) RevokeProviderConnection(ctx context.Context, tenantID, connectionID, actorID, reason string) (domain.ProviderConnection, error) {
	var out domain.ProviderConnection
	err := s.pool.QueryRow(ctx, `
		UPDATE provider_connections
		SET state='revoked', revoked_at=now(), updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND state <> 'revoked'
		RETURNING id, tenant_id, name, provider, state, credential_type, credential_hint, config_json,
			COALESCE(verified_at, 'epoch'::timestamptz), COALESCE(revoked_at, 'epoch'::timestamptz), created_by, created_at, updated_at`,
		tenantID, connectionID,
	).Scan(&out.ID, &out.TenantID, &out.Name, &out.Provider, &out.State, &out.CredentialType, &out.CredentialHint, &out.Config,
		&out.VerifiedAt, &out.RevokedAt, &out.CreatedBy, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProviderConnection{}, app.ErrNotFound
	}
	if err != nil {
		return domain.ProviderConnection{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "provider_connection.revoked", Resource: "provider_connection", ResourceID: connectionID, Reason: reason})
	return normalizeProviderConnection(out), nil
}

func (s *Store) CreateReconciliationJob(ctx context.Context, tenantID, actorID string, req app.ReconciliationJobRequest) (domain.ReconciliationJob, error) {
	conn, err := s.getProviderConnectionPublic(ctx, tenantID, req.ConnectionID)
	if err != nil {
		return domain.ReconciliationJob{}, err
	}
	id := mustID("rec")
	state := domain.ReconciliationJobStateScheduled
	if req.DryRun {
		state = domain.ReconciliationJobStateCompleted
	}
	var item domain.ReconciliationJob
	err = s.pool.QueryRow(ctx, `
		INSERT INTO reconciliation_jobs(id, tenant_id, connection_id, provider, state, dry_run, capture_missing, route_recovered, redeliver_failed,
			scope_object_id, window_start, window_end, reason, created_by, completed_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,CASE WHEN $6 THEN now() ELSE NULL END)
		RETURNING id, tenant_id, connection_id, provider, state, dry_run, capture_missing, route_recovered, redeliver_failed, scope_object_id,
			COALESCE(window_start, 'epoch'::timestamptz), COALESCE(window_end, 'epoch'::timestamptz), cursor, reason,
			total_items, matched_items, missing_items, captured_items, redelivered_items, unrecoverable_items, failed_items, error,
			created_by, created_at, COALESCE(started_at, 'epoch'::timestamptz), COALESCE(completed_at, 'epoch'::timestamptz), COALESCE(canceled_at, 'epoch'::timestamptz)`,
		id, tenantID, req.ConnectionID, conn.Provider, state, req.DryRun, req.CaptureMissing, req.RouteRecovered, req.RedeliverFailed,
		req.ScopeObjectID, nullableTime(req.WindowStart), nullableTime(req.WindowEnd), req.Reason, actorID,
	).Scan(&item.ID, &item.TenantID, &item.ConnectionID, &item.Provider, &item.State, &item.DryRun, &item.CaptureMissing, &item.RouteRecovered,
		&item.RedeliverFailed, &item.ScopeObjectID, &item.WindowStart, &item.WindowEnd, &item.Cursor, &item.Reason, &item.TotalItems,
		&item.MatchedItems, &item.MissingItems, &item.CapturedItems, &item.RedeliveredItems, &item.UnrecoverableItems, &item.FailedItems,
		&item.Error, &item.CreatedBy, &item.CreatedAt, &item.StartedAt, &item.CompletedAt, &item.CanceledAt)
	if err != nil {
		return domain.ReconciliationJob{}, err
	}
	if !req.DryRun {
		payload, _ := json.Marshal(map[string]any{"job_id": id})
		if _, err := s.pool.Exec(ctx, `INSERT INTO outbox(id, tenant_id, kind, resource_id, payload) VALUES($1,$2,$3,$4,$5)`, mustID("out"), tenantID, app.OutboxKindReconciliationJob, id, payload); err != nil {
			return domain.ReconciliationJob{}, err
		}
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "reconciliation.created", Resource: "reconciliation_job", ResourceID: id, Reason: req.Reason})
	return normalizeReconciliationJob(item), nil
}

func (s *Store) ListReconciliationJobs(ctx context.Context, tenantID string, limit int) ([]domain.ReconciliationJob, error) {
	rows, err := s.pool.Query(ctx, reconciliationJobSelectSQL()+` WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ReconciliationJob
	for rows.Next() {
		item, err := scanReconciliationJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, normalizeReconciliationJob(item))
	}
	return out, rows.Err()
}

func (s *Store) GetReconciliationJob(ctx context.Context, tenantID, jobID string) (domain.ReconciliationJob, error) {
	item, err := scanReconciliationJob(s.pool.QueryRow(ctx, reconciliationJobSelectSQL()+` WHERE tenant_id=$1 AND id=$2`, tenantID, jobID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ReconciliationJob{}, app.ErrNotFound
	}
	return normalizeReconciliationJob(item), err
}

func (s *Store) ListReconciliationItems(ctx context.Context, tenantID, jobID string, limit int) ([]domain.ReconciliationItem, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, job_id, provider, provider_object_id, provider_object_type, outcome, local_event_id, recovered_event_id,
			provider_api_evidence_id, redelivery_requested, error, metadata_json, created_at, updated_at
		FROM reconciliation_items
		WHERE tenant_id=$1 AND job_id=$2
		ORDER BY created_at ASC
		LIMIT $3`, tenantID, jobID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ReconciliationItem
	for rows.Next() {
		item, err := scanReconciliationItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) CancelReconciliationJob(ctx context.Context, tenantID, jobID, actorID, reason string) (domain.ReconciliationJob, error) {
	item, err := scanReconciliationJob(s.pool.QueryRow(ctx, reconciliationJobSelectSQL()+`
		WHERE tenant_id=$1 AND id=$2 AND state NOT IN ('completed','failed','canceled')`, tenantID, jobID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ReconciliationJob{}, app.ErrNotFound
	}
	if err != nil {
		return domain.ReconciliationJob{}, err
	}
	err = s.pool.QueryRow(ctx, `
		UPDATE reconciliation_jobs
		SET state='canceled', canceled_at=now(), completed_at=now(), error='', cursor=cursor
		WHERE tenant_id=$1 AND id=$2
		RETURNING id, tenant_id, connection_id, provider, state, dry_run, capture_missing, route_recovered, redeliver_failed, scope_object_id,
			COALESCE(window_start, 'epoch'::timestamptz), COALESCE(window_end, 'epoch'::timestamptz), cursor, reason,
			total_items, matched_items, missing_items, captured_items, redelivered_items, unrecoverable_items, failed_items, error,
			created_by, created_at, COALESCE(started_at, 'epoch'::timestamptz), COALESCE(completed_at, 'epoch'::timestamptz), COALESCE(canceled_at, 'epoch'::timestamptz)`,
		tenantID, item.ID,
	).Scan(&item.ID, &item.TenantID, &item.ConnectionID, &item.Provider, &item.State, &item.DryRun, &item.CaptureMissing, &item.RouteRecovered,
		&item.RedeliverFailed, &item.ScopeObjectID, &item.WindowStart, &item.WindowEnd, &item.Cursor, &item.Reason, &item.TotalItems,
		&item.MatchedItems, &item.MissingItems, &item.CapturedItems, &item.RedeliveredItems, &item.UnrecoverableItems, &item.FailedItems,
		&item.Error, &item.CreatedBy, &item.CreatedAt, &item.StartedAt, &item.CompletedAt, &item.CanceledAt)
	if err != nil {
		return domain.ReconciliationJob{}, err
	}
	_ = s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "reconciliation.canceled", Resource: "reconciliation_job", ResourceID: jobID, Reason: reason})
	return normalizeReconciliationJob(item), nil
}

func (s *Store) CreateAuditExport(ctx context.Context, tenantID, actorID string, req app.CreateAuditExportRequest) (domain.EvidenceExport, error) {
	id := mustID("exp")
	now := time.Now().UTC()
	auditEvents, err := s.auditEventsForExport(ctx, tenantID, req.From, req.To)
	if err != nil {
		return domain.EvidenceExport{}, err
	}
	auditItems := make([]any, 0, len(auditEvents))
	for _, item := range auditEvents {
		auditItems = append(auditItems, item)
	}
	auditJSONL, err := evidence.JSONLines(auditItems)
	if err != nil {
		return domain.EvidenceExport{}, err
	}
	files := map[string][]byte{"audit_events.jsonl": auditJSONL}
	if req.IncludeTimelines {
		timeline, err := s.timelineJSONLForExport(ctx, tenantID, req.From, req.To)
		if err != nil {
			return domain.EvidenceExport{}, err
		}
		files["timelines.jsonl"] = timeline
	}
	if req.IncludeRawPayloads {
		raw, err := s.rawPayloadsJSONLForExport(ctx, tenantID, req.From, req.To)
		if err != nil {
			return domain.EvidenceExport{}, err
		}
		files["raw_payloads.jsonl"] = raw
	}
	payloadEvidence, err := s.payloadEvidenceJSONLForExport(ctx, tenantID, req.From, req.To, req.IncludePayloadBodies)
	if err != nil {
		return domain.EvidenceExport{}, err
	}
	files["payload_evidence.jsonl"] = payloadEvidence
	reconciliationEvidence, err := s.reconciliationEvidenceJSONLForExport(ctx, tenantID, req.From, req.To, req.IncludePayloadBodies)
	if err != nil {
		return domain.EvidenceExport{}, err
	}
	files["reconciliation_evidence.jsonl"] = reconciliationEvidence
	chainProof, chainManifest, err := s.auditChainProofForExport(ctx, tenantID, req.From, req.To)
	if err != nil {
		return domain.EvidenceExport{}, err
	}
	files["audit_chain_proof.jsonl"] = chainProof
	eventIDs, err := s.eventIDsForExport(ctx, tenantID, req.From, req.To)
	if err != nil {
		return domain.EvidenceExport{}, err
	}
	bundle, err := evidence.BuildTarGzipBundle(evidence.Manifest{
		ExportID:             id,
		TenantID:             tenantID,
		CreatedAt:            now,
		From:                 manifestTime(req.From),
		To:                   manifestTime(req.To),
		IncludedEvents:       eventIDs,
		IncludeRawPayloads:   req.IncludeRawPayloads,
		IncludeTimelines:     req.IncludeTimelines,
		IncludePayloadBodies: req.IncludePayloadBodies,
		AuditChain:           chainManifest,
	}, files)
	if err != nil {
		return domain.EvidenceExport{}, err
	}
	verification, err := evidence.VerifyTarGzipBundle(bundle.Bytes)
	if err != nil {
		return domain.EvidenceExport{}, err
	}
	if !verification.Valid {
		return domain.EvidenceExport{}, fmt.Errorf("audit export bundle verification failed: %s", strings.Join(verification.Failures, "; "))
	}
	storageBackend := domain.RawStoragePostgres
	objectBucket := ""
	objectKey := ""
	bodyForDB := bundle.Bytes
	objectWritten := false
	if s.rawStorageMode == domain.RawStorageS3 {
		storageBackend = domain.RawStorageS3
		objectBucket = s.objectBucket
		objectKey = blobstore.ExportKey(tenantID, id)
		if err := s.objectStore.Put(ctx, blobstore.Object{
			Bucket:      objectBucket,
			Key:         objectKey,
			ContentType: "application/gzip",
			SHA256:      bundle.BundleSHA256,
			SizeBytes:   int64(len(bundle.Bytes)),
		}, bundle.Bytes); err != nil {
			return domain.EvidenceExport{}, err
		}
		objectWritten = true
		bodyForDB = []byte{}
	}
	manifestJSON := string(bundle.Manifest)
	filesJSON, _ := json.Marshal(bundle.Files)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.EvidenceExport{}, err
	}
	defer rollback(ctx, tx)
	var out domain.EvidenceExport
	err = tx.QueryRow(ctx, `
		INSERT INTO evidence_exports(id, tenant_id, state, from_time, to_time, include_raw_payloads, include_timelines, include_payload_bodies, format,
			storage_backend, object_bucket, object_key, sha256, manifest_sha256, size_bytes, bundle, manifest, file_hashes,
			created_by, completed_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'tar+gzip+jsonl',$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17::jsonb,$18,now())
		RETURNING id, tenant_id, state, COALESCE(from_time, 'epoch'::timestamptz), COALESCE(to_time, 'epoch'::timestamptz),
			include_raw_payloads, include_timelines, include_payload_bodies, format, storage_backend, object_bucket, object_key, sha256,
			manifest_sha256, size_bytes, error, created_by, created_at, COALESCE(completed_at, 'epoch'::timestamptz)`,
		id, tenantID, domain.EvidenceExportStateReady, nullableTime(req.From), nullableTime(req.To),
		req.IncludeRawPayloads, req.IncludeTimelines, req.IncludePayloadBodies, storageBackend, objectBucket, objectKey,
		bundle.BundleSHA256, bundle.ManifestSHA256, int64(len(bundle.Bytes)), bodyForDB, manifestJSON, string(filesJSON), actorID,
	).Scan(&out.ID, &out.TenantID, &out.State, &out.From, &out.To, &out.IncludeRawPayloads, &out.IncludeTimelines, &out.IncludePayloadBodies,
		&out.Format, &out.StorageBackend, &out.ObjectBucket, &out.ObjectKey, &out.SHA256, &out.ManifestSHA256,
		&out.SizeBytes, &out.Error, &out.CreatedBy, &out.CreatedAt, &out.CompletedAt)
	if err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.EvidenceExport{}, err
	}
	for _, file := range bundle.Files {
		if _, err := tx.Exec(ctx, `
			INSERT INTO evidence_export_items(id, tenant_id, export_id, resource_type, resource_id, file_name, sha256, size_bytes)
			VALUES($1,$2,$3,'export_file',$4,$5,$6,$7)`,
			mustID("exi"), tenantID, id, file.Name, file.Name, file.SHA256, file.SizeBytes,
		); err != nil {
			if objectWritten {
				_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
			}
			return domain.EvidenceExport{}, err
		}
	}
	reason := req.Reason
	if reason == "" {
		reason = "audit export"
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "audit_export.created", Resource: "audit_export", ResourceID: id, Reason: reason}); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.EvidenceExport{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, objectBucket, objectKey)
		}
		return domain.EvidenceExport{}, err
	}
	return normalizeEvidenceExportTimes(out), nil
}

func (s *Store) GetAuditExport(ctx context.Context, tenantID, exportID string) (domain.EvidenceExport, error) {
	out, _, err := s.getAuditExportWithBundle(ctx, tenantID, exportID)
	if err != nil {
		return domain.EvidenceExport{}, err
	}
	return normalizeEvidenceExportTimes(out), nil
}

func (s *Store) ListAuditExports(ctx context.Context, tenantID string, limit int) ([]domain.EvidenceExport, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, state, COALESCE(from_time, 'epoch'::timestamptz), COALESCE(to_time, 'epoch'::timestamptz),
			include_raw_payloads, include_timelines, include_payload_bodies, format, storage_backend, object_bucket, object_key, sha256,
			manifest_sha256, size_bytes, error, created_by, created_at, COALESCE(completed_at, 'epoch'::timestamptz)
		FROM evidence_exports
		WHERE tenant_id=$1
		ORDER BY created_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.EvidenceExport
	for rows.Next() {
		var item domain.EvidenceExport
		if err := rows.Scan(&item.ID, &item.TenantID, &item.State, &item.From, &item.To, &item.IncludeRawPayloads, &item.IncludeTimelines, &item.IncludePayloadBodies,
			&item.Format, &item.StorageBackend, &item.ObjectBucket, &item.ObjectKey, &item.SHA256, &item.ManifestSHA256,
			&item.SizeBytes, &item.Error, &item.CreatedBy, &item.CreatedAt, &item.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, normalizeEvidenceExportTimes(item))
	}
	return out, rows.Err()
}

func (s *Store) DownloadAuditExport(ctx context.Context, tenantID, exportID, actorID string) (app.EvidenceExportDownload, error) {
	out, body, err := s.getAuditExportWithBundle(ctx, tenantID, exportID)
	if err != nil {
		return app.EvidenceExportDownload{}, err
	}
	if out.State != domain.EvidenceExportStateReady {
		return app.EvidenceExportDownload{}, app.ErrGone
	}
	if out.StorageBackend == domain.RawStorageS3 {
		if s.objectStore == nil {
			return app.EvidenceExportDownload{}, errors.New("object store is not configured")
		}
		body, err = s.objectStore.Get(ctx, out.ObjectBucket, out.ObjectKey)
		if err != nil {
			if errors.Is(err, blobstore.ErrNotFound) {
				return app.EvidenceExportDownload{}, app.ErrGone
			}
			return app.EvidenceExportDownload{}, errObjectStoreReadFailed
		}
	}
	if len(body) == 0 {
		return app.EvidenceExportDownload{}, app.ErrGone
	}
	if evidence.SHA256(body) != out.SHA256 {
		return app.EvidenceExportDownload{}, errors.New("audit export bundle hash mismatch")
	}
	if err := s.recordAuditEvent(ctx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "audit_export.downloaded", Resource: "audit_export", ResourceID: exportID}); err != nil {
		return app.EvidenceExportDownload{}, err
	}
	out = normalizeEvidenceExportTimes(out)
	return app.EvidenceExportDownload{
		Export:      out,
		Filename:    exportID + ".tar.gz",
		ContentType: "application/gzip",
		Body:        body,
	}, nil
}

func (s *Store) ApplyRetentionPolicies(ctx context.Context, workerID string, limit int) error {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, resource_type, source_id, retention_days, state, legal_hold, hold_reason, created_by, created_at, updated_at
		FROM retention_policies
		WHERE state='active' AND legal_hold=false
		ORDER BY updated_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		policy, err := scanRetentionPolicy(rows)
		if err != nil {
			return err
		}
		if err := s.applyRetentionPolicy(ctx, workerID, policy); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) ListDeadLetter(ctx context.Context, tenantID string, limit int) ([]map[string]any, error) {
	return listRows(ctx, s.pool, `SELECT id, delivery_id, event_id, reason, state, created_at FROM dead_letter_entries WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
}

func (s *Store) ReleaseDeadLetter(ctx context.Context, tenantID, entryID, actorID, reasonCode, reason string) (app.ReplayJob, error) {
	var deliveryID, eventID string
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(delivery_id,''), COALESCE(event_id,'') FROM dead_letter_entries WHERE tenant_id=$1 AND id=$2 AND state='open'`, tenantID, entryID).Scan(&deliveryID, &eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ReplayJob{}, app.ErrNotFound
	}
	if err != nil {
		return app.ReplayJob{}, err
	}
	req := app.ReplayRequest{DeliveryID: deliveryID, EventID: eventID, ReasonCode: reasonCode, Reason: reason}
	job, err := s.CreateReplay(ctx, tenantID, actorID, req)
	if err != nil {
		return app.ReplayJob{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.ReplayJob{}, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, `UPDATE dead_letter_entries SET state='released' WHERE tenant_id=$1 AND id=$2`, tenantID, entryID); err != nil {
		return app.ReplayJob{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "dead_letter.released", Resource: "dead_letter_entry", ResourceID: entryID, Reason: reason}); err != nil {
		return app.ReplayJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.ReplayJob{}, err
	}
	return job, nil
}

func (s *Store) BulkReleaseDeadLetter(ctx context.Context, tenantID string, entryIDs []string, actorID, reasonCode, reason string) ([]app.ReplayJob, error) {
	if len(entryIDs) == 0 {
		rows, err := s.pool.Query(ctx, `SELECT id FROM dead_letter_entries WHERE tenant_id=$1 AND state='open' ORDER BY created_at ASC LIMIT 100`, tenantID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			entryIDs = append(entryIDs, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	jobs := make([]app.ReplayJob, 0, len(entryIDs))
	for _, entryID := range entryIDs {
		job, err := s.ReleaseDeadLetter(ctx, tenantID, entryID, actorID, reasonCode, reason)
		if err != nil {
			return jobs, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (s *Store) ListQuarantine(ctx context.Context, tenantID string, limit int) ([]map[string]any, error) {
	return listRows(ctx, s.pool, `SELECT id, event_id, reason, state, created_at FROM quarantine_entries WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
}

func (s *Store) ApproveQuarantine(ctx context.Context, tenantID, entryID, actorID, reason string, routeAfterRelease bool) (map[string]any, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	var eventID string
	err = tx.QueryRow(ctx, `UPDATE quarantine_entries SET state='approved' WHERE tenant_id=$1 AND id=$2 AND state='open' RETURNING COALESCE(event_id,'')`, tenantID, entryID).Scan(&eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, app.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "quarantine.approved", Resource: "quarantine_entry", ResourceID: entryID, Reason: reason}); err != nil {
		return nil, err
	}
	if routeAfterRelease && eventID != "" {
		payload, _ := json.Marshal(map[string]any{"event_id": eventID, "allow_recovered": false})
		if _, err := tx.Exec(ctx, `INSERT INTO outbox(id, tenant_id, kind, resource_id, payload) VALUES($1,$2,$3,$4,$5)`, mustID("out"), tenantID, app.OutboxKindRouteEvent, eventID, payload); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"id": entryID, "event_id": eventID, "state": "approved"}, nil
}

func (s *Store) RejectQuarantine(ctx context.Context, tenantID, entryID, actorID, reason string) (map[string]any, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	var eventID string
	err = tx.QueryRow(ctx, `UPDATE quarantine_entries SET state='rejected' WHERE tenant_id=$1 AND id=$2 AND state='open' RETURNING COALESCE(event_id,'')`, tenantID, entryID).Scan(&eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, app.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "quarantine.rejected", Resource: "quarantine_entry", ResourceID: entryID, Reason: reason}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"id": entryID, "event_id": eventID, "state": "rejected"}, nil
}

func (s *Store) DryRunReplay(ctx context.Context, tenantID string, req app.ReplayRequest) (app.ReplayDryRun, error) {
	if req.ConfigMode == "" {
		req.ConfigMode = app.ReplayConfigCurrent
	}
	var count int
	total := 0
	if req.EventID != "" {
		if req.ConfigMode == app.ReplayConfigOriginal {
			if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM deliveries WHERE tenant_id=$1 AND event_id=$2 AND COALESCE(replay_job_id,'')=''`, tenantID, req.EventID).Scan(&count); err != nil {
				return app.ReplayDryRun{}, err
			}
		} else {
			event, err := s.GetEvent(ctx, tenantID, req.EventID)
			if err != nil {
				return app.ReplayDryRun{}, err
			}
			if event.Verified {
				if err := s.pool.QueryRow(ctx, `
					SELECT
						(SELECT count(*) FROM subscriptions s WHERE s.tenant_id=$1 AND s.state='active' AND $2 = ANY(s.event_types)) +
						(SELECT count(*) FROM routes r WHERE r.tenant_id=$1 AND r.source_id=$3 AND r.state='active' AND $2 = ANY(r.event_types))`,
					tenantID, event.Type, event.SourceID,
				).Scan(&count); err != nil {
					return app.ReplayDryRun{}, err
				}
			}
		}
		total += count
	}
	if req.DeliveryID != "" {
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM deliveries WHERE tenant_id=$1 AND id=$2`, tenantID, req.DeliveryID).Scan(&count); err != nil {
			return app.ReplayDryRun{}, err
		}
		total += count
	}
	var warnings []string
	if req.ConfigMode == app.ReplayConfigOriginal && req.EventID != "" && total == 0 {
		warnings = append(warnings, "original config event replay found no original delivery decisions")
	}
	if req.ConfigMode == app.ReplayConfigOriginal && req.EventID != "" {
		var deletedPayloads int
		if err := s.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM deliveries d
			JOIN delivery_payloads p ON p.tenant_id=d.tenant_id AND p.id=d.delivery_payload_id
			WHERE d.tenant_id=$1
			  AND d.event_id=$2
			  AND COALESCE(d.replay_job_id,'')=''
			  AND p.storage_status <> 'stored'`, tenantID, req.EventID).Scan(&deletedPayloads); err != nil {
			return app.ReplayDryRun{}, err
		}
		if deletedPayloads > 0 {
			warnings = append(warnings, "original config replay includes delivery payload bodies deleted by retention")
		}
	}
	if req.DeliveryID != "" {
		var deletedPayloads int
		if err := s.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM deliveries d
			JOIN delivery_payloads p ON p.tenant_id=d.tenant_id AND p.id=d.delivery_payload_id
			WHERE d.tenant_id=$1 AND d.id=$2 AND p.storage_status <> 'stored'`, tenantID, req.DeliveryID).Scan(&deletedPayloads); err != nil {
			return app.ReplayDryRun{}, err
		}
		if deletedPayloads > 0 {
			warnings = append(warnings, "selected delivery payload body was deleted by retention")
		}
	}
	if req.RateLimitPerMinute > 0 {
		warnings = append(warnings, "rate limit applies to replay scheduling and does not change live delivery priority")
	}
	return app.ReplayDryRun{WouldReplayEvents: total, WouldCreateDeliveries: total, Warnings: warnings}, nil
}

const replayJobSelectSQL = `SELECT id, state, scope_hash, COALESCE(reason_code,'operator_requested'), reason, config_mode, rate_limit_per_minute, total_items, processed_items, failed_items, approval_required, COALESCE(approved_by,''), approved_at, created_by, created_at FROM replay_jobs`

type replayJobScanner interface {
	Scan(dest ...any) error
}

func scanReplayJob(scanner replayJobScanner) (app.ReplayJob, error) {
	var item app.ReplayJob
	var approvedAt sql.NullTime
	var createdAt time.Time
	if err := scanner.Scan(&item.ID, &item.State, &item.ScopeHash, &item.ReasonCode, &item.Reason, &item.ConfigMode, &item.RateLimitPerMinute, &item.TotalItems, &item.ProcessedItems, &item.FailedItems, &item.ApprovalRequired, &item.ApprovedBy, &approvedAt, &item.CreatedBy, &createdAt); err != nil {
		return app.ReplayJob{}, err
	}
	if approvedAt.Valid {
		t := approvedAt.Time.UTC()
		item.ApprovedAt = &t
	}
	created := createdAt.UTC()
	item.CreatedAt = &created
	return item, nil
}

func (s *Store) CreateReplay(ctx context.Context, tenantID, actorID string, req app.ReplayRequest) (app.ReplayJob, error) {
	if req.ConfigMode == "" {
		req.ConfigMode = app.ReplayConfigCurrent
	}
	req.ReasonCode = strings.TrimSpace(req.ReasonCode)
	if req.ReasonCode == "" {
		req.ReasonCode = app.ReplayReasonOperatorRequested
	}
	req.Reason = strings.TrimSpace(req.Reason)
	id := mustID("rpl")
	scopeBytes, _ := json.Marshal(req)
	scopeHash := domain.HashSHA256(scopeBytes)
	dryRun, err := s.DryRunReplay(ctx, tenantID, req)
	if err != nil {
		return app.ReplayJob{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.ReplayJob{}, err
	}
	defer rollback(ctx, tx)
	state := "scheduled"
	if req.RequireApproval {
		state = "pending_approval"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO replay_jobs(id, tenant_id, state, scope_hash, scope_json, reason_code, reason, created_by, total_items, config_mode, rate_limit_per_minute, approval_required) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, id, tenantID, state, scopeHash, scopeBytes, req.ReasonCode, req.Reason, actorID, dryRun.WouldCreateDeliveries, req.ConfigMode, req.RateLimitPerMinute, req.RequireApproval); err != nil {
		return app.ReplayJob{}, err
	}
	if !req.RequireApproval {
		if _, err := tx.Exec(ctx, `INSERT INTO outbox(id, tenant_id, kind, resource_id, payload) VALUES($1,$2,$3,$4,$5)`, mustID("out"), tenantID, app.OutboxKindReplayJob, id, scopeBytes); err != nil {
			return app.ReplayJob{}, err
		}
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "replay.created", Resource: "replay_job", ResourceID: id, Reason: replayAuditReason(req)}); err != nil {
		return app.ReplayJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.ReplayJob{}, err
	}
	return app.ReplayJob{ID: id, State: state, ScopeHash: scopeHash, ReasonCode: req.ReasonCode, Reason: req.Reason, ConfigMode: req.ConfigMode, RateLimitPerMinute: req.RateLimitPerMinute, TotalItems: dryRun.WouldCreateDeliveries, ApprovalRequired: req.RequireApproval, CreatedBy: actorID}, nil
}

func (s *Store) ListReplayJobs(ctx context.Context, tenantID string, limit int) ([]app.ReplayJob, error) {
	rows, err := s.pool.Query(ctx, replayJobSelectSQL+` WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.ReplayJob
	for rows.Next() {
		item, err := scanReplayJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func replayAuditReason(req app.ReplayRequest) string {
	parts := []string{
		"reason_code=" + req.ReasonCode,
		"reason=" + req.Reason,
		"config_mode=" + req.ConfigMode,
	}
	if req.EventID != "" {
		parts = append(parts, "event_id="+req.EventID)
	}
	if req.DeliveryID != "" {
		parts = append(parts, "delivery_id="+req.DeliveryID)
	}
	if req.EndpointID != "" {
		parts = append(parts, "endpoint_id="+req.EndpointID)
	}
	if req.RequireApproval {
		parts = append(parts, "approval_required=true")
	}
	if req.RateLimitPerMinute > 0 {
		parts = append(parts, "rate_limit_per_minute="+strconv.Itoa(req.RateLimitPerMinute))
	}
	return strings.Join(parts, " ")
}

func (s *Store) ApproveReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (app.ReplayJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.ReplayJob{}, err
	}
	defer rollback(ctx, tx)

	var scopeBytes []byte
	err = tx.QueryRow(ctx, `SELECT scope_json FROM replay_jobs WHERE tenant_id=$1 AND id=$2 AND state='pending_approval' AND approval_required=true FOR UPDATE`, tenantID, replayJobID).Scan(&scopeBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ReplayJob{}, app.ErrNotFound
	}
	if err != nil {
		return app.ReplayJob{}, err
	}
	item, err := scanReplayJob(tx.QueryRow(ctx, `
		UPDATE replay_jobs
		SET state='scheduled', approved_by=$1, approved_at=now(), approval_reason=$2
		WHERE tenant_id=$3 AND id=$4 AND state='pending_approval' AND approval_required=true
		RETURNING id, state, scope_hash, COALESCE(reason_code,'operator_requested'), reason, config_mode, rate_limit_per_minute, total_items, processed_items, failed_items, approval_required, COALESCE(approved_by,''), approved_at, created_by, created_at`,
		actorID, reason, tenantID, replayJobID,
	))
	if err != nil {
		return app.ReplayJob{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO outbox(id, tenant_id, kind, resource_id, payload) VALUES($1,$2,$3,$4,$5)`, mustID("out"), tenantID, app.OutboxKindReplayJob, replayJobID, scopeBytes); err != nil {
		return app.ReplayJob{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: "replay.approved", Resource: "replay_job", ResourceID: replayJobID, Reason: reason}); err != nil {
		return app.ReplayJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.ReplayJob{}, err
	}
	return item, nil
}

func (s *Store) PauseReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (app.ReplayJob, error) {
	return s.updateReplayState(ctx, tenantID, replayJobID, actorID, reason, "paused", "replay.paused")
}

func (s *Store) ResumeReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (app.ReplayJob, error) {
	return s.updateReplayState(ctx, tenantID, replayJobID, actorID, reason, "scheduled", "replay.resumed")
}

func (s *Store) CancelReplayJob(ctx context.Context, tenantID, replayJobID, actorID, reason string) (app.ReplayJob, error) {
	return s.updateReplayState(ctx, tenantID, replayJobID, actorID, reason, "canceled", "replay.canceled")
}

func (s *Store) updateReplayState(ctx context.Context, tenantID, replayJobID, actorID, reason, state, action string) (app.ReplayJob, error) {
	extra := ""
	if state == "paused" {
		extra = ", paused_at=now()"
	}
	if state == "canceled" {
		extra = ", canceled_at=now()"
	}
	stateGuard := "state NOT IN ('completed','canceled')"
	if state == "scheduled" {
		stateGuard = "state NOT IN ('completed','canceled','pending_approval')"
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.ReplayJob{}, err
	}
	defer rollback(ctx, tx)
	item, err := scanReplayJob(tx.QueryRow(ctx, `UPDATE replay_jobs SET state=$1`+extra+` WHERE tenant_id=$2 AND id=$3 AND `+stateGuard+` RETURNING id, state, scope_hash, COALESCE(reason_code,'operator_requested'), reason, config_mode, rate_limit_per_minute, total_items, processed_items, failed_items, approval_required, COALESCE(approved_by,''), approved_at, created_by, created_at`, state, tenantID, replayJobID))
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ReplayJob{}, app.ErrNotFound
	}
	if err != nil {
		return app.ReplayJob{}, err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: tenantID, ActorID: actorID, Action: action, Resource: "replay_job", ResourceID: replayJobID, Reason: reason}); err != nil {
		return app.ReplayJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.ReplayJob{}, err
	}
	return item, nil
}

func (s *Store) ClaimOutbox(ctx context.Context, workerID string, limit int) ([]worker.OutboxItem, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	if err := upsertWorkerLease(ctx, tx, workerID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE outbox SET state='pending', locked_by=NULL, lock_expires_at=NULL WHERE state='in_progress' AND lock_expires_at <= now()`); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		WITH candidates AS (
			SELECT id, tenant_id, available_at,
			       CASE kind WHEN 'route_event' THEN 0 WHEN 'route_recovered_event' THEN 0 WHEN 'replay_job' THEN 1 ELSE 2 END AS priority
			FROM outbox
			WHERE state='pending' AND available_at <= now()
		),
		ranked AS (
			SELECT id, tenant_id, available_at, priority,
			       row_number() OVER (PARTITION BY priority, tenant_id ORDER BY available_at ASC, id ASC) AS tenant_rank
			FROM candidates
		),
		claimed AS (
			SELECT o.id
			FROM outbox o
			JOIN ranked r ON r.id=o.id
			WHERE o.state='pending' AND o.available_at <= now()
			ORDER BY r.priority ASC, r.tenant_rank ASC, r.available_at ASC, r.tenant_id ASC, r.id ASC
			LIMIT $2
			FOR UPDATE OF o SKIP LOCKED
		)
		UPDATE outbox o
		SET state='in_progress', locked_by=$1, lock_expires_at=now() + interval '60 seconds'
		FROM claimed
		WHERE o.id=claimed.id
		RETURNING o.id, o.tenant_id, o.kind, o.resource_id`, workerID, limit)
	if err != nil {
		return nil, err
	}
	var out []worker.OutboxItem
	for rows.Next() {
		var item worker.OutboxItem
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Kind, &item.ResourceID); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) CompleteOutbox(ctx context.Context, outboxID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE outbox SET state='completed', locked_by=NULL, lock_expires_at=NULL WHERE id=$1`, outboxID)
	return err
}

func (s *Store) enqueueRouteEvent(ctx context.Context, tenantID, eventID string, allowRecovered bool) error {
	kind := app.OutboxKindRouteEvent
	if allowRecovered {
		kind = app.OutboxKindRouteRecoveredEvent
	}
	payload, _ := json.Marshal(map[string]any{"event_id": eventID, "allow_recovered": allowRecovered})
	_, err := s.pool.Exec(ctx, `INSERT INTO outbox(id, tenant_id, kind, resource_id, payload) VALUES($1,$2,$3,$4,$5)`, mustID("out"), tenantID, kind, eventID, payload)
	return err
}

func (s *Store) ListDeliveryFanoutTargets(ctx context.Context, tenantID, sourceID, eventType string) ([]app.DeliveryFanoutTarget, error) {
	subRows, err := s.pool.Query(ctx, `
		SELECT s.id, s.endpoint_id, s.active_version_id, COALESCE(NULLIF(e.retry_policy_id,''),''), COALESCE(NULLIF(s.transformation_version_id,''),'')
		FROM subscriptions s
		JOIN endpoints e ON e.tenant_id=s.tenant_id AND e.id=s.endpoint_id
		WHERE s.tenant_id=$1 AND s.state='active' AND $2 = ANY(s.event_types)`, tenantID, eventType)
	if err != nil {
		return nil, err
	}
	var out []app.DeliveryFanoutTarget
	for subRows.Next() {
		var target app.DeliveryFanoutTarget
		if err := subRows.Scan(&target.SubscriptionID, &target.EndpointID, &target.SubscriptionVersionID, &target.EndpointRetryPolicyID, &target.TransformationVersionID); err != nil {
			subRows.Close()
			return nil, err
		}
		out = append(out, target)
	}
	subRows.Close()
	if err := subRows.Err(); err != nil {
		return nil, err
	}
	routeRows, err := s.pool.Query(ctx, `
		SELECT r.id, r.endpoint_id, r.active_version_id, COALESCE(NULLIF(r.retry_policy_id,''),''), COALESCE(NULLIF(e.retry_policy_id,''),''), COALESCE(NULLIF(r.transformation_version_id,''),'')
		FROM routes r
		JOIN endpoints e ON e.tenant_id=r.tenant_id AND e.id=r.endpoint_id
		WHERE r.tenant_id=$1 AND r.source_id=$2 AND r.state='active' AND $3 = ANY(r.event_types)
		ORDER BY r.priority ASC`, tenantID, sourceID, eventType)
	if err != nil {
		return nil, err
	}
	defer routeRows.Close()
	for routeRows.Next() {
		var target app.DeliveryFanoutTarget
		if err := routeRows.Scan(&target.RouteID, &target.EndpointID, &target.RouteVersionID, &target.RouteRetryPolicyID, &target.EndpointRetryPolicyID, &target.TransformationVersionID); err != nil {
			return nil, err
		}
		out = append(out, target)
	}
	return out, routeRows.Err()
}

func (s *Store) CreateDeliverySnapshot(ctx context.Context, req app.DeliverySnapshotRequest) (app.DeliverySnapshotResult, error) {
	deliveryID := mustID("del")
	retrySeed := req.RetrySeed
	if retrySeed == "" {
		retrySeed = deliveryRetrySeed(req.TenantID, deliveryID, req.EventID, req.EndpointID)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.DeliverySnapshotResult{}, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO deliveries(id, tenant_id, event_id, endpoint_id, route_id, route_version_id, subscription_id, subscription_version_id, retry_policy_id, replay_job_id, adapter_version_id, normalized_envelope_id, transformation_version_id, retry_seed, state, next_attempt_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'scheduled',$15)`,
		deliveryID, req.TenantID, req.EventID, req.EndpointID, req.RouteID, req.RouteVersionID,
		req.SubscriptionID, req.SubscriptionVersionID, req.RetryPolicyID, req.ReplayJobID,
		req.AdapterVersionID, req.NormalizedEnvelopeID, req.TransformationVersionID, retrySeed, req.NextAttemptAt,
	); err != nil {
		return app.DeliverySnapshotResult{}, err
	}
	var payloadID, normalizedID, adapterVersionID, transformationVersionID string
	switch req.DeliveryPayloadMode {
	case app.DeliveryPayloadClone:
		payloadID, normalizedID, adapterVersionID, transformationVersionID, err = s.cloneDeliveryPayload(ctx, tx, req.TenantID, req.SourceDeliveryPayloadID, deliveryID)
	default:
		payloadID, normalizedID, adapterVersionID, err = s.createDeliveryPayload(ctx, tx, req.TenantID, req.EventID, deliveryID, req.TransformationVersionID)
		transformationVersionID = req.TransformationVersionID
	}
	if err != nil {
		return app.DeliverySnapshotResult{}, err
	}
	payloadHash, err := s.deliveryPayloadSHA256(ctx, tx, req.TenantID, payloadID)
	if err != nil {
		return app.DeliverySnapshotResult{}, err
	}
	result := app.DeliverySnapshotResult{
		DeliveryID:              deliveryID,
		DeliveryPayloadID:       payloadID,
		DeliveryPayloadSHA256:   payloadHash,
		AdapterVersionID:        adapterVersionID,
		NormalizedEnvelopeID:    normalizedID,
		TransformationVersionID: transformationVersionID,
	}
	if req.ReplayJobID != "" {
		if err := insertReplayDecisionEvidence(ctx, tx, app.ReplayDecisionEvidence{
			TenantID: req.TenantID, ReplayJobID: req.ReplayJobID, EventID: req.EventID,
			OriginalDeliveryID: req.OriginalDeliveryID, NewDeliveryID: result.DeliveryID, ConfigMode: req.ConfigMode,
			RouteVersionID: req.RouteVersionID, SubscriptionVersionID: req.SubscriptionVersionID, RetryPolicyID: req.RetryPolicyID,
			AdapterVersionID: result.AdapterVersionID, NormalizedEnvelopeID: result.NormalizedEnvelopeID,
			TransformationVersionID: result.TransformationVersionID, DeliveryPayloadID: result.DeliveryPayloadID, DeliveryPayloadSHA256: result.DeliveryPayloadSHA256,
		}); err != nil {
			return app.DeliverySnapshotResult{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return app.DeliverySnapshotResult{}, err
	}
	return result, nil
}

func (s *Store) GetReplayJobWork(ctx context.Context, tenantID, replayJobID string) (app.ReplayJobWork, error) {
	var work app.ReplayJobWork
	var scopeBytes []byte
	err := s.pool.QueryRow(ctx, `SELECT scope_json, state, config_mode, rate_limit_per_minute FROM replay_jobs WHERE tenant_id=$1 AND id=$2`, tenantID, replayJobID).
		Scan(&scopeBytes, &work.State, &work.ConfigMode, &work.RateLimitPerMinute)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ReplayJobWork{}, app.ErrNotFound
	}
	if err != nil {
		return app.ReplayJobWork{}, err
	}
	if err := json.Unmarshal(scopeBytes, &work.Request); err != nil {
		return app.ReplayJobWork{}, err
	}
	if work.Request.ConfigMode == "" {
		work.Request.ConfigMode = work.ConfigMode
	}
	if work.Request.RateLimitPerMinute == 0 {
		work.Request.RateLimitPerMinute = work.RateLimitPerMinute
	}
	return work, nil
}

func (s *Store) StartReplayJob(ctx context.Context, tenantID, replayJobID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE replay_jobs SET state='running' WHERE tenant_id=$1 AND id=$2 AND state='scheduled'`, tenantID, replayJobID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) ListOriginalDeliveryReplaySources(ctx context.Context, tenantID, eventID string) ([]app.DeliveryReplaySource, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, event_id, endpoint_id, COALESCE(route_id,''), COALESCE(route_version_id,''), COALESCE(subscription_id,''), COALESCE(subscription_version_id,''), COALESCE(retry_policy_id,''), COALESCE(adapter_version_id,''), COALESCE(normalized_envelope_id,''), COALESCE(transformation_version_id,''), COALESCE(delivery_payload_id,'')
		FROM deliveries
		WHERE tenant_id=$1
		  AND event_id=$2
		  AND COALESCE(replay_job_id,'') = ''
		ORDER BY created_at ASC, id ASC`,
		tenantID, eventID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.DeliveryReplaySource
	for rows.Next() {
		var item app.DeliveryReplaySource
		if err := rows.Scan(&item.ID, &item.EventID, &item.EndpointID, &item.RouteID, &item.RouteVersionID, &item.SubscriptionID, &item.SubscriptionVersionID, &item.RetryPolicyID, &item.AdapterVersionID, &item.NormalizedEnvelopeID, &item.TransformationVersionID, &item.DeliveryPayloadID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetDeliveryReplaySource(ctx context.Context, tenantID, deliveryID string) (app.DeliveryReplaySource, error) {
	var item app.DeliveryReplaySource
	err := s.pool.QueryRow(ctx, `
		SELECT id, event_id, endpoint_id, COALESCE(route_id,''), COALESCE(route_version_id,''), COALESCE(subscription_id,''), COALESCE(subscription_version_id,''), COALESCE(retry_policy_id,''), COALESCE(adapter_version_id,''), COALESCE(normalized_envelope_id,''), COALESCE(transformation_version_id,''), COALESCE(delivery_payload_id,'')
		FROM deliveries
		WHERE tenant_id=$1 AND id=$2`, tenantID, deliveryID).
		Scan(&item.ID, &item.EventID, &item.EndpointID, &item.RouteID, &item.RouteVersionID, &item.SubscriptionID, &item.SubscriptionVersionID, &item.RetryPolicyID, &item.AdapterVersionID, &item.NormalizedEnvelopeID, &item.TransformationVersionID, &item.DeliveryPayloadID)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.DeliveryReplaySource{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) GetCurrentDeliveryFanoutTarget(ctx context.Context, tenantID, routeID, subscriptionID string) (app.DeliveryFanoutTarget, bool, error) {
	var target app.DeliveryFanoutTarget
	if routeID != "" {
		err := s.pool.QueryRow(ctx, `
			SELECT r.id, r.endpoint_id, r.active_version_id,
			       COALESCE(NULLIF(r.retry_policy_id,''), ''),
			       COALESCE(NULLIF(e.retry_policy_id,''), ''),
			       COALESCE(NULLIF(r.transformation_version_id,''),'')
			FROM routes r
			JOIN endpoints e ON e.tenant_id=r.tenant_id AND e.id=r.endpoint_id
			WHERE r.tenant_id=$1 AND r.id=$2 AND r.state='active'`,
			tenantID, routeID,
		).Scan(&target.RouteID, &target.EndpointID, &target.RouteVersionID, &target.RouteRetryPolicyID, &target.EndpointRetryPolicyID, &target.TransformationVersionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return app.DeliveryFanoutTarget{}, false, nil
		}
		return target, err == nil, err
	}
	if subscriptionID != "" {
		err := s.pool.QueryRow(ctx, `
			SELECT s.id, s.endpoint_id, s.active_version_id,
			       COALESCE(NULLIF(e.retry_policy_id,''), ''),
			       COALESCE(NULLIF(s.transformation_version_id,''),'')
			FROM subscriptions s
			JOIN endpoints e ON e.tenant_id=s.tenant_id AND e.id=s.endpoint_id
			WHERE s.tenant_id=$1 AND s.id=$2 AND s.state='active'`,
			tenantID, subscriptionID,
		).Scan(&target.SubscriptionID, &target.EndpointID, &target.SubscriptionVersionID, &target.EndpointRetryPolicyID, &target.TransformationVersionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return app.DeliveryFanoutTarget{}, false, nil
		}
		return target, err == nil, err
	}
	return target, true, nil
}

func (s *Store) InsertReplayNoopItem(ctx context.Context, tenantID, replayJobID, eventID, configMode, errorText string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO replay_items(id, tenant_id, replay_job_id, event_id, state, config_mode, error, completed_at)
		VALUES($1,$2,$3,$4,'completed',$5,$6,now())`,
		mustID("rpi"), tenantID, replayJobID, eventID, configMode, errorText)
	return err
}

func (s *Store) CompleteReplayJob(ctx context.Context, tenantID, replayJobID string, processedItems int) error {
	_, err := s.pool.Exec(ctx, `UPDATE replay_jobs SET state='completed', processed_items=$3, completed_at=now() WHERE tenant_id=$1 AND id=$2 AND state <> 'canceled'`, tenantID, replayJobID, processedItems)
	return err
}

func (s *Store) GetReconciliationConnection(ctx context.Context, tenantID, connectionID string) (domain.ProviderConnection, string, error) {
	return s.getProviderConnectionSecret(ctx, tenantID, connectionID)
}

func (s *Store) GetReconciliationWork(ctx context.Context, tenantID, jobID string) (app.ReconciliationWork, error) {
	job, err := scanReconciliationJob(s.pool.QueryRow(ctx, reconciliationJobSelectSQL()+` WHERE tenant_id=$1 AND id=$2`, tenantID, jobID))
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ReconciliationWork{}, app.ErrNotFound
	}
	if err != nil {
		return app.ReconciliationWork{}, err
	}
	conn, credential, err := s.getProviderConnectionSecret(ctx, tenantID, job.ConnectionID)
	if err != nil {
		return app.ReconciliationWork{}, err
	}
	return app.ReconciliationWork{Job: normalizeReconciliationJob(job), Connection: conn, Credential: credential}, nil
}

func (s *Store) StartReconciliationJob(ctx context.Context, tenantID, jobID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE reconciliation_jobs SET state='running', started_at=COALESCE(started_at, now()) WHERE tenant_id=$1 AND id=$2 AND state='scheduled'`, tenantID, jobID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) RecordProviderAPIEvidence(ctx context.Context, record app.ProviderAPIEvidenceRecord) (string, error) {
	return s.insertProviderAPIEvidence(ctx, record.TenantID, record.JobID, record.ItemID, record.ConnectionID, record.Provider, reconcile.Evidence{
		Method: record.Evidence.Method, URL: record.Evidence.URL, StatusCode: record.Evidence.StatusCode,
		Body: record.Evidence.Body, Error: record.Evidence.Error,
	})
}

func (s *Store) FindLocalProviderEvent(ctx context.Context, tenantID string, conn domain.ProviderConnection, providerObjectID string) (string, error) {
	return s.findLocalProviderEvent(ctx, tenantID, conn, providerObjectID)
}

func (s *Store) InsertReconciliationItem(ctx context.Context, input app.ReconciliationItemRecord) (string, error) {
	return s.insertReconciliationItem(ctx, reconciliationItemInput{
		tenantID: input.TenantID, jobID: input.JobID, provider: input.Provider, objectID: input.ObjectID, objectType: input.ObjectType,
		outcome: input.Outcome, localEventID: input.LocalEventID, recoveredEventID: input.RecoveredEventID, evidenceID: input.EvidenceID,
		redeliveryRequested: input.RedeliveryRequested, errText: input.Error, metadata: input.Metadata,
	})
}

func (s *Store) AttachProviderEvidenceToItem(ctx context.Context, tenantID, itemID, evidenceID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE provider_api_evidence SET item_id=$1 WHERE tenant_id=$2 AND id=$3`, itemID, tenantID, evidenceID)
	return err
}

func (s *Store) UpdateReconciliationCursor(ctx context.Context, tenantID, jobID, cursor string) error {
	_, err := s.pool.Exec(ctx, `UPDATE reconciliation_jobs SET cursor=$1 WHERE tenant_id=$2 AND id=$3`, cursor, tenantID, jobID)
	return err
}

func (s *Store) CompleteReconciliationJob(ctx context.Context, tenantID, jobID string) error {
	return s.completeReconciliationJob(ctx, tenantID, jobID)
}

func (s *Store) FailReconciliationJob(ctx context.Context, tenantID, jobID, errorText string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE reconciliation_jobs
		SET state='failed', error=$3, completed_at=now()
		WHERE tenant_id=$1 AND id=$2 AND state <> 'canceled'`,
		tenantID, jobID, errorText,
	)
	return err
}

func (s *Store) createDeliveryPayload(ctx context.Context, tx pgx.Tx, tenantID, eventID, deliveryID, transformationVersionID string) (payloadID, normalizedID, adapterVersionID string, err error) {
	var envelope, data []byte
	var storageStatus string
	err = tx.QueryRow(ctx, `
		SELECT id, adapter_version_id, envelope_json, data_json, storage_status
		FROM normalized_envelopes
		WHERE tenant_id=$1 AND event_id=$2`,
		tenantID, eventID,
	).Scan(&normalizedID, &adapterVersionID, &envelope, &data, &storageStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		envelope, err = s.legacyDeliveryEnvelope(ctx, tx, tenantID, eventID)
		if err != nil {
			return "", "", "", err
		}
	} else if err != nil {
		return "", "", "", err
	} else if storageStatus == domain.StorageStatusDeleted {
		return "", "", "", app.ErrGone
	}
	body := envelope
	if transformationVersionID != "" {
		var operations []byte
		if err := tx.QueryRow(ctx, `SELECT operations_json FROM transformation_versions WHERE tenant_id=$1 AND id=$2`, tenantID, transformationVersionID).Scan(&operations); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return "", "", "", app.ErrNotFound
			}
			return "", "", "", err
		}
		ops, err := transform.ParseOperations(operations)
		if err != nil {
			return "", "", "", err
		}
		body, err = transform.Apply(body, ops)
		if err != nil {
			return "", "", "", err
		}
	}
	payloadID = mustID("dpl")
	hash := domain.HashSHA256(body)
	if _, err := tx.Exec(ctx, `
		INSERT INTO delivery_payloads(id, tenant_id, delivery_id, event_id, normalized_envelope_id, transformation_version_id, content_type, sha256, size_bytes, body, storage_status)
		VALUES($1,$2,$3,$4,$5,$6,'application/json',$7,$8,$9,$10)`,
		payloadID, tenantID, deliveryID, eventID, normalizedID, transformationVersionID, hash, int64(len(body)), body, domain.StorageStatusStored,
	); err != nil {
		return "", "", "", err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE deliveries
		SET adapter_version_id=$1, normalized_envelope_id=$2, transformation_version_id=$3, delivery_payload_id=$4
		WHERE tenant_id=$5 AND id=$6`,
		adapterVersionID, normalizedID, transformationVersionID, payloadID, tenantID, deliveryID,
	); err != nil {
		return "", "", "", err
	}
	_ = data
	return payloadID, normalizedID, adapterVersionID, nil
}

func (s *Store) CaptureRecoveredProviderEvent(ctx context.Context, input app.RecoveredProviderEventCapture) (string, error) {
	conn := input.Connection
	sourceID := strings.TrimSpace(conn.Config["source_id"])
	if sourceID == "" {
		return "", errors.New("provider connection config source_id is required for recovered capture")
	}
	var source domain.Source
	err := s.pool.QueryRow(ctx, `SELECT id, tenant_id, name, provider, adapter, state, created_at FROM sources WHERE tenant_id=$1 AND id=$2 AND state='active'`, conn.TenantID, sourceID).
		Scan(&source.ID, &source.TenantID, &source.Name, &source.Provider, &source.Adapter, &source.State, &source.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", app.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	eventID := mustID("evt")
	rawID := mustID("raw")
	receiptID := mustID("rcp")
	rawHash := domain.HashSHA256(input.RawBody)
	dedupeKey := "reconcile:" + conn.Provider + ":" + source.ID + ":" + input.ObjectID
	raw := domain.RawPayload{
		TenantID:    conn.TenantID,
		SHA256:      rawHash,
		ContentType: "application/json",
		SizeBytes:   int64(len(input.RawBody)),
		Body:        append([]byte(nil), input.RawBody...),
		CreatedAt:   now,
	}
	storage, bodyForDB, err := s.prepareRawPayloadStorage(ctx, conn.TenantID, rawID, raw)
	if err != nil {
		return "", err
	}
	objectWritten := storage.backend == domain.RawStorageS3
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, storage.bucket, storage.key)
		}
		return "", err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO raw_payloads(id, tenant_id, sha256, content_type, size_bytes, body, storage_backend, object_bucket, object_key, storage_status, created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		rawID, conn.TenantID, rawHash, raw.ContentType, raw.SizeBytes, bodyForDB, storage.backend, storage.bucket, storage.key, domain.StorageStatusStored, now,
	); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, storage.bucket, storage.key)
		}
		return "", err
	}
	var existingEventID string
	err = tx.QueryRow(ctx, `SELECT id FROM events WHERE tenant_id=$1 AND dedupe_key=$2`, conn.TenantID, dedupeKey).Scan(&existingEventID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if existingEventID != "" {
		eventID = existingEventID
		if _, err := tx.Exec(ctx, `UPDATE raw_payloads SET event_id=$1 WHERE id=$2`, eventID, rawID); err != nil {
			return "", err
		}
	} else {
		eventType := firstNonEmpty(input.EventType, "unknown")
		if _, err := tx.Exec(ctx, `
			INSERT INTO events(id, tenant_id, source_id, provider, type, provider_event_id, raw_payload_id, raw_payload_hash,
				signature_verified, verification_reason, dedupe_key, dedupe_status, received_at, trace_id)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,false,$9,$10,$11,$12,$13)`,
			eventID, conn.TenantID, source.ID, source.Provider, eventType, input.ObjectID, rawID, rawHash,
			domain.VerificationReasonProviderAPIReconcile, dedupeKey, domain.DedupeUnique, now, "",
		); err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `UPDATE raw_payloads SET event_id=$1 WHERE id=$2`, eventID, rawID); err != nil {
			return "", err
		}
		headers := headerPairsFromMap(input.RequestHeaders)
		normalized, err := provider.Normalize(provider.NormalizeInput{
			Adapter: source.Adapter, Provider: source.Provider, TenantID: conn.TenantID, SourceID: source.ID,
			RawBody: input.RawBody, Headers: domain.CanonicalHeaders(headers), Verified: false,
			VerifyReason: domain.VerificationReasonProviderAPIReconcile, RawHash: rawHash,
		})
		if err == nil {
			adapterVersionID, err := s.lookupAdapterVersionID(ctx, tx, firstNonEmpty(source.Adapter, source.Provider))
			if err != nil {
				return "", err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO normalized_envelopes(id, tenant_id, event_id, adapter_version_id, provider, provider_event_id, type, source, subject,
					envelope_json, data_json, metadata_json, envelope_sha256, data_sha256, metadata_sha256, storage_status, created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13,$14,$15,$16,$17)`,
				mustID("nenv"), conn.TenantID, eventID, adapterVersionID, source.Provider, normalized.ProviderEventID, normalized.Type,
				normalized.Source, normalized.Subject, string(normalized.Envelope), string(normalized.Data), string(normalized.Metadata),
				normalized.EnvelopeHash, normalized.DataHash, normalized.MetadataHash, domain.StorageStatusStored, now,
			); err != nil {
				return "", err
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO idempotency_records(tenant_id, dedupe_key, resource_type, resource_id, status_code)
			VALUES($1,$2,'event',$3,202)
			ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`,
			conn.TenantID, dedupeKey, eventID,
		); err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO dedupe_records(tenant_id, source_id, dedupe_key, first_event_id, last_receipt_id, status)
			VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT (tenant_id, dedupe_key) DO UPDATE
			SET last_receipt_id=EXCLUDED.last_receipt_id, status=EXCLUDED.status, last_seen_at=now()`,
			conn.TenantID, source.ID, dedupeKey, eventID, receiptID, domain.DedupeUnique,
		); err != nil {
			return "", err
		}
	}
	headersJSON, _ := json.Marshal(headerPairsFromMap(input.RequestHeaders))
	if _, err := tx.Exec(ctx, `
		INSERT INTO provider_receipts(id, tenant_id, source_id, event_id, raw_payload_id, raw_headers, remote_ip, verification_ok, verification_reason, received_at)
		VALUES($1,$2,$3,$4,$5,$6,'provider-api',false,$7,$8)`,
		receiptID, conn.TenantID, source.ID, eventID, rawID, headersJSON, domain.VerificationReasonProviderAPIReconcile, now,
	); err != nil {
		return "", err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: conn.TenantID, ActorID: "reconciliation-worker", Action: "reconciliation.event_captured", Resource: "event", ResourceID: eventID, Reason: conn.ID}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(ctx, storage.bucket, storage.key)
		}
		return "", err
	}
	if input.RouteRecovered {
		if err := s.enqueueRouteEvent(ctx, conn.TenantID, eventID, true); err != nil {
			return "", err
		}
	}
	return eventID, nil
}

func (s *Store) cloneDeliveryPayload(ctx context.Context, tx pgx.Tx, tenantID, sourcePayloadID, newDeliveryID string) (payloadID, normalizedID, adapterVersionID, transformationVersionID string, err error) {
	if sourcePayloadID == "" {
		var eventID string
		if err := tx.QueryRow(ctx, `SELECT event_id, COALESCE(transformation_version_id,'') FROM deliveries WHERE tenant_id=$1 AND id=$2`, tenantID, newDeliveryID).Scan(&eventID, &transformationVersionID); err != nil {
			return "", "", "", "", err
		}
		payloadID, normalizedID, adapterVersionID, err = s.createDeliveryPayload(ctx, tx, tenantID, eventID, newDeliveryID, transformationVersionID)
		return payloadID, normalizedID, adapterVersionID, transformationVersionID, err
	}
	var eventID, contentType, hash, storageStatus string
	var size int64
	var body []byte
	err = tx.QueryRow(ctx, `
		SELECT p.event_id, p.normalized_envelope_id, COALESCE(n.adapter_version_id,''), p.transformation_version_id,
		       p.content_type, p.sha256, p.size_bytes, p.body, p.storage_status
		FROM delivery_payloads p
		LEFT JOIN normalized_envelopes n ON n.tenant_id=p.tenant_id AND n.id=p.normalized_envelope_id
		WHERE p.tenant_id=$1 AND p.id=$2`,
		tenantID, sourcePayloadID,
	).Scan(&eventID, &normalizedID, &adapterVersionID, &transformationVersionID, &contentType, &hash, &size, &body, &storageStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", "", app.ErrNotFound
	}
	if err != nil {
		return "", "", "", "", err
	}
	if storageStatus == domain.StorageStatusDeleted {
		return "", "", "", "", app.ErrGone
	}
	payloadID = mustID("dpl")
	if _, err := tx.Exec(ctx, `
		INSERT INTO delivery_payloads(id, tenant_id, delivery_id, event_id, normalized_envelope_id, transformation_version_id, content_type, sha256, size_bytes, body, storage_status)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		payloadID, tenantID, newDeliveryID, eventID, normalizedID, transformationVersionID, contentType, hash, size, body, domain.StorageStatusStored,
	); err != nil {
		return "", "", "", "", err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE deliveries
		SET adapter_version_id=$1, normalized_envelope_id=$2, transformation_version_id=$3, delivery_payload_id=$4
		WHERE tenant_id=$5 AND id=$6`,
		adapterVersionID, normalizedID, transformationVersionID, payloadID, tenantID, newDeliveryID,
	); err != nil {
		return "", "", "", "", err
	}
	return payloadID, normalizedID, adapterVersionID, transformationVersionID, nil
}

func (s *Store) deliveryPayloadSHA256(ctx context.Context, tx pgx.Tx, tenantID, payloadID string) (string, error) {
	if payloadID == "" {
		return "", nil
	}
	var hash string
	err := tx.QueryRow(ctx, `SELECT sha256 FROM delivery_payloads WHERE tenant_id=$1 AND id=$2`, tenantID, payloadID).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", app.ErrNotFound
	}
	return hash, err
}

func (s *Store) legacyDeliveryEnvelope(ctx context.Context, tx pgx.Tx, tenantID, eventID string) ([]byte, error) {
	var eventType, provider, providerEventID, rawPayloadHash string
	err := tx.QueryRow(ctx, `SELECT type, provider, provider_event_id, raw_payload_hash FROM events WHERE tenant_id=$1 AND id=$2`, tenantID, eventID).Scan(&eventType, &provider, &providerEventID, &rawPayloadHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, app.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id":                eventID,
		"type":              eventType,
		"provider":          provider,
		"provider_event_id": providerEventID,
		"raw_payload_hash":  rawPayloadHash,
	})
}

func insertReplayDecisionEvidence(ctx context.Context, tx pgx.Tx, ev app.ReplayDecisionEvidence) error {
	if ev.ConfigMode == "" {
		ev.ConfigMode = app.ReplayConfigCurrent
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO replay_items(id, tenant_id, replay_job_id, event_id, original_delivery_id, new_delivery_id, state, config_mode,
			route_version_id, subscription_version_id, retry_policy_id, adapter_version_id, normalized_envelope_id, transformation_version_id, delivery_payload_id, delivery_payload_sha256, completed_at)
		VALUES($1,$2,$3,$4,$5,$6,'completed',$7,$8,$9,$10,$11,$12,$13,$14,$15,now())`,
		mustID("rpi"), ev.TenantID, ev.ReplayJobID, ev.EventID, ev.OriginalDeliveryID, ev.NewDeliveryID, ev.ConfigMode,
		ev.RouteVersionID, ev.SubscriptionVersionID, ev.RetryPolicyID, ev.AdapterVersionID, ev.NormalizedEnvelopeID, ev.TransformationVersionID, ev.DeliveryPayloadID, ev.DeliveryPayloadSHA256,
	); err != nil {
		return err
	}
	receiptDeliveryID := ev.OriginalDeliveryID
	if receiptDeliveryID == "" {
		receiptDeliveryID = ev.NewDeliveryID
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO replay_receipts(id, tenant_id, replay_job_id, event_id, delivery_id, config_mode,
			route_version_id, subscription_version_id, retry_policy_id, adapter_version_id, normalized_envelope_id, transformation_version_id, delivery_payload_id, delivery_payload_sha256)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		mustID("rrc"), ev.TenantID, ev.ReplayJobID, ev.EventID, receiptDeliveryID, ev.ConfigMode,
		ev.RouteVersionID, ev.SubscriptionVersionID, ev.RetryPolicyID, ev.AdapterVersionID, ev.NormalizedEnvelopeID, ev.TransformationVersionID, ev.DeliveryPayloadID, ev.DeliveryPayloadSHA256,
	)
	return err
}

func (s *Store) ClaimDueDeliveries(ctx context.Context, workerID string, limit int) ([]worker.DeliveryItem, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	if err := upsertWorkerLease(ctx, tx, workerID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE deliveries SET state='scheduled', locked_by=NULL, lock_expires_at=NULL WHERE state='in_progress' AND lock_expires_at <= now()`); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		WITH candidates AS (
			SELECT d.id, d.tenant_id, d.next_attempt_at,
			       (COALESCE(d.replay_job_id,'') <> '') AS is_replay
			FROM deliveries d
			JOIN endpoints e ON e.tenant_id=d.tenant_id AND e.id=d.endpoint_id
			WHERE d.state='scheduled'
			  AND d.next_attempt_at <= now()
			  AND e.state='active'
			  AND (e.disabled_until IS NULL OR e.disabled_until <= now())
		),
		ranked AS (
			SELECT d.id, d.tenant_id, d.next_attempt_at, d.is_replay,
			       row_number() OVER (PARTITION BY is_replay, d.tenant_id ORDER BY d.next_attempt_at ASC, d.id ASC) AS tenant_rank
			FROM candidates d
		),
		claimed AS (
			SELECT d.id
			FROM deliveries d
			JOIN ranked r ON r.id=d.id
			JOIN endpoints e ON e.tenant_id=d.tenant_id AND e.id=d.endpoint_id
			WHERE d.state='scheduled'
			  AND d.next_attempt_at <= now()
			  AND e.state='active'
			  AND (e.disabled_until IS NULL OR e.disabled_until <= now())
			ORDER BY r.is_replay ASC, r.tenant_rank ASC, r.next_attempt_at ASC, r.tenant_id ASC, r.id ASC
			LIMIT $2
			FOR UPDATE OF d SKIP LOCKED
		)
		UPDATE deliveries d
		SET state='in_progress', locked_by=$1, lock_expires_at=now() + interval '60 seconds'
		FROM claimed
		WHERE d.id=claimed.id
		RETURNING d.id, d.tenant_id, d.event_id, d.endpoint_id, d.attempt_count, COALESCE(d.retry_policy_id,''), COALESCE(d.retry_seed,'')`, workerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []worker.DeliveryItem
	for rows.Next() {
		var item worker.DeliveryItem
		if err := rows.Scan(&item.ID, &item.TenantID, &item.EventID, &item.EndpointID, &item.AttemptCount, &item.RetryPolicyID, &item.RetrySeed); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for i := range out {
		if err := s.populateDeliveryItem(ctx, tx, &out[i]); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) populateDeliveryItem(ctx context.Context, tx pgx.Tx, item *worker.DeliveryItem) error {
	var encrypted, encryptedMTLSCert, encryptedMTLSKey []byte
	var mtlsEnabled bool
	var payloadID, payloadRowID, payloadStatus string
	err := tx.QueryRow(ctx, `
		SELECT e.url, es.id, es.version, es.encrypted_secret, e.mtls_enabled,
		       COALESCE(e.encrypted_mtls_client_cert,''::bytea), COALESCE(e.encrypted_mtls_client_key,''::bytea),
		       COALESCE(d.delivery_payload_id,''), COALESCE(p.id,''), COALESCE(p.body,''::bytea), COALESCE(p.storage_status,'')
		FROM deliveries d
		JOIN endpoints e ON e.tenant_id=d.tenant_id AND e.id=d.endpoint_id
		JOIN endpoint_secrets es ON es.tenant_id=e.tenant_id AND es.endpoint_id=e.id AND es.state='active'
		LEFT JOIN delivery_payloads p ON p.tenant_id=d.tenant_id AND p.id=d.delivery_payload_id
		WHERE d.tenant_id=$1 AND d.id=$2
		ORDER BY es.version DESC
		LIMIT 1`,
		item.TenantID, item.ID,
	).Scan(&item.EndpointURL, &item.SigningKeyID, &item.SigningKeyVersion, &encrypted, &mtlsEnabled, &encryptedMTLSCert, &encryptedMTLSKey, &payloadID, &payloadRowID, &item.Body, &payloadStatus)
	if err != nil {
		return err
	}
	if payloadID != "" && (payloadRowID == "" || payloadStatus == domain.StorageStatusDeleted) {
		return app.ErrGone
	}
	secret, err := s.decryptSecret(ctx, item.TenantID, "endpoint_signing_secret", encrypted)
	if err != nil {
		return err
	}
	item.SigningSecret = secret
	if mtlsEnabled {
		if len(encryptedMTLSCert) == 0 || len(encryptedMTLSKey) == 0 {
			return fmt.Errorf("endpoint mTLS is enabled without encrypted client material")
		}
		item.MTLSClientCertPEM, err = s.decryptSecret(ctx, item.TenantID, "endpoint_mtls_client_cert", encryptedMTLSCert)
		if err != nil {
			return err
		}
		item.MTLSClientKeyPEM, err = s.decryptSecret(ctx, item.TenantID, "endpoint_mtls_client_key", encryptedMTLSKey)
		if err != nil {
			return err
		}
	}
	if payloadID == "" {
		body, err := s.legacyDeliveryEnvelope(ctx, tx, item.TenantID, item.EventID)
		if err != nil {
			return err
		}
		item.Body = body
	}
	return nil
}

func (s *Store) RecordDeliveryAttempt(ctx context.Context, item worker.DeliveryItem, result worker.DeliveryResult, deliverErr error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	policy, err := s.retryPolicyForDelivery(ctx, tx, item.TenantID, item.RetryPolicyID)
	if err != nil {
		return err
	}
	attemptNo := item.AttemptCount + 1
	state := "succeeded"
	retryable := false
	failureClass := result.FailureClass
	if deliverErr != nil || result.StatusCode < 200 || result.StatusCode > 299 {
		state = "failed"
		class := policy.ClassifyStatus(result.StatusCode)
		retryable = class.Retryable
		if failureClass == "" {
			failureClass = class.Reason
		}
	}
	body := string(result.ResponseBody)
	if len(body) > 16<<10 {
		body = body[:16<<10]
	}
	requestHash := domain.HashSHA256(item.Body)
	responseHash := domain.HashSHA256(result.ResponseBody)
	completedAt := time.Now().UTC()
	retrySeed := item.RetrySeed
	if retrySeed == "" {
		retrySeed = deliveryRetrySeed(item.TenantID, item.ID, item.EventID, item.EndpointID)
	}
	var retryDelay time.Duration
	var nextRetryAt time.Time
	willRetry := state != "succeeded" && retryable && attemptNo < policy.MaxAttempts
	if willRetry {
		retryDelay = policy.NextDeterministicDelay(attemptNo, retrySeed)
		nextRetryAt = completedAt.Add(retryDelay)
	}
	var nextRetryValue any
	if !nextRetryAt.IsZero() {
		nextRetryValue = nextRetryAt
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO delivery_attempts(id, tenant_id, delivery_id, event_id, endpoint_id, request_sha256, response_sha256, attempt_no, state, response_status, response_body_truncated, failure_class, retryable, retry_delay_ms, next_retry_at, completed_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		mustID("att"), item.TenantID, item.ID, item.EventID, item.EndpointID, requestHash, responseHash, attemptNo, state, result.StatusCode, body, failureClass, retryable, retryDelay.Milliseconds(), nextRetryValue, completedAt,
	); err != nil {
		return err
	}
	if state == "succeeded" {
		if _, err := tx.Exec(ctx, `UPDATE deliveries SET state='succeeded', attempt_count=$1, locked_by=NULL, lock_expires_at=NULL WHERE tenant_id=$2 AND id=$3`, attemptNo, item.TenantID, item.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE endpoints SET failure_count=0, circuit_state='closed', disabled_until=NULL WHERE tenant_id=$1 AND id=$2`, item.TenantID, item.EndpointID); err != nil {
			return err
		}
	} else if willRetry {
		if _, err := tx.Exec(ctx, `UPDATE deliveries SET state='scheduled', attempt_count=$1, next_attempt_at=$2, retry_seed=$3, locked_by=NULL, lock_expires_at=NULL WHERE tenant_id=$4 AND id=$5`, attemptNo, nextRetryAt, retrySeed, item.TenantID, item.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE endpoints
			SET failure_count=failure_count+1,
			    circuit_state=CASE WHEN failure_count + 1 >= 3 THEN 'open' ELSE circuit_state END,
			    disabled_until=CASE WHEN failure_count + 1 >= 3 THEN now() + interval '5 minutes' ELSE disabled_until END
			WHERE tenant_id=$1 AND id=$2`, item.TenantID, item.EndpointID); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, `UPDATE deliveries SET state='dead_lettered', attempt_count=$1, locked_by=NULL, lock_expires_at=NULL WHERE tenant_id=$2 AND id=$3`, attemptNo, item.TenantID, item.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE endpoints
			SET failure_count=failure_count+1, circuit_state='open', disabled_until=now() + interval '10 minutes'
			WHERE tenant_id=$1 AND id=$2`, item.TenantID, item.EndpointID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO dead_letter_entries(id, tenant_id, delivery_id, event_id, reason, state) VALUES($1,$2,$3,$4,$5,'open')`, mustID("dlq"), item.TenantID, item.ID, item.EventID, failureClass); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ClaimNotificationDeliveries(ctx context.Context, workerID string, limit int) ([]worker.SignalDeliveryItem, error) {
	if limit <= 0 {
		limit = 10
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	if err := upsertWorkerLease(ctx, tx, workerID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		WITH claimed AS (
			SELECT d.id
			FROM notification_deliveries d
			JOIN notification_channels c ON c.tenant_id=d.tenant_id AND c.id=d.channel_id
			WHERE d.state='scheduled'
			  AND d.next_attempt_at <= now()
			  AND c.state='active'
			ORDER BY d.next_attempt_at ASC, d.created_at ASC, d.id ASC
			LIMIT $2
			FOR UPDATE OF d SKIP LOCKED
		)
		UPDATE notification_deliveries d
		SET state='in_progress', worker_id=$1, updated_at=now()
		FROM claimed
		WHERE d.id=claimed.id
		RETURNING d.id, d.tenant_id, d.attempt_count, d.body, d.channel_id`, workerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []worker.SignalDeliveryItem
	var channelIDs []string
	for rows.Next() {
		var item worker.SignalDeliveryItem
		var channelID string
		if err := rows.Scan(&item.ID, &item.TenantID, &item.AttemptCount, &item.Body, &channelID); err != nil {
			return nil, err
		}
		out = append(out, item)
		channelIDs = append(channelIDs, channelID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		var encrypted []byte
		if err := tx.QueryRow(ctx, `
			SELECT url, encrypted_secret
			FROM notification_channels
			WHERE tenant_id=$1 AND id=$2 AND state='active'`, out[i].TenantID, channelIDs[i]).Scan(&out[i].URL, &encrypted); err != nil {
			return nil, err
		}
		secret, err := s.decryptSecret(ctx, out[i].TenantID, "notification_channel_signing_secret", encrypted)
		if err != nil {
			return nil, err
		}
		out[i].Secret = secret
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) RecordNotificationDeliveryAttempt(ctx context.Context, item worker.SignalDeliveryItem, result worker.SignalDeliveryResult, deliverErr error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	attemptCount := item.AttemptCount + 1
	state := domain.SignalDeliverySucceeded
	if deliverErr != nil || result.StatusCode < 200 || result.StatusCode > 299 {
		state = domain.SignalDeliveryFailed
	}
	failureClass := result.FailureClass
	if failureClass == "" && deliverErr != nil {
		failureClass = "network_error"
	}
	response := result.ResponseBody
	if len(response) > 16<<10 {
		response = response[:16<<10]
	}
	errText := ""
	if deliverErr != nil {
		errText = truncateText(deliverErr.Error(), 512)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO notification_delivery_attempts(id, tenant_id, delivery_id, status_code, failure_class, response_body, response_truncated, error)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		mustID("natt"), item.TenantID, item.ID, result.StatusCode, failureClass, response, result.ResponseTruncated, errText); err != nil {
		return err
	}
	if state == domain.SignalDeliverySucceeded {
		if _, err := tx.Exec(ctx, `
			UPDATE notification_deliveries
			SET state='succeeded', attempt_count=$3, last_attempt_at=now(), worker_id='', updated_at=now()
			WHERE tenant_id=$1 AND id=$2`, item.TenantID, item.ID, attemptCount); err != nil {
			return err
		}
	} else if attemptCount < 5 {
		nextAttempt := time.Now().UTC().Add(time.Duration(attemptCount*attemptCount) * time.Minute)
		if _, err := tx.Exec(ctx, `
			UPDATE notification_deliveries
			SET state='scheduled', attempt_count=$3, next_attempt_at=$4, last_attempt_at=now(), worker_id='', updated_at=now()
			WHERE tenant_id=$1 AND id=$2`, item.TenantID, item.ID, attemptCount, nextAttempt); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE notification_deliveries
			SET state='failed', attempt_count=$3, last_attempt_at=now(), worker_id='', updated_at=now()
			WHERE tenant_id=$1 AND id=$2`, item.TenantID, item.ID, attemptCount); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) EnqueueSIEMDeliveries(ctx context.Context, workerID string, limit int) error {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, s.tenant_id, s.cursor_sequence
		FROM siem_sinks s
		WHERE s.state='active'
		  AND NOT EXISTS (
		      SELECT 1 FROM siem_deliveries d
		      WHERE d.tenant_id=s.tenant_id AND d.sink_id=s.id AND d.state IN ('scheduled', 'in_progress')
		  )
		ORDER BY s.updated_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	type sinkCursor struct {
		id       string
		tenantID string
		cursor   int64
	}
	var sinks []sinkCursor
	for rows.Next() {
		var item sinkCursor
		if err := rows.Scan(&item.id, &item.tenantID, &item.cursor); err != nil {
			return err
		}
		sinks = append(sinks, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, sink := range sinks {
		body, from, to, err := s.buildSIEMBatch(ctx, sink.tenantID, sink.cursor, 100)
		if err != nil {
			return err
		}
		if len(body) == 0 {
			continue
		}
		if _, err := s.insertSIEMDelivery(ctx, sink.tenantID, sink.id, from, to, body); err != nil {
			return err
		}
		_ = workerID
	}
	return nil
}

func (s *Store) buildSIEMBatch(ctx context.Context, tenantID string, cursor int64, limit int) ([]byte, int64, int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.sequence, c.audit_event_id, c.event_hash, c.previous_chain_hash, c.chain_hash,
		       c.canonicalization_version, c.source, c.state, c.created_at,
		       COALESCE(a.actor_id,''), COALESCE(a.action,''), COALESCE(a.resource,''),
		       COALESCE(a.resource_id,''), COALESCE(a.reason,''), COALESCE(a.occurred_at, 'epoch'::timestamptz)
		FROM audit_chain_entries c
		LEFT JOIN audit_events a ON a.tenant_id=c.tenant_id AND a.id=c.audit_event_id
		WHERE c.tenant_id=$1 AND c.sequence > $2
		ORDER BY c.sequence ASC
		LIMIT $3`, tenantID, cursor, limit)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	var b strings.Builder
	var from, to int64
	for rows.Next() {
		var sequence int64
		var auditEventID, eventHash, previousHash, chainHash, version, source, state string
		var entryCreatedAt, occurredAt time.Time
		var actorID, action, resource, resourceID, reason string
		if err := rows.Scan(&sequence, &auditEventID, &eventHash, &previousHash, &chainHash, &version, &source, &state, &entryCreatedAt,
			&actorID, &action, &resource, &resourceID, &reason, &occurredAt); err != nil {
			return nil, 0, 0, err
		}
		if from == 0 {
			from = sequence
		}
		to = sequence
		row := map[string]any{
			"tenant_id":                tenantID,
			"sequence":                 sequence,
			"audit_event_id":           auditEventID,
			"event_hash":               eventHash,
			"previous_chain_hash":      previousHash,
			"chain_hash":               chainHash,
			"canonicalization_version": version,
			"chain_entry_source":       source,
			"chain_entry_state":        state,
			"chain_entry_created_at":   entryCreatedAt,
			"actor_id":                 actorID,
			"action":                   action,
			"resource":                 resource,
			"resource_id":              resourceID,
			"reason":                   reason,
			"occurred_at":              occurredAt,
		}
		raw, err := json.Marshal(row)
		if err != nil {
			return nil, 0, 0, err
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, err
	}
	if to == 0 {
		return nil, 0, 0, nil
	}
	return []byte(b.String()), from, to, nil
}

func (s *Store) ClaimSIEMDeliveries(ctx context.Context, workerID string, limit int) ([]worker.SignalDeliveryItem, error) {
	if limit <= 0 {
		limit = 10
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	if err := upsertWorkerLease(ctx, tx, workerID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		WITH claimed AS (
			SELECT d.id
			FROM siem_deliveries d
			JOIN siem_sinks s ON s.tenant_id=d.tenant_id AND s.id=d.sink_id
			WHERE d.state='scheduled'
			  AND d.next_attempt_at <= now()
			  AND s.state='active'
			ORDER BY d.next_attempt_at ASC, d.created_at ASC, d.id ASC
			LIMIT $2
			FOR UPDATE OF d SKIP LOCKED
		)
		UPDATE siem_deliveries d
		SET state='in_progress', worker_id=$1, updated_at=now()
		FROM claimed
		WHERE d.id=claimed.id
		RETURNING d.id, d.tenant_id, d.attempt_count, d.body, d.sink_id`, workerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []worker.SignalDeliveryItem
	var sinkIDs []string
	for rows.Next() {
		var item worker.SignalDeliveryItem
		var sinkID string
		if err := rows.Scan(&item.ID, &item.TenantID, &item.AttemptCount, &item.Body, &sinkID); err != nil {
			return nil, err
		}
		out = append(out, item)
		sinkIDs = append(sinkIDs, sinkID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		var encrypted []byte
		if err := tx.QueryRow(ctx, `
			SELECT url, encrypted_secret
			FROM siem_sinks
			WHERE tenant_id=$1 AND id=$2 AND state='active'`, out[i].TenantID, sinkIDs[i]).Scan(&out[i].URL, &encrypted); err != nil {
			return nil, err
		}
		secret, err := s.decryptSecret(ctx, out[i].TenantID, "siem_sink_signing_secret", encrypted)
		if err != nil {
			return nil, err
		}
		out[i].Secret = secret
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) RecordSIEMDeliveryAttempt(ctx context.Context, item worker.SignalDeliveryItem, result worker.SignalDeliveryResult, deliverErr error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	var sinkID string
	var toSequence int64
	if err := tx.QueryRow(ctx, `SELECT sink_id, to_sequence FROM siem_deliveries WHERE tenant_id=$1 AND id=$2`, item.TenantID, item.ID).Scan(&sinkID, &toSequence); err != nil {
		return err
	}
	attemptCount := item.AttemptCount + 1
	state := domain.SignalDeliverySucceeded
	if deliverErr != nil || result.StatusCode < 200 || result.StatusCode > 299 {
		state = domain.SignalDeliveryFailed
	}
	failureClass := result.FailureClass
	if failureClass == "" && deliverErr != nil {
		failureClass = "network_error"
	}
	response := result.ResponseBody
	if len(response) > 16<<10 {
		response = response[:16<<10]
	}
	errText := ""
	if deliverErr != nil {
		errText = truncateText(deliverErr.Error(), 512)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO siem_delivery_attempts(id, tenant_id, delivery_id, status_code, failure_class, response_body, response_truncated, error)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		mustID("satt"), item.TenantID, item.ID, result.StatusCode, failureClass, response, result.ResponseTruncated, errText); err != nil {
		return err
	}
	if state == domain.SignalDeliverySucceeded {
		if _, err := tx.Exec(ctx, `
			UPDATE siem_deliveries
			SET state='succeeded', attempt_count=$3, last_attempt_at=now(), worker_id='', updated_at=now()
			WHERE tenant_id=$1 AND id=$2`, item.TenantID, item.ID, attemptCount); err != nil {
			return err
		}
		if toSequence > 0 {
			if _, err := tx.Exec(ctx, `
				UPDATE siem_sinks
				SET cursor_sequence=GREATEST(cursor_sequence, $3), updated_at=now()
				WHERE tenant_id=$1 AND id=$2`, item.TenantID, sinkID, toSequence); err != nil {
				return err
			}
		}
	} else if attemptCount < 5 {
		nextAttempt := time.Now().UTC().Add(time.Duration(attemptCount*attemptCount) * time.Minute)
		if _, err := tx.Exec(ctx, `
			UPDATE siem_deliveries
			SET state='scheduled', attempt_count=$3, next_attempt_at=$4, last_attempt_at=now(), worker_id='', updated_at=now()
			WHERE tenant_id=$1 AND id=$2`, item.TenantID, item.ID, attemptCount, nextAttempt); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE siem_deliveries
			SET state='failed', attempt_count=$3, last_attempt_at=now(), worker_id='', updated_at=now()
			WHERE tenant_id=$1 AND id=$2`, item.TenantID, item.ID, attemptCount); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func truncateText(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func scanRetentionPolicy(row rowScanner) (domain.RetentionPolicy, error) {
	var item domain.RetentionPolicy
	err := row.Scan(&item.ID, &item.TenantID, &item.ResourceType, &item.SourceID, &item.RetentionDays, &item.State, &item.LegalHold, &item.HoldReason, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func scanAuditChainAnchor(row rowScanner) (domain.AuditChainAnchor, error) {
	var item domain.AuditChainAnchor
	err := row.Scan(&item.ID, &item.TenantID, &item.FromSequence, &item.ToSequence, &item.ChainHash, &item.ManifestSHA256,
		&item.StorageBackend, &item.ObjectBucket, &item.ObjectKey, &item.CreatedBy, &item.Reason, &item.CreatedAt)
	return item, err
}

func scanAuditChainEntry(row rowScanner) (domain.AuditChainEntry, error) {
	var item domain.AuditChainEntry
	err := row.Scan(&item.ID, &item.TenantID, &item.Sequence, &item.AuditEventID, &item.EventHash, &item.PreviousChainHash,
		&item.ChainHash, &item.CanonicalizationVersion, &item.Source, &item.State, &item.AuditEventDeletedAt, &item.TombstoneReason, &item.CreatedAt)
	if item.AuditEventDeletedAt.Equal(time.Unix(0, 0).UTC()) {
		item.AuditEventDeletedAt = time.Time{}
	}
	return item, err
}

func scanSource(row rowScanner) (domain.Source, error) {
	var item domain.Source
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.Provider, &item.Adapter, &item.State, &item.CreatedAt)
	return item, err
}

func scanProducerClient(row rowScanner) (domain.ProducerClient, error) {
	var item domain.ProducerClient
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.SourceID, &item.Scopes, &item.TokenTTLSeconds, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt, &item.DisabledAt)
	if item.DisabledAt.Equal(time.Unix(0, 0).UTC()) {
		item.DisabledAt = time.Time{}
	}
	return item, err
}

func scanProducerMTLSIdentity(row rowScanner) (domain.ProducerMTLSIdentity, error) {
	var item domain.ProducerMTLSIdentity
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.SourceID, &item.CertificateFingerprintSHA256, &item.CertSubject, &item.DNSSANs, &item.URISANs, &item.EmailSANs, &item.NotBefore, &item.NotAfter, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt, &item.DisabledAt)
	if item.DisabledAt.Equal(time.Unix(0, 0).UTC()) {
		item.DisabledAt = time.Time{}
	}
	return item, err
}

func scanEndpoint(row rowScanner) (domain.Endpoint, error) {
	var item domain.Endpoint
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.URL, &item.State, &item.RetryPolicyID, &item.MTLSEnabled, &item.MTLSCertSubject, &item.CircuitState, &item.FailureCount, &item.DisabledUntil, &item.CreatedAt)
	return item, err
}

func (s *Store) auditEventsForExport(ctx context.Context, tenantID string, from, to time.Time) ([]domain.AuditEvent, error) {
	query := `SELECT id, tenant_id, actor_id, action, resource, resource_id, reason, occurred_at FROM audit_events WHERE tenant_id=$1`
	args := []any{tenantID}
	if !from.IsZero() {
		args = append(args, from)
		query += fmt.Sprintf(" AND occurred_at >= $%d", len(args))
	}
	if !to.IsZero() {
		args = append(args, to)
		query += fmt.Sprintf(" AND occurred_at <= $%d", len(args))
	}
	query += " ORDER BY occurred_at ASC, id ASC"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuditEvent
	for rows.Next() {
		var item domain.AuditEvent
		if err := rows.Scan(&item.ID, &item.TenantID, &item.ActorID, &item.Action, &item.Resource, &item.ResourceID, &item.Reason, &item.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) auditChainProofForExport(ctx context.Context, tenantID string, from, to time.Time) ([]byte, *evidence.AuditChain, error) {
	query := `
		SELECT c.id, c.tenant_id, c.sequence, c.audit_event_id, c.event_hash, c.previous_chain_hash, c.chain_hash,
		       c.canonicalization_version, c.source, c.state, COALESCE(c.audit_event_deleted_at, 'epoch'::timestamptz), c.tombstone_reason, c.created_at
		FROM audit_chain_entries c
		JOIN audit_events a ON a.tenant_id=c.tenant_id AND a.id=c.audit_event_id
		WHERE c.tenant_id=$1`
	args := []any{tenantID}
	if !from.IsZero() {
		args = append(args, from)
		query += fmt.Sprintf(" AND a.occurred_at >= $%d", len(args))
	}
	if !to.IsZero() {
		args = append(args, to)
		query += fmt.Sprintf(" AND a.occurred_at <= $%d", len(args))
	}
	query += " ORDER BY c.sequence ASC"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var entries []domain.AuditChainEntry
	items := []any{}
	for rows.Next() {
		entry, err := scanAuditChainEntry(rows)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, entry)
		items = append(items, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	body, err := evidence.JSONLines(items)
	if err != nil {
		return nil, nil, err
	}
	if len(entries) == 0 {
		return body, nil, nil
	}
	manifest := &evidence.AuditChain{
		FromSequence:   entries[0].Sequence,
		ToSequence:     entries[len(entries)-1].Sequence,
		StartChainHash: entries[0].PreviousChainHash,
		EndChainHash:   entries[len(entries)-1].ChainHash,
	}
	anchors, err := s.coveringAuditChainAnchors(ctx, tenantID, manifest.FromSequence, manifest.ToSequence)
	if err != nil {
		return nil, nil, err
	}
	manifest.Anchors = anchors
	return body, manifest, nil
}

func (s *Store) coveringAuditChainAnchors(ctx context.Context, tenantID string, fromSequence, toSequence int64) ([]evidence.AuditChainAnchor, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, from_sequence, to_sequence, chain_hash, manifest_sha256
		FROM audit_chain_anchors
		WHERE tenant_id=$1 AND from_sequence <= $2 AND to_sequence >= $3
		ORDER BY created_at DESC`, tenantID, fromSequence, toSequence)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []evidence.AuditChainAnchor
	for rows.Next() {
		var item evidence.AuditChainAnchor
		if err := rows.Scan(&item.ID, &item.FromSequence, &item.ToSequence, &item.ChainHash, &item.ManifestSHA256); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) timelineJSONLForExport(ctx context.Context, tenantID string, from, to time.Time) ([]byte, error) {
	eventIDs, err := s.eventIDsForExport(ctx, tenantID, from, to)
	if err != nil {
		return nil, err
	}
	var lines []any
	for _, eventID := range eventIDs {
		items, err := s.ListEventTimeline(ctx, tenantID, eventID, 100)
		if err != nil {
			return nil, err
		}
		lines = append(lines, map[string]any{"event_id": eventID, "timeline": items})
	}
	return evidence.JSONLines(lines)
}

func (s *Store) eventIDsForExport(ctx context.Context, tenantID string, from, to time.Time) ([]string, error) {
	query := `SELECT id FROM events WHERE tenant_id=$1`
	args := []any{tenantID}
	if !from.IsZero() {
		args = append(args, from)
		query += fmt.Sprintf(" AND received_at >= $%d", len(args))
	}
	if !to.IsZero() {
		args = append(args, to)
		query += fmt.Sprintf(" AND received_at <= $%d", len(args))
	}
	query += " ORDER BY received_at ASC, id ASC"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var eventIDs []string
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			return nil, err
		}
		eventIDs = append(eventIDs, eventID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return eventIDs, nil
}

func (s *Store) rawPayloadsJSONLForExport(ctx context.Context, tenantID string, from, to time.Time) ([]byte, error) {
	query := `
		SELECT rp.id, rp.tenant_id, COALESCE(rp.event_id, ''), rp.sha256, rp.content_type, rp.size_bytes, rp.body,
			rp.storage_backend, rp.object_bucket, rp.object_key, rp.storage_status,
			COALESCE(rp.storage_deleted_at, 'epoch'::timestamptz), rp.created_at,
			COALESCE(ev.received_at, receipts.first_received_at, rp.created_at) AS evidence_received_at,
			COALESCE(receipts.receipt_ids, ARRAY[]::text[]) AS receipt_ids
		FROM raw_payloads rp
		LEFT JOIN events ev ON ev.tenant_id=rp.tenant_id AND ev.id=rp.event_id
		LEFT JOIN LATERAL (
			SELECT min(pr.received_at) AS first_received_at, array_agg(pr.id ORDER BY pr.received_at ASC, pr.id ASC) AS receipt_ids
			FROM provider_receipts pr
			WHERE pr.tenant_id=rp.tenant_id AND pr.raw_payload_id=rp.id
		) receipts ON true
		WHERE rp.tenant_id=$1
			AND (rp.event_id IS NOT NULL OR COALESCE(array_length(receipts.receipt_ids, 1), 0) > 0)`
	args := []any{tenantID}
	if !from.IsZero() {
		args = append(args, from)
		query += fmt.Sprintf(" AND COALESCE(ev.received_at, receipts.first_received_at, rp.created_at) >= $%d", len(args))
	}
	if !to.IsZero() {
		args = append(args, to)
		query += fmt.Sprintf(" AND COALESCE(ev.received_at, receipts.first_received_at, rp.created_at) <= $%d", len(args))
	}
	query += " ORDER BY evidence_received_at ASC, rp.id ASC"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lines []any
	for rows.Next() {
		var raw domain.RawPayload
		var evidenceReceivedAt time.Time
		var receiptIDs []string
		if err := rows.Scan(&raw.ID, &raw.TenantID, &raw.EventID, &raw.SHA256, &raw.ContentType, &raw.SizeBytes, &raw.Body,
			&raw.StorageBackend, &raw.ObjectBucket, &raw.ObjectKey, &raw.StorageStatus, &raw.StorageDeletedAt, &raw.CreatedAt,
			&evidenceReceivedAt, &receiptIDs); err != nil {
			return nil, err
		}
		bodyAvailable := raw.StorageStatus != domain.StorageStatusDeleted
		if bodyAvailable && raw.StorageBackend == domain.RawStorageS3 {
			if s.objectStore == nil {
				return nil, errors.New("object store is not configured")
			}
			body, err := s.objectStore.Get(ctx, raw.ObjectBucket, raw.ObjectKey)
			if err != nil {
				if errors.Is(err, blobstore.ErrNotFound) {
					bodyAvailable = false
				} else {
					return nil, errObjectStoreReadFailed
				}
			} else {
				raw.Body = body
			}
		}
		item := map[string]any{
			"id":              raw.ID,
			"event_id":        raw.EventID,
			"sha256":          raw.SHA256,
			"content_type":    raw.ContentType,
			"size_bytes":      raw.SizeBytes,
			"storage_backend": raw.StorageBackend,
			"storage_status":  raw.StorageStatus,
			"body_available":  bodyAvailable,
			"created_at":      raw.CreatedAt,
			"received_at":     evidenceReceivedAt,
			"receipt_ids":     receiptIDs,
		}
		if bodyAvailable {
			item["body_base64"] = base64.StdEncoding.EncodeToString(raw.Body)
		}
		lines = append(lines, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return evidence.JSONLines(lines)
}

func (s *Store) payloadEvidenceJSONLForExport(ctx context.Context, tenantID string, from, to time.Time, includeBodies bool) ([]byte, error) {
	lines, err := s.normalizedEvidenceLines(ctx, tenantID, from, to, includeBodies)
	if err != nil {
		return nil, err
	}
	payloadLines, err := s.deliveryPayloadEvidenceLines(ctx, tenantID, from, to, includeBodies)
	if err != nil {
		return nil, err
	}
	lines = append(lines, payloadLines...)
	return evidence.JSONLines(lines)
}

func (s *Store) normalizedEvidenceLines(ctx context.Context, tenantID string, from, to time.Time, includeBodies bool) ([]any, error) {
	query := `
		SELECT n.id, n.event_id, n.adapter_version_id, n.provider, n.provider_event_id, n.type, n.source, n.subject,
			n.envelope_sha256, n.data_sha256, n.metadata_sha256, n.storage_status,
			COALESCE(n.storage_deleted_at, 'epoch'::timestamptz), n.created_at, n.metadata_json,
			CASE WHEN $2::boolean AND n.storage_status='stored' THEN n.envelope_json ELSE '{}'::jsonb END,
			CASE WHEN $2::boolean AND n.storage_status='stored' THEN n.data_json ELSE '{}'::jsonb END
		FROM normalized_envelopes n
		JOIN events ev ON ev.tenant_id=n.tenant_id AND ev.id=n.event_id
		WHERE n.tenant_id=$1`
	args := []any{tenantID, includeBodies}
	if !from.IsZero() {
		args = append(args, from)
		query += fmt.Sprintf(" AND ev.received_at >= $%d", len(args))
	}
	if !to.IsZero() {
		args = append(args, to)
		query += fmt.Sprintf(" AND ev.received_at <= $%d", len(args))
	}
	query += " ORDER BY ev.received_at ASC, n.id ASC"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lines []any
	for rows.Next() {
		var id, eventID, adapterVersionID, provider, providerEventID, eventType, source, subject string
		var envelopeHash, dataHash, metadataHash, storageStatus string
		var storageDeletedAt, createdAt time.Time
		var metadata, envelope, data json.RawMessage
		if err := rows.Scan(&id, &eventID, &adapterVersionID, &provider, &providerEventID, &eventType, &source, &subject,
			&envelopeHash, &dataHash, &metadataHash, &storageStatus, &storageDeletedAt, &createdAt, &metadata, &envelope, &data); err != nil {
			return nil, err
		}
		bodyAvailable := storageStatus == domain.StorageStatusStored
		item := map[string]any{
			"resource_type":      "normalized_envelope",
			"id":                 id,
			"event_id":           eventID,
			"adapter_version_id": adapterVersionID,
			"provider":           provider,
			"provider_event_id":  providerEventID,
			"type":               eventType,
			"source":             source,
			"subject":            subject,
			"envelope_sha256":    envelopeHash,
			"data_sha256":        dataHash,
			"metadata_sha256":    metadataHash,
			"metadata":           metadata,
			"storage_status":     storageStatus,
			"body_available":     bodyAvailable,
			"body_included":      includeBodies && bodyAvailable,
			"storage_deleted_at": zeroTimeOmit(storageDeletedAt),
			"created_at":         createdAt,
		}
		if includeBodies && bodyAvailable {
			item["envelope"] = envelope
			item["data"] = data
		}
		lines = append(lines, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func (s *Store) deliveryPayloadEvidenceLines(ctx context.Context, tenantID string, from, to time.Time, includeBodies bool) ([]any, error) {
	query := `
		SELECT p.id, p.delivery_id, p.event_id, p.normalized_envelope_id, p.transformation_version_id,
			p.content_type, p.sha256, p.size_bytes, p.storage_status,
			COALESCE(p.storage_deleted_at, 'epoch'::timestamptz), p.created_at,
			CASE WHEN $2::boolean AND p.storage_status='stored' THEN p.body ELSE ''::bytea END
		FROM delivery_payloads p
		JOIN events ev ON ev.tenant_id=p.tenant_id AND ev.id=p.event_id
		WHERE p.tenant_id=$1`
	args := []any{tenantID, includeBodies}
	if !from.IsZero() {
		args = append(args, from)
		query += fmt.Sprintf(" AND ev.received_at >= $%d", len(args))
	}
	if !to.IsZero() {
		args = append(args, to)
		query += fmt.Sprintf(" AND ev.received_at <= $%d", len(args))
	}
	query += " ORDER BY ev.received_at ASC, p.id ASC"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lines []any
	for rows.Next() {
		var id, deliveryID, eventID, normalizedID, transformationVersionID, contentType, hash, storageStatus string
		var sizeBytes int64
		var storageDeletedAt, createdAt time.Time
		var body []byte
		if err := rows.Scan(&id, &deliveryID, &eventID, &normalizedID, &transformationVersionID, &contentType, &hash, &sizeBytes,
			&storageStatus, &storageDeletedAt, &createdAt, &body); err != nil {
			return nil, err
		}
		bodyAvailable := storageStatus == domain.StorageStatusStored
		item := map[string]any{
			"resource_type":             "delivery_payload",
			"id":                        id,
			"delivery_id":               deliveryID,
			"event_id":                  eventID,
			"normalized_envelope_id":    normalizedID,
			"transformation_version_id": transformationVersionID,
			"content_type":              contentType,
			"sha256":                    hash,
			"size_bytes":                sizeBytes,
			"storage_status":            storageStatus,
			"body_available":            bodyAvailable,
			"body_included":             includeBodies && bodyAvailable,
			"storage_deleted_at":        zeroTimeOmit(storageDeletedAt),
			"created_at":                createdAt,
		}
		if includeBodies && bodyAvailable {
			item["body_base64"] = base64.StdEncoding.EncodeToString(body)
		}
		lines = append(lines, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func (s *Store) reconciliationEvidenceJSONLForExport(ctx context.Context, tenantID string, from, to time.Time, includeBodies bool) ([]byte, error) {
	query := `
		SELECT j.id, j.connection_id, j.provider, j.state, j.dry_run, j.capture_missing, j.route_recovered, j.redeliver_failed,
		       j.scope_object_id, COALESCE(j.window_start, 'epoch'::timestamptz), COALESCE(j.window_end, 'epoch'::timestamptz),
		       j.total_items, j.matched_items, j.missing_items, j.captured_items, j.redelivered_items, j.unrecoverable_items, j.failed_items,
		       j.error, j.created_by, j.created_at, COALESCE(j.completed_at, 'epoch'::timestamptz)
		FROM reconciliation_jobs j
		WHERE j.tenant_id=$1`
	args := []any{tenantID}
	if !from.IsZero() {
		args = append(args, from)
		query += fmt.Sprintf(" AND j.created_at >= $%d", len(args))
	}
	if !to.IsZero() {
		args = append(args, to)
		query += fmt.Sprintf(" AND j.created_at <= $%d", len(args))
	}
	query += " ORDER BY j.created_at ASC, j.id ASC"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lines []any
	for rows.Next() {
		var id, connectionID, providerName, state, scopeObjectID, errText, createdBy string
		var dryRun, captureMissing, routeRecovered, redeliverFailed bool
		var windowStart, windowEnd, createdAt, completedAt time.Time
		var total, matched, missing, captured, redelivered, unrecoverable, failed int
		if err := rows.Scan(&id, &connectionID, &providerName, &state, &dryRun, &captureMissing, &routeRecovered, &redeliverFailed,
			&scopeObjectID, &windowStart, &windowEnd, &total, &matched, &missing, &captured, &redelivered, &unrecoverable, &failed,
			&errText, &createdBy, &createdAt, &completedAt); err != nil {
			return nil, err
		}
		items, err := s.reconciliationItemsForExport(ctx, tenantID, id)
		if err != nil {
			return nil, err
		}
		apiEvidence, err := s.providerAPIEvidenceForExport(ctx, tenantID, id, includeBodies)
		if err != nil {
			return nil, err
		}
		lines = append(lines, map[string]any{
			"resource_type":         "reconciliation_job",
			"id":                    id,
			"connection_id":         connectionID,
			"provider":              providerName,
			"state":                 state,
			"dry_run":               dryRun,
			"capture_missing":       captureMissing,
			"route_recovered":       routeRecovered,
			"redeliver_failed":      redeliverFailed,
			"scope_object_id":       scopeObjectID,
			"window_start":          zeroTimeOmit(windowStart),
			"window_end":            zeroTimeOmit(windowEnd),
			"total_items":           total,
			"matched_items":         matched,
			"missing_items":         missing,
			"captured_items":        captured,
			"redelivered_items":     redelivered,
			"unrecoverable_items":   unrecoverable,
			"failed_items":          failed,
			"error":                 errText,
			"created_by":            createdBy,
			"created_at":            createdAt,
			"completed_at":          zeroTimeOmit(completedAt),
			"items":                 items,
			"provider_api_evidence": apiEvidence,
			"body_included":         includeBodies,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return evidence.JSONLines(lines)
}

func (s *Store) reconciliationItemsForExport(ctx context.Context, tenantID, jobID string) ([]map[string]any, error) {
	return listRows(ctx, s.pool, `
		SELECT id, provider, provider_object_id, provider_object_type, outcome, local_event_id, recovered_event_id,
		       provider_api_evidence_id, redelivery_requested, error, metadata_json, created_at, updated_at
		FROM reconciliation_items
		WHERE tenant_id=$1 AND job_id=$2
		ORDER BY created_at ASC, id ASC`, tenantID, jobID)
}

func (s *Store) providerAPIEvidenceForExport(ctx context.Context, tenantID, jobID string, includeBodies bool) ([]map[string]any, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, item_id, connection_id, provider, request_method, request_url, response_status, response_sha256,
		       response_size_bytes, storage_status, COALESCE(storage_deleted_at, 'epoch'::timestamptz), error, created_at,
		       CASE WHEN $3::boolean AND storage_status='stored' THEN response_body ELSE ''::bytea END
		FROM provider_api_evidence
		WHERE tenant_id=$1 AND job_id=$2
		ORDER BY created_at ASC, id ASC`, tenantID, jobID, includeBodies)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, itemID, connectionID, providerName, method, rawURL, hash, storageStatus, errText string
		var status int
		var size int64
		var storageDeletedAt, createdAt time.Time
		var body []byte
		if err := rows.Scan(&id, &itemID, &connectionID, &providerName, &method, &rawURL, &status, &hash, &size,
			&storageStatus, &storageDeletedAt, &errText, &createdAt, &body); err != nil {
			return nil, err
		}
		bodyAvailable := storageStatus == domain.ProviderAPIEvidenceStorageStatusStored
		item := map[string]any{
			"id":                  id,
			"item_id":             itemID,
			"connection_id":       connectionID,
			"provider":            providerName,
			"request_method":      method,
			"request_url":         rawURL,
			"response_status":     status,
			"response_sha256":     hash,
			"response_size_bytes": size,
			"storage_status":      storageStatus,
			"body_available":      bodyAvailable,
			"body_included":       includeBodies && bodyAvailable,
			"storage_deleted_at":  zeroTimeOmit(storageDeletedAt),
			"error":               errText,
			"created_at":          createdAt,
		}
		if includeBodies && bodyAvailable {
			item["response_body_base64"] = base64.StdEncoding.EncodeToString(body)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func zeroTimeOmit(value time.Time) any {
	if value.Equal(time.Unix(0, 0).UTC()) {
		return nil
	}
	return value
}

func manifestTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	out := value.UTC()
	return &out
}

func (s *Store) getAuditExportWithBundle(ctx context.Context, tenantID, exportID string) (domain.EvidenceExport, []byte, error) {
	var out domain.EvidenceExport
	var body []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, state, COALESCE(from_time, 'epoch'::timestamptz), COALESCE(to_time, 'epoch'::timestamptz),
			include_raw_payloads, include_timelines, include_payload_bodies, format, storage_backend, object_bucket, object_key, sha256,
			manifest_sha256, size_bytes, error, created_by, created_at, COALESCE(completed_at, 'epoch'::timestamptz), bundle
		FROM evidence_exports
		WHERE tenant_id=$1 AND id=$2`, tenantID, exportID).
		Scan(&out.ID, &out.TenantID, &out.State, &out.From, &out.To, &out.IncludeRawPayloads, &out.IncludeTimelines, &out.IncludePayloadBodies,
			&out.Format, &out.StorageBackend, &out.ObjectBucket, &out.ObjectKey, &out.SHA256, &out.ManifestSHA256,
			&out.SizeBytes, &out.Error, &out.CreatedBy, &out.CreatedAt, &out.CompletedAt, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.EvidenceExport{}, nil, app.ErrNotFound
	}
	return out, body, err
}

func normalizeEvidenceExportTimes(item domain.EvidenceExport) domain.EvidenceExport {
	if item.From.Equal(time.Unix(0, 0).UTC()) {
		item.From = time.Time{}
	}
	if item.To.Equal(time.Unix(0, 0).UTC()) {
		item.To = time.Time{}
	}
	if item.CompletedAt.Equal(time.Unix(0, 0).UTC()) {
		item.CompletedAt = time.Time{}
	}
	return item
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func (s *Store) applyRetentionPolicy(ctx context.Context, workerID string, policy domain.RetentionPolicy) error {
	if policy.LegalHold {
		return nil
	}
	runID := mustID("rrn")
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO retention_runs(id, tenant_id, policy_id, resource_type, state)
		VALUES($1,$2,$3,$4,$5)`, runID, policy.TenantID, policy.ID, policy.ResourceType, domain.RetentionRunStateRunning); err != nil {
		return err
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -policy.RetentionDays)
	processed := 0
	switch policy.ResourceType {
	case domain.RetentionResourceRawPayload:
		processed, err = s.applyRawPayloadRetention(ctx, tx, policy, runID, cutoff)
	case domain.RetentionResourceNormalized:
		processed, err = s.applyNormalizedEnvelopeRetention(ctx, tx, policy, runID, cutoff)
	case domain.RetentionResourceDeliveryPayload:
		processed, err = s.applyDeliveryPayloadRetention(ctx, tx, policy, runID, cutoff)
	case domain.RetentionResourceProviderAPI:
		processed, err = s.applyProviderAPIEvidenceRetention(ctx, tx, policy, runID, cutoff)
	case domain.RetentionResourceAuditEvent:
		processed, err = s.applyAuditEventRetention(ctx, tx, policy, runID, cutoff)
	default:
		err = fmt.Errorf("unsupported retention resource type %q", policy.ResourceType)
	}
	if err != nil {
		_, _ = tx.Exec(ctx, `UPDATE retention_runs SET state=$1, error=$2, completed_at=now() WHERE tenant_id=$3 AND id=$4`, domain.RetentionRunStateFailed, err.Error(), policy.TenantID, runID)
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE retention_runs
		SET state=$1, matched_items=$2, processed_items=$2, completed_at=now()
		WHERE tenant_id=$3 AND id=$4`, domain.RetentionRunStateCompleted, processed, policy.TenantID, runID); err != nil {
		return err
	}
	if _, err := recordAuditEventTx(ctx, tx, auditEventInput{TenantID: policy.TenantID, ActorID: workerID, Action: "retention.run.completed", Resource: "retention_policy", ResourceID: policy.ID, Reason: policy.ResourceType}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) applyRawPayloadRetention(ctx context.Context, tx pgx.Tx, policy domain.RetentionPolicy, runID string, cutoff time.Time) (int, error) {
	query := `
		SELECT rp.id, rp.storage_backend, rp.object_bucket, rp.object_key
		FROM raw_payloads rp
		LEFT JOIN events ev ON ev.tenant_id=rp.tenant_id AND ev.id=rp.event_id
		WHERE rp.tenant_id=$1 AND rp.storage_status='stored' AND rp.created_at < $2`
	args := []any{policy.TenantID, cutoff}
	if policy.SourceID != "" {
		args = append(args, policy.SourceID)
		query += fmt.Sprintf(" AND ev.source_id=$%d", len(args))
	}
	query += " ORDER BY rp.created_at ASC LIMIT 100"
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type rawCandidate struct {
		id, backend, bucket, key string
	}
	var candidates []rawCandidate
	for rows.Next() {
		var item rawCandidate
		if err := rows.Scan(&item.id, &item.backend, &item.bucket, &item.key); err != nil {
			return 0, err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, item := range candidates {
		if item.backend == domain.RawStorageS3 && item.key != "" && s.objectStore != nil {
			if err := s.objectStore.Delete(ctx, item.bucket, item.key); err != nil && !errors.Is(err, blobstore.ErrNotFound) {
				return 0, err
			}
		} else if item.backend == domain.RawStorageS3 && item.key != "" {
			return 0, errors.New("object store is not configured")
		}
		if _, err := tx.Exec(ctx, `
			UPDATE raw_payloads
			SET body='', storage_status='deleted', storage_deleted_at=now()
			WHERE tenant_id=$1 AND id=$2`, policy.TenantID, item.id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO retention_run_items(id, tenant_id, retention_run_id, resource_type, resource_id, action, state)
			VALUES($1,$2,$3,$4,$5,'delete_body','completed')`,
			mustID("rri"), policy.TenantID, runID, domain.RetentionResourceRawPayload, item.id,
		); err != nil {
			return 0, err
		}
	}
	return len(candidates), nil
}

func (s *Store) applyNormalizedEnvelopeRetention(ctx context.Context, tx pgx.Tx, policy domain.RetentionPolicy, runID string, cutoff time.Time) (int, error) {
	query := `
		SELECT n.id
		FROM normalized_envelopes n
		LEFT JOIN events ev ON ev.tenant_id=n.tenant_id AND ev.id=n.event_id
		WHERE n.tenant_id=$1 AND n.storage_status='stored' AND n.created_at < $2`
	args := []any{policy.TenantID, cutoff}
	if policy.SourceID != "" {
		args = append(args, policy.SourceID)
		query += fmt.Sprintf(" AND ev.source_id=$%d", len(args))
	}
	query += " ORDER BY n.created_at ASC LIMIT 100"
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `
			UPDATE normalized_envelopes
			SET envelope_json='{}'::jsonb, data_json='{}'::jsonb, storage_status='deleted', storage_deleted_at=now()
			WHERE tenant_id=$1 AND id=$2`, policy.TenantID, id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO retention_run_items(id, tenant_id, retention_run_id, resource_type, resource_id, action, state)
			VALUES($1,$2,$3,$4,$5,'delete_body','completed')`,
			mustID("rri"), policy.TenantID, runID, domain.RetentionResourceNormalized, id,
		); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

func (s *Store) applyDeliveryPayloadRetention(ctx context.Context, tx pgx.Tx, policy domain.RetentionPolicy, runID string, cutoff time.Time) (int, error) {
	query := `
		SELECT p.id
		FROM delivery_payloads p
		LEFT JOIN events ev ON ev.tenant_id=p.tenant_id AND ev.id=p.event_id
		WHERE p.tenant_id=$1 AND p.storage_status='stored' AND p.created_at < $2`
	args := []any{policy.TenantID, cutoff}
	if policy.SourceID != "" {
		args = append(args, policy.SourceID)
		query += fmt.Sprintf(" AND ev.source_id=$%d", len(args))
	}
	query += " ORDER BY p.created_at ASC LIMIT 100"
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `
			UPDATE delivery_payloads
			SET body='', storage_status='deleted', storage_deleted_at=now()
			WHERE tenant_id=$1 AND id=$2`, policy.TenantID, id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO retention_run_items(id, tenant_id, retention_run_id, resource_type, resource_id, action, state)
			VALUES($1,$2,$3,$4,$5,'delete_body','completed')`,
			mustID("rri"), policy.TenantID, runID, domain.RetentionResourceDeliveryPayload, id,
		); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

func (s *Store) applyProviderAPIEvidenceRetention(ctx context.Context, tx pgx.Tx, policy domain.RetentionPolicy, runID string, cutoff time.Time) (int, error) {
	rows, err := tx.Query(ctx, `
		SELECT id
		FROM provider_api_evidence
		WHERE tenant_id=$1 AND storage_status='stored' AND created_at < $2
		ORDER BY created_at ASC
		LIMIT 100`, policy.TenantID, cutoff)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `
			UPDATE provider_api_evidence
			SET response_body='', storage_status='deleted', storage_deleted_at=now()
			WHERE tenant_id=$1 AND id=$2`, policy.TenantID, id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO retention_run_items(id, tenant_id, retention_run_id, resource_type, resource_id, action, state)
			VALUES($1,$2,$3,$4,$5,'delete_body','completed')`,
			mustID("rri"), policy.TenantID, runID, domain.RetentionResourceProviderAPI, id,
		); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

func (s *Store) applyAuditEventRetention(ctx context.Context, tx pgx.Tx, policy domain.RetentionPolicy, runID string, cutoff time.Time) (int, error) {
	rows, err := tx.Query(ctx, `
		SELECT id
		FROM audit_events
		WHERE tenant_id=$1 AND occurred_at < $2
		ORDER BY occurred_at ASC
		LIMIT 100`, policy.TenantID, cutoff)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `
			UPDATE audit_chain_entries
			SET state=$3, audit_event_deleted_at=now(), tombstone_reason=$4
			WHERE tenant_id=$1 AND audit_event_id=$2 AND state<>$3`,
			policy.TenantID, id, domain.AuditChainEntryStateRetained, "retention_policy:"+policy.ID); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id=$1 AND id=$2`, policy.TenantID, id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO retention_run_items(id, tenant_id, retention_run_id, resource_type, resource_id, action, state)
			VALUES($1,$2,$3,$4,$5,'delete_row','completed')`,
			mustID("rri"), policy.TenantID, runID, domain.RetentionResourceAuditEvent, id,
		); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func (s *Store) getProviderConnectionPublic(ctx context.Context, tenantID, connectionID string) (domain.ProviderConnection, error) {
	item, err := scanProviderConnection(s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, provider, state, credential_type, credential_hint, config_json,
			COALESCE(verified_at, 'epoch'::timestamptz), COALESCE(revoked_at, 'epoch'::timestamptz), created_by, created_at, updated_at
		FROM provider_connections
		WHERE tenant_id=$1 AND id=$2`, tenantID, connectionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProviderConnection{}, app.ErrNotFound
	}
	return normalizeProviderConnection(item), err
}

func (s *Store) getProviderConnectionSecret(ctx context.Context, tenantID, connectionID string) (domain.ProviderConnection, string, error) {
	var encrypted []byte
	var item domain.ProviderConnection
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, provider, state, credential_type, credential_hint, config_json,
			COALESCE(verified_at, 'epoch'::timestamptz), COALESCE(revoked_at, 'epoch'::timestamptz), created_by, created_at, updated_at, encrypted_credential
		FROM provider_connections
		WHERE tenant_id=$1 AND id=$2 AND state='active'`, tenantID, connectionID)
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.Provider, &item.State, &item.CredentialType, &item.CredentialHint, &item.Config,
		&item.VerifiedAt, &item.RevokedAt, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt, &encrypted)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProviderConnection{}, "", app.ErrNotFound
	}
	if err != nil {
		return domain.ProviderConnection{}, "", err
	}
	plain, err := s.decryptSecret(ctx, item.TenantID, "provider_connection_credential", encrypted)
	if err != nil {
		return domain.ProviderConnection{}, "", err
	}
	return normalizeProviderConnection(item), string(plain), nil
}

func scanProviderConnection(row rowScanner) (domain.ProviderConnection, error) {
	var item domain.ProviderConnection
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.Provider, &item.State, &item.CredentialType, &item.CredentialHint, &item.Config, &item.VerifiedAt, &item.RevokedAt, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func scanProviderAdapter(row rowScanner) (domain.ProviderAdapter, error) {
	var item domain.ProviderAdapter
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.Kind, &item.Description, &item.RiskLevel, &item.State, &item.ProvenanceURL, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt, &item.RetiredAt)
	return item, err
}

func normalizeProviderAdapter(item domain.ProviderAdapter) domain.ProviderAdapter {
	if item.RetiredAt.Equal(time.Unix(0, 0).UTC()) {
		item.RetiredAt = time.Time{}
	}
	return item
}

func adapterVersionColumns() string {
	return `id, COALESCE(tenant_id,''), adapter_id, name, version, kind, config_hash, definition_json, definition_sha256,
		package_sha256, package_signature, sbom_sha256, provenance_url, risk_level, test_results_json, review_notes, state,
		created_by, reviewed_by, activated_by, created_at, COALESCE(reviewed_at, 'epoch'::timestamptz),
		COALESCE(activated_at, 'epoch'::timestamptz), COALESCE(deprecated_at, 'epoch'::timestamptz), COALESCE(retired_at, 'epoch'::timestamptz)`
}

func scanAdapterVersion(row rowScanner) (domain.AdapterVersion, error) {
	var item domain.AdapterVersion
	err := row.Scan(&item.ID, &item.TenantID, &item.AdapterID, &item.Name, &item.Version, &item.Kind, &item.ConfigHash, &item.Definition,
		&item.DefinitionSHA256, &item.PackageSHA256, &item.PackageSignature, &item.SBOMSHA256, &item.ProvenanceURL, &item.RiskLevel,
		&item.TestResults, &item.ReviewNotes, &item.State, &item.CreatedBy, &item.ReviewedBy, &item.ActivatedBy, &item.CreatedAt,
		&item.ReviewedAt, &item.ActivatedAt, &item.DeprecatedAt, &item.RetiredAt)
	return item, err
}

func normalizeAdapterVersion(item domain.AdapterVersion) domain.AdapterVersion {
	epoch := time.Unix(0, 0).UTC()
	if item.ReviewedAt.Equal(epoch) {
		item.ReviewedAt = time.Time{}
	}
	if item.ActivatedAt.Equal(epoch) {
		item.ActivatedAt = time.Time{}
	}
	if item.DeprecatedAt.Equal(epoch) {
		item.DeprecatedAt = time.Time{}
	}
	if item.RetiredAt.Equal(epoch) {
		item.RetiredAt = time.Time{}
	}
	return item
}

func scanAdapterTestVector(row rowScanner) (domain.AdapterTestVector, error) {
	var item domain.AdapterTestVector
	err := row.Scan(&item.ID, &item.TenantID, &item.AdapterVersionID, &item.Name, &item.Purpose, &item.Request, &item.Expected,
		&item.RequestSHA256, &item.ExpectedSHA256, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Store) ensureTenantAdapterVersion(ctx context.Context, tenantID, adapterID, versionID string) error {
	var id string
	err := s.pool.QueryRow(ctx, `SELECT id FROM adapter_versions WHERE tenant_id=$1 AND adapter_id=$2 AND id=$3`, tenantID, adapterID, versionID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	return err
}

func adapterVersionNextState(current, action string) (string, error) {
	switch action {
	case "submit_tests":
		if current != domain.AdapterStateDraft {
			return "", fmt.Errorf("%w: submit_tests requires draft state", app.ErrInvalidInput)
		}
		return domain.AdapterStateAutomatedTests, nil
	case "request_review":
		if current != domain.AdapterStateAutomatedTests {
			return "", fmt.Errorf("%w: request_review requires automated_tests state", app.ErrInvalidInput)
		}
		return domain.AdapterStateSecurityReview, nil
	case "approve_staging":
		if current != domain.AdapterStateSecurityReview {
			return "", fmt.Errorf("%w: approve_staging requires security_review state", app.ErrInvalidInput)
		}
		return domain.AdapterStateStagingApproved, nil
	case "activate":
		if current != domain.AdapterStateStagingApproved {
			return "", fmt.Errorf("%w: activate requires staging_approved state", app.ErrInvalidInput)
		}
		return domain.AdapterStateActive, nil
	case "deprecate":
		if current != domain.AdapterStateActive && current != domain.AdapterStateStagingApproved {
			return "", fmt.Errorf("%w: deprecate requires active or staging_approved state", app.ErrInvalidInput)
		}
		return domain.AdapterStateDeprecated, nil
	case "retire":
		if current == domain.AdapterStateActive {
			return "", fmt.Errorf("%w: retire active adapter version only after deprecation", app.ErrInvalidInput)
		}
		return domain.AdapterStateRetired, nil
	default:
		return "", fmt.Errorf("%w: unsupported adapter version action", app.ErrInvalidInput)
	}
}

func nullableJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

func normalizeProviderConnection(item domain.ProviderConnection) domain.ProviderConnection {
	if item.Config == nil {
		item.Config = map[string]string{}
	}
	if item.VerifiedAt.Equal(time.Unix(0, 0).UTC()) {
		item.VerifiedAt = time.Time{}
	}
	if item.RevokedAt.Equal(time.Unix(0, 0).UTC()) {
		item.RevokedAt = time.Time{}
	}
	return item
}

func reconciliationJobSelectSQL() string {
	return `SELECT id, tenant_id, connection_id, provider, state, dry_run, capture_missing, route_recovered, redeliver_failed, scope_object_id,
		COALESCE(window_start, 'epoch'::timestamptz), COALESCE(window_end, 'epoch'::timestamptz), cursor, reason,
		total_items, matched_items, missing_items, captured_items, redelivered_items, unrecoverable_items, failed_items, error,
		created_by, created_at, COALESCE(started_at, 'epoch'::timestamptz), COALESCE(completed_at, 'epoch'::timestamptz), COALESCE(canceled_at, 'epoch'::timestamptz)
		FROM reconciliation_jobs`
}

func scanReconciliationJob(row rowScanner) (domain.ReconciliationJob, error) {
	var item domain.ReconciliationJob
	err := row.Scan(&item.ID, &item.TenantID, &item.ConnectionID, &item.Provider, &item.State, &item.DryRun, &item.CaptureMissing, &item.RouteRecovered,
		&item.RedeliverFailed, &item.ScopeObjectID, &item.WindowStart, &item.WindowEnd, &item.Cursor, &item.Reason, &item.TotalItems,
		&item.MatchedItems, &item.MissingItems, &item.CapturedItems, &item.RedeliveredItems, &item.UnrecoverableItems, &item.FailedItems,
		&item.Error, &item.CreatedBy, &item.CreatedAt, &item.StartedAt, &item.CompletedAt, &item.CanceledAt)
	return item, err
}

func normalizeReconciliationJob(item domain.ReconciliationJob) domain.ReconciliationJob {
	epoch := time.Unix(0, 0).UTC()
	if item.WindowStart.Equal(epoch) {
		item.WindowStart = time.Time{}
	}
	if item.WindowEnd.Equal(epoch) {
		item.WindowEnd = time.Time{}
	}
	if item.StartedAt.Equal(epoch) {
		item.StartedAt = time.Time{}
	}
	if item.CompletedAt.Equal(epoch) {
		item.CompletedAt = time.Time{}
	}
	if item.CanceledAt.Equal(epoch) {
		item.CanceledAt = time.Time{}
	}
	return item
}

func scanReconciliationItem(row rowScanner) (domain.ReconciliationItem, error) {
	var item domain.ReconciliationItem
	err := row.Scan(&item.ID, &item.TenantID, &item.JobID, &item.Provider, &item.ProviderObjectID, &item.ProviderObjectType, &item.Outcome,
		&item.LocalEventID, &item.RecoveredEventID, &item.ProviderAPIEvidenceID, &item.RedeliveryRequested, &item.Error, &item.Metadata, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

type reconciliationItemInput struct {
	tenantID            string
	jobID               string
	provider            string
	objectID            string
	objectType          string
	outcome             string
	localEventID        string
	recoveredEventID    string
	evidenceID          string
	redeliveryRequested bool
	errText             string
	metadata            []byte
}

func (s *Store) insertReconciliationItem(ctx context.Context, input reconciliationItemInput) (string, error) {
	id := mustID("rci")
	if len(input.metadata) == 0 {
		input.metadata = []byte("{}")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO reconciliation_items(id, tenant_id, job_id, provider, provider_object_id, provider_object_type, outcome, local_event_id,
			recovered_event_id, provider_api_evidence_id, redelivery_requested, error, metadata_json)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)`,
		id, input.tenantID, input.jobID, input.provider, input.objectID, input.objectType, input.outcome, input.localEventID,
		input.recoveredEventID, input.evidenceID, input.redeliveryRequested, input.errText, string(input.metadata),
	)
	return id, err
}

func (s *Store) insertProviderAPIEvidence(ctx context.Context, tenantID, jobID, itemID, connectionID, providerName string, ev reconcile.Evidence) (string, error) {
	id := mustID("pae")
	body := ev.Body
	status := domain.ProviderAPIEvidenceStorageStatusStored
	if len(body) == 0 {
		status = domain.ProviderAPIEvidenceStorageStatusMetadata
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO provider_api_evidence(id, tenant_id, job_id, item_id, connection_id, provider, request_method, request_url,
			response_status, response_sha256, response_size_bytes, response_body, storage_status, error)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		id, tenantID, jobID, itemID, connectionID, providerName, ev.Method, redactProviderURL(ev.URL), ev.StatusCode,
		domain.HashSHA256(body), int64(len(body)), body, status, ev.Error,
	)
	return id, err
}

func (s *Store) findLocalProviderEvent(ctx context.Context, tenantID string, conn domain.ProviderConnection, providerObjectID string) (string, error) {
	query := `SELECT id FROM events WHERE tenant_id=$1 AND provider=$2 AND provider_event_id=$3`
	args := []any{tenantID, conn.Provider, providerObjectID}
	if sourceID := strings.TrimSpace(conn.Config["source_id"]); sourceID != "" {
		query += ` AND source_id=$4`
		args = append(args, sourceID)
	}
	query += ` ORDER BY received_at ASC LIMIT 1`
	var id string
	err := s.pool.QueryRow(ctx, query, args...).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func headerPairsFromMap(values map[string]string) []domain.HeaderPair {
	headers := []domain.HeaderPair{{Name: "Webhookery-Recovered-By", Value: "provider-api-reconciliation"}}
	for name, value := range values {
		headers = append(headers, domain.HeaderPair{Name: name, Value: value})
	}
	return headers
}

func redactProviderURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	query := parsed.Query()
	for key := range query {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "key") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") {
			query.Set(key, "redacted")
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (s *Store) completeReconciliationJob(ctx context.Context, tenantID, jobID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE reconciliation_jobs j
		SET state='completed',
		    total_items=counts.total,
		    matched_items=counts.matched,
		    missing_items=counts.missing,
		    captured_items=counts.captured,
		    redelivered_items=counts.redelivered,
		    unrecoverable_items=counts.unrecoverable,
		    failed_items=counts.failed,
		    completed_at=now()
		FROM (
			SELECT
				count(*)::int AS total,
				count(*) FILTER (WHERE outcome='matched')::int AS matched,
				count(*) FILTER (WHERE outcome='missing')::int AS missing,
				count(*) FILTER (WHERE outcome='captured')::int AS captured,
				count(*) FILTER (WHERE outcome='redelivery_requested')::int AS redelivered,
				count(*) FILTER (WHERE outcome='unrecoverable')::int AS unrecoverable,
				count(*) FILTER (WHERE outcome='failed')::int AS failed
			FROM reconciliation_items
			WHERE tenant_id=$1 AND job_id=$2
		) counts
		WHERE j.tenant_id=$1 AND j.id=$2 AND j.state <> 'canceled'`, tenantID, jobID)
	return err
}

func scanEvent(row rowScanner) (domain.Event, error) {
	var item domain.Event
	err := row.Scan(&item.ID, &item.TenantID, &item.SourceID, &item.Provider, &item.Type, &item.ProviderID, &item.RawPayloadID, &item.RawPayloadHash, &item.Verified, &item.VerifyReason, &item.DedupeKey, &item.DedupeStatus, &item.ReceivedAt, &item.TraceID)
	return item, err
}

func scanEventType(row rowScanner) (domain.EventType, error) {
	var item domain.EventType
	err := row.Scan(&item.TenantID, &item.Name, &item.Description, &item.State, &item.CreatedAt)
	return item, err
}

func scanEventSchema(row rowScanner) (domain.EventSchema, error) {
	var item domain.EventSchema
	err := row.Scan(&item.ID, &item.TenantID, &item.EventType, &item.Version, &item.Schema, &item.State, &item.CreatedAt)
	return item, err
}

func scanWorkerStatus(row rowScanner) (domain.WorkerStatus, error) {
	var item domain.WorkerStatus
	err := row.Scan(&item.WorkerID, &item.State, &item.LastSeenAt, &item.ExpiresAt)
	return item, err
}

func scanQueueStats(row rowScanner, tenantID string) (domain.QueueStats, error) {
	var item domain.QueueStats
	var oldest float64
	err := row.Scan(&item.Name, &item.Pending, &item.InProgress, &item.Completed, &item.Terminal, &item.DueNow, &oldest, &item.NextAvailableAt)
	item.TenantID = tenantID
	item.OldestPendingAgeSec = int64(oldest)
	return item, err
}

func scanMetricRollup(row rowScanner) (domain.MetricRollup, error) {
	var item domain.MetricRollup
	var dimensions []byte
	err := row.Scan(&item.ID, &item.TenantID, &item.MetricName, &item.BucketStart, &item.BucketSeconds, &dimensions, &item.DimensionsHash, &item.Value, &item.Source, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.MetricRollup{}, err
	}
	if len(dimensions) > 0 {
		if err := json.Unmarshal(dimensions, &item.Dimensions); err != nil {
			return domain.MetricRollup{}, err
		}
	}
	if item.Dimensions == nil {
		item.Dimensions = map[string]string{}
	}
	return item, nil
}

func scanAlertRule(row rowScanner) (domain.AlertRule, error) {
	var item domain.AlertRule
	var dimensions []byte
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.RuleType, &item.MetricName, &item.Threshold, &item.Comparator, &item.WindowSeconds, &dimensions, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.AlertRule{}, err
	}
	if len(dimensions) > 0 {
		if err := json.Unmarshal(dimensions, &item.Dimensions); err != nil {
			return domain.AlertRule{}, err
		}
	}
	if item.Dimensions == nil {
		item.Dimensions = map[string]string{}
	}
	return item, nil
}

func scanAlertFiring(row rowScanner) (domain.AlertFiring, error) {
	var item domain.AlertFiring
	err := row.Scan(&item.ID, &item.TenantID, &item.RuleID, &item.State, &item.ObservedValue, &item.Threshold, &item.Reason, &item.StartedAt, &item.LastEvaluatedAt,
		&item.AcknowledgedBy, &item.AcknowledgedAt, &item.ResolvedAt, &item.UpdatedAt)
	return item, err
}

func normalizeAlertFiring(item domain.AlertFiring) domain.AlertFiring {
	epoch := time.Unix(0, 0).UTC()
	if item.AcknowledgedAt.Equal(epoch) {
		item.AcknowledgedAt = time.Time{}
	}
	if item.ResolvedAt.Equal(epoch) {
		item.ResolvedAt = time.Time{}
	}
	return item
}

func scanNotificationChannel(row rowScanner) (domain.NotificationChannel, error) {
	var item domain.NotificationChannel
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.ChannelType, &item.URL, &item.State, &item.SecretHint, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func scanNotificationDelivery(row rowScanner) (domain.NotificationDelivery, error) {
	var item domain.NotificationDelivery
	err := row.Scan(&item.ID, &item.TenantID, &item.ChannelID, &item.FiringID, &item.Transition, &item.State, &item.BodySHA256, &item.AttemptCount, &item.NextAttemptAt, &item.LastAttemptAt, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func normalizeNotificationDelivery(item domain.NotificationDelivery) domain.NotificationDelivery {
	epoch := time.Unix(0, 0).UTC()
	if item.LastAttemptAt.Equal(epoch) {
		item.LastAttemptAt = time.Time{}
	}
	return item
}

func scanNotificationDeliveryAttempt(row rowScanner) (domain.NotificationDeliveryAttempt, error) {
	var item domain.NotificationDeliveryAttempt
	var response []byte
	err := row.Scan(&item.ID, &item.TenantID, &item.DeliveryID, &item.StatusCode, &item.FailureClass, &response, &item.ResponseTruncated, &item.Error, &item.CreatedAt)
	item.ResponseBody = string(response)
	return item, err
}

func scanSIEMSink(row rowScanner) (domain.SIEMSink, error) {
	var item domain.SIEMSink
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.SinkType, &item.URL, &item.State, &item.SecretHint, &item.CursorSequence, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func scanSIEMDelivery(row rowScanner) (domain.SIEMDelivery, error) {
	var item domain.SIEMDelivery
	err := row.Scan(&item.ID, &item.TenantID, &item.SinkID, &item.FromSequence, &item.ToSequence, &item.State, &item.BodySHA256, &item.AttemptCount, &item.NextAttemptAt, &item.LastAttemptAt, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func normalizeSIEMDelivery(item domain.SIEMDelivery) domain.SIEMDelivery {
	epoch := time.Unix(0, 0).UTC()
	if item.LastAttemptAt.Equal(epoch) {
		item.LastAttemptAt = time.Time{}
	}
	return item
}

func scanSIEMDeliveryAttempt(row rowScanner) (domain.SIEMDeliveryAttempt, error) {
	var item domain.SIEMDeliveryAttempt
	var response []byte
	err := row.Scan(&item.ID, &item.TenantID, &item.DeliveryID, &item.StatusCode, &item.FailureClass, &response, &item.ResponseTruncated, &item.Error, &item.CreatedAt)
	item.ResponseBody = string(response)
	return item, err
}

func scanRoute(row rowScanner) (domain.Route, error) {
	var item domain.Route
	err := row.Scan(&item.ID, &item.TenantID, &item.SourceID, &item.Name, &item.Priority, &item.EventTypes, &item.EndpointID, &item.State, &item.Version, &item.ActiveVersionID, &item.RetryPolicyID, &item.TransformationID, &item.TransformationVersionID, &item.CreatedAt)
	return item, err
}

func scanSubscription(row rowScanner) (domain.Subscription, error) {
	var item domain.Subscription
	err := row.Scan(&item.ID, &item.TenantID, &item.EndpointID, &item.EventTypes, &item.PayloadFormat, &item.TransformationID, &item.TransformationVersionID, &item.State, &item.Version, &item.ActiveVersionID, &item.CreatedAt)
	return item, err
}

func scanRouteVersion(row rowScanner) (domain.RouteVersion, error) {
	var item domain.RouteVersion
	err := row.Scan(&item.ID, &item.TenantID, &item.RouteID, &item.Version, &item.ConfigHash, &item.SourceID, &item.Name, &item.Priority, &item.EventTypes, &item.EndpointID, &item.RetryPolicyID, &item.TransformationID, &item.TransformationVersionID, &item.State, &item.CreatedBy, &item.CreatedAt)
	return item, err
}

func scanRetryPolicy(row rowScanner) (domain.RetryPolicy, error) {
	var item domain.RetryPolicy
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.Version, &item.State, &item.MaxAttempts, &item.MaxDurationSeconds, &item.InitialDelaySeconds, &item.MaxDelaySeconds, &item.RateLimitPerMinute, &item.CreatedBy, &item.CreatedAt)
	return item, err
}

func scanTransformation(row rowScanner) (domain.Transformation, error) {
	var item domain.Transformation
	err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.State, &item.ActiveVersionID, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func scanTransformationVersion(row rowScanner) (domain.TransformationVersion, error) {
	var item domain.TransformationVersion
	err := row.Scan(&item.ID, &item.TenantID, &item.TransformationID, &item.Version, &item.ConfigHash, &item.Operations, &item.State, &item.CreatedBy, &item.CreatedAt)
	return item, err
}

func scanDelivery(row rowScanner) (domain.Delivery, error) {
	var item domain.Delivery
	err := row.Scan(&item.ID, &item.TenantID, &item.EventID, &item.EndpointID, &item.RouteID, &item.RouteVersionID, &item.SubscriptionID, &item.SubscriptionVersionID, &item.RetryPolicyID, &item.ReplayJobID, &item.AdapterVersionID, &item.NormalizedEnvelopeID, &item.TransformationVersionID, &item.DeliveryPayloadID, &item.DeliveryPayloadSHA256, &item.RetrySeed, &item.State, &item.AttemptCount, &item.NextAttemptAt)
	return item, err
}

func scanDeliveryAttempt(row rowScanner) (domain.DeliveryAttempt, error) {
	var item domain.DeliveryAttempt
	err := row.Scan(&item.ID, &item.TenantID, &item.DeliveryID, &item.EventID, &item.EndpointID, &item.RequestSHA256, &item.ResponseSHA256, &item.AttemptNo, &item.State, &item.ResponseStatus, &item.ResponseBodyTruncated, &item.FailureClass, &item.Retryable, &item.RetryDelayMS, &item.NextRetryAt, &item.StartedAt, &item.CompletedAt)
	if item.NextRetryAt.Equal(time.Unix(0, 0).UTC()) {
		item.NextRetryAt = time.Time{}
	}
	return item, err
}

func (s *Store) getRoute(ctx context.Context, tenantID, routeID string) (domain.Route, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, tenant_id, source_id, name, priority, event_types, endpoint_id, state, version, active_version_id, retry_policy_id, transformation_id, transformation_version_id, created_at FROM routes WHERE tenant_id=$1 AND id=$2`, tenantID, routeID)
	item, err := scanRoute(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Route{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) insertRouteVersion(ctx context.Context, tx pgx.Tx, route domain.Route, actorID string) (domain.RouteVersion, error) {
	version := domain.RouteVersion{
		ID:                      mustID("rv"),
		TenantID:                route.TenantID,
		RouteID:                 route.ID,
		Version:                 route.Version,
		SourceID:                route.SourceID,
		Name:                    route.Name,
		Priority:                route.Priority,
		EventTypes:              append([]string(nil), route.EventTypes...),
		EndpointID:              route.EndpointID,
		RetryPolicyID:           route.RetryPolicyID,
		TransformationID:        route.TransformationID,
		TransformationVersionID: route.TransformationVersionID,
		State:                   route.State,
		CreatedBy:               actorID,
	}
	hash, err := s.insertConfigVersion(ctx, tx, route.TenantID, domain.ConfigResourceRoute, route.ID, route.Version, map[string]any{
		"route_id":                  route.ID,
		"source_id":                 route.SourceID,
		"name":                      route.Name,
		"priority":                  route.Priority,
		"event_types":               route.EventTypes,
		"endpoint_id":               route.EndpointID,
		"retry_policy_id":           route.RetryPolicyID,
		"transformation_id":         route.TransformationID,
		"transformation_version_id": route.TransformationVersionID,
		"state":                     route.State,
		"version":                   route.Version,
	}, actorID)
	if err != nil {
		return domain.RouteVersion{}, err
	}
	version.ConfigHash = hash
	err = tx.QueryRow(ctx, `
		INSERT INTO route_versions(id, tenant_id, route_id, version, config_hash, source_id, name, priority, event_types, endpoint_id, retry_policy_id, transformation_id, transformation_version_id, state, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		RETURNING created_at`,
		version.ID, version.TenantID, version.RouteID, version.Version, version.ConfigHash, version.SourceID,
		version.Name, version.Priority, version.EventTypes, version.EndpointID, version.RetryPolicyID,
		version.TransformationID, version.TransformationVersionID, version.State, version.CreatedBy,
	).Scan(&version.CreatedAt)
	return version, err
}

func (s *Store) insertSubscriptionVersion(ctx context.Context, tx pgx.Tx, subscription domain.Subscription, actorID string) (domain.SubscriptionVersion, error) {
	version := domain.SubscriptionVersion{
		ID:                      mustID("sv"),
		TenantID:                subscription.TenantID,
		SubscriptionID:          subscription.ID,
		Version:                 subscription.Version,
		EndpointID:              subscription.EndpointID,
		EventTypes:              append([]string(nil), subscription.EventTypes...),
		PayloadFormat:           subscription.PayloadFormat,
		TransformationID:        subscription.TransformationID,
		TransformationVersionID: subscription.TransformationVersionID,
		State:                   subscription.State,
		CreatedBy:               actorID,
	}
	hash, err := s.insertConfigVersion(ctx, tx, subscription.TenantID, domain.ConfigResourceSubscription, subscription.ID, subscription.Version, map[string]any{
		"subscription_id":           subscription.ID,
		"endpoint_id":               subscription.EndpointID,
		"event_types":               subscription.EventTypes,
		"payload_format":            subscription.PayloadFormat,
		"transformation_id":         subscription.TransformationID,
		"transformation_version_id": subscription.TransformationVersionID,
		"state":                     subscription.State,
		"version":                   subscription.Version,
	}, actorID)
	if err != nil {
		return domain.SubscriptionVersion{}, err
	}
	version.ConfigHash = hash
	err = tx.QueryRow(ctx, `
		INSERT INTO subscription_versions(id, tenant_id, subscription_id, version, config_hash, endpoint_id, event_types, payload_format, transformation_id, transformation_version_id, state, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING created_at`,
		version.ID, version.TenantID, version.SubscriptionID, version.Version, version.ConfigHash,
		version.EndpointID, version.EventTypes, version.PayloadFormat, version.TransformationID,
		version.TransformationVersionID, version.State, version.CreatedBy,
	).Scan(&version.CreatedAt)
	return version, err
}

func (s *Store) insertTransformationVersion(ctx context.Context, tx pgx.Tx, tenantID, transformationID, actorID string, operationsRaw []byte, state string) (domain.TransformationVersion, error) {
	ops, err := transform.ParseOperations(operationsRaw)
	if err != nil {
		return domain.TransformationVersion{}, err
	}
	operationsJSON, err := json.Marshal(ops)
	if err != nil {
		return domain.TransformationVersion{}, err
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1 FROM transformation_versions WHERE tenant_id=$1 AND transformation_id=$2`, tenantID, transformationID).Scan(&version); err != nil {
		return domain.TransformationVersion{}, err
	}
	item := domain.TransformationVersion{
		ID:               mustID("trv"),
		TenantID:         tenantID,
		TransformationID: transformationID,
		Version:          version,
		Operations:       operationsJSON,
		State:            state,
		CreatedBy:        actorID,
	}
	hash, err := s.insertConfigVersion(ctx, tx, tenantID, domain.ConfigResourceTransformation, transformationID, version, map[string]any{
		"transformation_id": transformationID,
		"operations":        ops,
		"state":             state,
		"version":           version,
	}, actorID)
	if err != nil {
		return domain.TransformationVersion{}, err
	}
	item.ConfigHash = hash
	err = tx.QueryRow(ctx, `
		INSERT INTO transformation_versions(id, tenant_id, transformation_id, version, config_hash, operations_json, state, created_by)
		VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)
		RETURNING created_at`,
		item.ID, item.TenantID, item.TransformationID, item.Version, item.ConfigHash, string(item.Operations), item.State, item.CreatedBy,
	).Scan(&item.CreatedAt)
	return item, err
}

func (s *Store) insertConfigVersion(ctx context.Context, tx pgx.Tx, tenantID, resourceType, resourceID string, version int, config any, actorID string) (string, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	hash := domain.HashSHA256(raw)
	_, err = tx.Exec(ctx, `
		INSERT INTO config_versions(id, tenant_id, resource_type, resource_id, version, config_hash, config_json, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)
		ON CONFLICT (tenant_id, resource_type, resource_id, version) DO NOTHING`,
		mustID("cfg"), tenantID, resourceType, resourceID, version, hash, string(raw), actorID,
	)
	return hash, err
}

func (s *Store) nextConfigVersion(ctx context.Context, tx pgx.Tx, tenantID, resourceType, resourceID string) (int, error) {
	var version int
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(max(version),0)+1
		FROM config_versions
		WHERE tenant_id=$1 AND resource_type=$2 AND resource_id=$3`,
		tenantID, resourceType, resourceID,
	).Scan(&version)
	return version, err
}

func deliveryRetrySeed(tenantID, deliveryID, eventID, endpointID string) string {
	return retry.Seed(tenantID, deliveryID, eventID, endpointID)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (s *Store) retryPolicyForDelivery(ctx context.Context, tx pgx.Tx, tenantID, retryPolicyID string) (retry.Policy, error) {
	if retryPolicyID == "" {
		return retry.DefaultPolicy(), nil
	}
	var policy domain.RetryPolicy
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, name, version, state, max_attempts, max_duration_seconds, initial_delay_seconds, max_delay_seconds, rate_limit_per_minute, created_by, created_at
		FROM retry_policies
		WHERE tenant_id=$1 AND id=$2 AND state='active'`,
		tenantID, retryPolicyID,
	).Scan(&policy.ID, &policy.TenantID, &policy.Name, &policy.Version, &policy.State, &policy.MaxAttempts, &policy.MaxDurationSeconds, &policy.InitialDelaySeconds, &policy.MaxDelaySeconds, &policy.RateLimitPerMinute, &policy.CreatedBy, &policy.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return retry.Policy{}, app.ErrNotFound
	}
	if err != nil {
		return retry.Policy{}, err
	}
	return retry.Policy{
		MaxAttempts:  policy.MaxAttempts,
		MaxDuration:  time.Duration(policy.MaxDurationSeconds) * time.Second,
		InitialDelay: time.Duration(policy.InitialDelaySeconds) * time.Second,
		MaxDelay:     time.Duration(policy.MaxDelaySeconds) * time.Second,
	}, nil
}

func nextSecretVersion(ctx context.Context, tx pgx.Tx, table, tenantID, resourceID string, gracePeriodHours int) (int, time.Time, error) {
	query := ""
	switch table {
	case "source_secret_versions":
		query = `SELECT COALESCE(max(version),0)+1 FROM source_secret_versions WHERE tenant_id=$1 AND source_id=$2`
	case "endpoint_secrets":
		query = `SELECT COALESCE(max(version),0)+1 FROM endpoint_secrets WHERE tenant_id=$1 AND endpoint_id=$2`
	default:
		return 0, time.Time{}, fmt.Errorf("unsupported secret version table %q", table)
	}
	var version int
	if err := tx.QueryRow(ctx, query, tenantID, resourceID).Scan(&version); err != nil {
		return 0, time.Time{}, err
	}
	if gracePeriodHours == 0 {
		gracePeriodHours = 72
	}
	return version, time.Now().UTC().Add(time.Duration(gracePeriodHours) * time.Hour), nil
}

func normalizeSourceSecretVersion(item domain.SourceSecretVersion) domain.SourceSecretVersion {
	if item.ExpiresAt.Equal(time.Unix(0, 0)) {
		item.ExpiresAt = time.Time{}
	}
	if item.RevokedAt.Equal(time.Unix(0, 0)) {
		item.RevokedAt = time.Time{}
	}
	return item
}

func normalizeEndpointSecretVersion(item domain.EndpointSecretVersion) domain.EndpointSecretVersion {
	if item.ExpiresAt.Equal(time.Unix(0, 0)) {
		item.ExpiresAt = time.Time{}
	}
	if item.RevokedAt.Equal(time.Unix(0, 0)) {
		item.RevokedAt = time.Time{}
	}
	return item
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(value, needle) {
			return true
		}
	}
	return false
}

func listRows(ctx context.Context, pool *pgxpool.Pool, query string, args ...any) ([]map[string]any, error) {
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	var out []map[string]any
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		item := make(map[string]any, len(values))
		for i, value := range values {
			item[string(fields[i].Name)] = value
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanCounts(ctx context.Context, pool *pgxpool.Pool, query string, args []any, out map[string]int64) error {
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return err
		}
		out[key] = count
	}
	return rows.Err()
}

func tenantPredicate(tenantID string) (string, []any) {
	if tenantID == "" {
		return "", nil
	}
	return " WHERE tenant_id=$1", []any{tenantID}
}

func tenantAnd(tenantID string) string {
	if tenantID == "" {
		return ""
	}
	return " AND tenant_id=$1"
}

func rollback(ctx context.Context, tx pgx.Tx) {
	_ = tx.Rollback(ctx)
}

func upsertWorkerLease(ctx context.Context, tx pgx.Tx, workerID string) error {
	if workerID == "" {
		workerID = "worker"
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO worker_leases(id, worker_id, expires_at)
		VALUES($1,$1,now() + interval '60 seconds')
		ON CONFLICT (id) DO UPDATE SET worker_id=EXCLUDED.worker_id, expires_at=EXCLUDED.expires_at, updated_at=now()`,
		workerID,
	)
	return err
}

func tryAcquireWorkerLease(ctx context.Context, tx pgx.Tx, leaseID, workerID string, ttl time.Duration) (bool, error) {
	leaseID = strings.TrimSpace(leaseID)
	if leaseID == "" {
		leaseID = "worker"
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		workerID = "worker"
	}
	seconds := int64(ttl.Seconds())
	if seconds <= 0 {
		seconds = 60
	}
	var acquired bool
	err := tx.QueryRow(ctx, `
		WITH acquired AS (
			INSERT INTO worker_leases(id, worker_id, expires_at)
			VALUES($1,$2,now() + ($3 * interval '1 second'))
			ON CONFLICT (id) DO UPDATE
			SET worker_id=EXCLUDED.worker_id, expires_at=EXCLUDED.expires_at, updated_at=now()
			WHERE worker_leases.expires_at <= now() OR worker_leases.worker_id=EXCLUDED.worker_id
			RETURNING 1
		)
		SELECT EXISTS(SELECT 1 FROM acquired)`,
		leaseID, workerID, seconds,
	).Scan(&acquired)
	return acquired, err
}

func mustID(prefix string) string {
	id, err := random.Token(prefix, 18)
	if err != nil {
		panic(fmt.Sprintf("generate id: %v", err))
	}
	return id
}

var _ app.IngestStore = (*Store)(nil)
var _ app.ControlStore = (*Store)(nil)
var _ app.DeliveryFanoutStore = (*Store)(nil)
var _ app.ReconciliationWorkStore = (*Store)(nil)
var _ app.APIKeyLookup = (*Store)(nil)
var _ worker.OutboxStore = (*Store)(nil)
var _ worker.DeliveryStore = (*Store)(nil)
var _ worker.RetentionStore = (*Store)(nil)
var _ worker.AuditChainBackfillStore = (*Store)(nil)
var _ = time.Now
