package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/blobstore"
	"webhookery/internal/domain"
	"webhookery/internal/evidence"
	"webhookery/internal/random"
	"webhookery/internal/retry"
	"webhookery/internal/transform"
	"webhookery/internal/worker"
)

type SecretBox interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

type Store struct {
	pool           *pgxpool.Pool
	box            SecretBox
	rawStorageMode string
	objectStore    blobstore.Store
	objectBucket   string
}

type StoreOptions struct {
	RawStorageMode string
	ObjectStore    blobstore.Store
	ObjectBucket   string
}

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
	return &Store{
		pool:           pool,
		box:            box,
		rawStorageMode: opts.RawStorageMode,
		objectStore:    opts.ObjectStore,
		objectBucket:   strings.TrimSpace(opts.ObjectBucket),
	}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Health(ctx context.Context) error {
	return s.pool.Ping(ctx)
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
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'api_key.created','api_key',$4,$5)`, mustID("aud"), key.TenantID, input.ActorID, key.ID, key.Name); err != nil {
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
	var item domain.APIKey
	err := s.pool.QueryRow(ctx, `
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
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'api_key.revoked','api_key',$4,$5)`, mustID("aud"), tenantID, actorID, apiKeyID, reason)
	return item, nil
}

func (s *Store) CreateSource(ctx context.Context, source domain.Source) (domain.Source, error) {
	if source.ID == "" {
		source.ID = mustID("src")
	}
	if source.State == "" {
		source.State = domain.StateActive
	}
	encrypted, err := s.box.Encrypt(source.VerificationSecret)
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
	}, ""); err != nil {
		return domain.Source{}, err
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
		plain, err := s.box.Decrypt(encrypted)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, plain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(secrets) == 0 && len(fallbackEncrypted) > 0 {
		plain, err := s.box.Decrypt(fallbackEncrypted)
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
	err = tx.QueryRow(ctx, `
		INSERT INTO endpoints(id, tenant_id, name, url, state, retry_policy_id)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING created_at`,
		endpoint.ID, endpoint.TenantID, endpoint.Name, endpoint.URL, endpoint.State, endpoint.RetryPolicyID,
	).Scan(&endpoint.CreatedAt)
	if err != nil {
		return domain.Endpoint{}, err
	}
	secret, err := random.Token("whsec_out", 32)
	if err != nil {
		return domain.Endpoint{}, err
	}
	encrypted, err := s.box.Encrypt([]byte(secret))
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
	}, ""); err != nil {
		return domain.Endpoint{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Endpoint{}, err
	}
	return endpoint, nil
}

func (s *Store) ListEndpoints(ctx context.Context, tenantID string, limit int) ([]domain.Endpoint, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, name, url, state, retry_policy_id, circuit_state, failure_count, COALESCE(disabled_until, 'epoch'::timestamptz), created_at FROM endpoints WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Endpoint
	for rows.Next() {
		var item domain.Endpoint
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.URL, &item.State, &item.RetryPolicyID, &item.CircuitState, &item.FailureCount, &item.DisabledUntil, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
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
	encrypted, err := s.box.Encrypt(nil)
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
	if _, err := tx.Exec(ctx, `INSERT INTO deliveries(id, tenant_id, event_id, endpoint_id, state, next_attempt_at) VALUES($1,$2,$3,$4,'scheduled',now())`, deliveryID, tenantID, eventID, endpointID); err != nil {
		return domain.Delivery{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO dedupe_records(tenant_id, source_id, dedupe_key, first_event_id, status) VALUES($1,$2,$3,$4,$5) ON CONFLICT (tenant_id, dedupe_key) DO UPDATE SET last_seen_at=now(), status=EXCLUDED.status`, tenantID, sourceID, dedupeKey, eventID, domain.DedupeUnique); err != nil {
		return domain.Delivery{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'endpoint.test_requested','endpoint',$4,$5)`, mustID("aud"), tenantID, actorID, endpointID, reason); err != nil {
		return domain.Delivery{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Delivery{}, err
	}
	return domain.Delivery{ID: deliveryID, TenantID: tenantID, EventID: eventID, EndpointID: endpointID, State: "scheduled", NextAttemptAt: time.Now().UTC()}, nil
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
	version, err := s.insertRouteVersion(ctx, tx, route, "")
	if err != nil {
		return domain.Route{}, err
	}
	route.ActiveVersionID = version.ID
	if _, err := tx.Exec(ctx, `UPDATE routes SET active_version_id=$1 WHERE tenant_id=$2 AND id=$3`, version.ID, route.TenantID, route.ID); err != nil {
		return domain.Route{}, err
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
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'route.activated','route',$4,$5)`, mustID("aud"), tenantID, actorID, routeID, reason); err != nil {
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
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'retry_policy.created','retry_policy',$4,$5)`, mustID("aud"), tenantID, actorID, item.ID, item.Name); err != nil {
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
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'transformation.created','transformation',$4,$5)`, mustID("aud"), tenantID, actorID, item.ID, item.Name); err != nil {
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
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'transformation_version.created','transformation',$4,$5)`, mustID("aud"), tenantID, actorID, transformationID, item.ConfigHash); err != nil {
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
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'transformation_version.activated','transformation',$4,$5)`, mustID("aud"), tenantID, actorID, transformationID, reason); err != nil {
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
		var item domain.EventSchema
		if err := rows.Scan(&item.ID, &item.TenantID, &item.EventType, &item.Version, &item.Schema, &item.State, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetEventSchema(ctx context.Context, tenantID, eventType, version string) (domain.EventSchema, error) {
	var item domain.EventSchema
	err := s.pool.QueryRow(ctx, `SELECT id, tenant_id, event_type, version, schema_json, state, created_at FROM event_schemas WHERE tenant_id=$1 AND event_type=$2 AND version=$3`, tenantID, eventType, version).
		Scan(&item.ID, &item.TenantID, &item.EventType, &item.Version, &item.Schema, &item.State, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.EventSchema{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) RotateSourceSecret(ctx context.Context, tenantID, sourceID, actorID string, req app.RotateSourceSecretRequest) (domain.SourceSecretVersion, error) {
	encrypted, err := s.box.Encrypt([]byte(req.NewSecret))
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
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'source_secret.rotated','source',$4,$5)`, mustID("aud"), tenantID, actorID, sourceID, req.Reason); err != nil {
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
	encrypted, err := s.box.Encrypt([]byte(secret))
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
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'endpoint_secret.rotated','endpoint',$4,$5)`, mustID("aud"), tenantID, actorID, endpointID, req.Reason); err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.EndpointSecretVersion{}, err
	}
	return normalizeEndpointSecretVersion(item), nil
}

func (s *Store) CaptureInbound(ctx context.Context, input app.CaptureInboundInput) (app.CaptureInboundResult, error) {
	eventID := mustID("evt")
	rawID := mustID("raw")
	receiptID := mustID("rcp")
	outboxID := mustID("out")
	storage, bodyForDB, err := s.prepareRawPayloadStorage(ctx, input.Source.TenantID, rawID, input.RawPayload)
	if err != nil {
		return app.CaptureInboundResult{}, err
	}
	objectWritten := storage.backend == domain.RawStorageS3
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(context.Background(), storage.bucket, storage.key)
		}
		return app.CaptureInboundResult{}, err
	}
	defer rollback(ctx, tx)

	if _, err := tx.Exec(ctx, "INSERT INTO tenants(id, name) VALUES($1, $1) ON CONFLICT (id) DO NOTHING", input.Source.TenantID); err != nil {
		return app.CaptureInboundResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO raw_payloads(id, tenant_id, sha256, content_type, size_bytes, body, storage_backend, object_bucket, object_key, storage_status, created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		rawID, input.Source.TenantID, input.RawPayload.SHA256, input.RawPayload.ContentType, input.RawPayload.SizeBytes, bodyForDB,
		storage.backend, storage.bucket, storage.key, domain.StorageStatusStored, input.RawPayload.CreatedAt,
	); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(context.Background(), storage.bucket, storage.key)
		}
		return app.CaptureInboundResult{}, err
	}

	var existingEventID string
	err = tx.QueryRow(ctx, `SELECT id FROM events WHERE tenant_id=$1 AND dedupe_key=$2`, input.Source.TenantID, input.Event.DedupeKey).Scan(&existingEventID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return app.CaptureInboundResult{}, err
	}
	dedupeStatus := domain.DedupeUnique
	if existingEventID != "" {
		eventID = existingEventID
		dedupeStatus = domain.DedupeDuplicateSuppressed
	} else {
		if input.Event.Type == "" {
			input.Event.Type = "unknown"
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO events(id, tenant_id, source_id, provider, type, provider_event_id, raw_payload_id, raw_payload_hash,
				signature_verified, verification_reason, dedupe_key, dedupe_status, received_at, trace_id)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			eventID, input.Source.TenantID, input.Source.ID, input.Source.Provider, input.Event.Type, input.Event.ProviderID,
			rawID, input.RawPayload.SHA256, input.VerificationOK, input.VerifyReason, input.Event.DedupeKey, dedupeStatus,
			input.Event.ReceivedAt, input.Event.TraceID,
		); err != nil {
			return app.CaptureInboundResult{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE raw_payloads SET event_id=$1 WHERE id=$2`, eventID, rawID); err != nil {
			return app.CaptureInboundResult{}, err
		}
		if len(input.Normalized.Envelope) > 0 {
			adapterVersionID, err := s.lookupAdapterVersionID(ctx, tx, firstNonEmpty(input.Source.Adapter, input.Source.Provider))
			if err != nil {
				return app.CaptureInboundResult{}, err
			}
			normalizedID := mustID("nenv")
			if _, err := tx.Exec(ctx, `
				INSERT INTO normalized_envelopes(id, tenant_id, event_id, adapter_version_id, provider, provider_event_id, type, source, subject,
					envelope_json, data_json, metadata_json, envelope_sha256, data_sha256, metadata_sha256, storage_status, created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13,$14,$15,$16,$17)`,
				normalizedID, input.Source.TenantID, eventID, adapterVersionID, input.Normalized.Provider, input.Normalized.ProviderEventID,
				input.Normalized.Type, input.Normalized.Source, input.Normalized.Subject, string(input.Normalized.Envelope),
				string(input.Normalized.Data), string(input.Normalized.Metadata), input.Normalized.EnvelopeSHA256, input.Normalized.DataSHA256,
				input.Normalized.MetadataSHA256, domain.StorageStatusStored, input.Normalized.CreatedAt,
			); err != nil {
				return app.CaptureInboundResult{}, err
			}
		}
		payload, _ := json.Marshal(map[string]any{"event_id": eventID})
		if _, err := tx.Exec(ctx, `INSERT INTO outbox(id, tenant_id, kind, resource_id, payload) VALUES($1,$2,$3,$4,$5)`, outboxID, input.Source.TenantID, "route_event", eventID, payload); err != nil {
			return app.CaptureInboundResult{}, err
		}
	}

	headersJSON, err := json.Marshal(input.Receipt.RawHeaders)
	if err != nil {
		return app.CaptureInboundResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO provider_receipts(id, tenant_id, source_id, event_id, raw_payload_id, raw_headers, remote_ip, verification_ok, verification_reason, received_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		receiptID, input.Source.TenantID, input.Source.ID, eventID, rawID, headersJSON, input.Receipt.RemoteIP,
		input.VerificationOK, input.VerifyReason, input.Receipt.ReceivedAt,
	); err != nil {
		return app.CaptureInboundResult{}, err
	}
	if input.Event.DedupeKey != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO idempotency_records(tenant_id, dedupe_key, resource_type, resource_id, status_code)
			VALUES($1,$2,'event',$3,202)
			ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`,
			input.Source.TenantID, input.Event.DedupeKey, eventID,
		); err != nil {
			return app.CaptureInboundResult{}, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO dedupe_records(tenant_id, source_id, dedupe_key, first_event_id, last_receipt_id, status)
			VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT (tenant_id, dedupe_key) DO UPDATE
			SET last_receipt_id=EXCLUDED.last_receipt_id, status=EXCLUDED.status, last_seen_at=now()`,
			input.Source.TenantID, input.Source.ID, input.Event.DedupeKey, eventID, receiptID, dedupeStatus,
		); err != nil {
			return app.CaptureInboundResult{}, err
		}
	}
	if !input.VerificationOK {
		if _, err := tx.Exec(ctx, `INSERT INTO quarantine_entries(id, tenant_id, event_id, reason) VALUES($1,$2,$3,$4)`, mustID("qua"), input.Source.TenantID, eventID, input.VerifyReason); err != nil {
			return app.CaptureInboundResult{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(context.Background(), storage.bucket, storage.key)
		}
		return app.CaptureInboundResult{}, err
	}
	return app.CaptureInboundResult{EventID: eventID, ReceiptID: receiptID, RawPayloadID: rawID, DedupeStatus: dedupeStatus}, nil
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
		return rawPayloadStorage{}, nil, err
	}
	return rawPayloadStorage{backend: domain.RawStorageS3, bucket: s.objectBucket, key: key}, []byte{}, nil
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
			return domain.RawPayload{}, err
		}
		if domain.HashSHA256(body) != raw.SHA256 {
			return domain.RawPayload{}, errors.New("raw payload object hash mismatch")
		}
		raw.Body = body
	}
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'raw_payload.read','event',$4,'')`, mustID("aud"), tenantID, actorID, eventID)
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
		_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'normalized_envelope.data_read','event',$4,'')`, mustID("aud"), tenantID, actorID, eventID)
	} else {
		item.Data = nil
	}
	return item, nil
}

func (s *Store) ListEventTimeline(ctx context.Context, tenantID, eventID string, limit int) ([]map[string]any, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM events WHERE tenant_id=$1 AND id=$2)`, tenantID, eventID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, app.ErrNotFound
	}
	return listRows(ctx, s.pool, `
		SELECT kind, ref_id, state, detail, occurred_at FROM (
			SELECT 'event' AS kind, id AS ref_id, dedupe_status AS state, verification_reason AS detail, received_at AS occurred_at
			FROM events WHERE tenant_id=$1 AND id=$2
			UNION ALL
			SELECT 'receipt' AS kind, id AS ref_id, CASE WHEN verification_ok THEN 'verified' ELSE 'rejected' END AS state, verification_reason AS detail, received_at AS occurred_at
			FROM provider_receipts WHERE tenant_id=$1 AND event_id=$2
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
			SELECT 'attempt' AS kind, id AS ref_id, state, failure_class AS detail, COALESCE(completed_at, started_at) AS occurred_at
			FROM delivery_attempts WHERE tenant_id=$1 AND event_id=$2
			UNION ALL
			SELECT 'audit' AS kind, id AS ref_id, action AS state, reason AS detail, occurred_at
			FROM audit_events WHERE tenant_id=$1 AND resource_id=$2
		) timeline
		ORDER BY occurred_at ASC
		LIMIT $3`, tenantID, eventID, limit)
}

func (s *Store) ListDeliveries(ctx context.Context, tenantID string, limit int) ([]domain.Delivery, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, event_id, endpoint_id, COALESCE(route_id,''), COALESCE(route_version_id,''), COALESCE(subscription_id,''), COALESCE(subscription_version_id,''), COALESCE(retry_policy_id,''), COALESCE(replay_job_id,''), COALESCE(adapter_version_id,''), COALESCE(normalized_envelope_id,''), COALESCE(transformation_version_id,''), COALESCE(delivery_payload_id,''), state, attempt_count, COALESCE(next_attempt_at, 'epoch'::timestamptz) FROM deliveries WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
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
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, delivery_id, event_id, endpoint_id, request_sha256, response_sha256, attempt_no, state, COALESCE(response_status, 0), response_body_truncated, failure_class, retryable, started_at, COALESCE(completed_at, started_at) FROM delivery_attempts WHERE tenant_id=$1 AND delivery_id=$2 ORDER BY attempt_no DESC LIMIT $3`, tenantID, deliveryID, limit)
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
	row := s.pool.QueryRow(ctx, `SELECT id, tenant_id, delivery_id, event_id, endpoint_id, request_sha256, response_sha256, attempt_no, state, COALESCE(response_status, 0), response_body_truncated, failure_class, retryable, started_at, COALESCE(completed_at, started_at) FROM delivery_attempts WHERE tenant_id=$1 AND id=$2`, tenantID, attemptID)
	item, err := scanDeliveryAttempt(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.DeliveryAttempt{}, app.ErrNotFound
	}
	return item, err
}

func (s *Store) RetryDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.Delivery, error) {
	row := s.pool.QueryRow(ctx, `UPDATE deliveries SET state='scheduled', next_attempt_at=now(), locked_by=NULL, lock_expires_at=NULL WHERE tenant_id=$1 AND id=$2 RETURNING id, tenant_id, event_id, endpoint_id, COALESCE(route_id,''), COALESCE(route_version_id,''), COALESCE(subscription_id,''), COALESCE(subscription_version_id,''), COALESCE(retry_policy_id,''), COALESCE(replay_job_id,''), COALESCE(adapter_version_id,''), COALESCE(normalized_envelope_id,''), COALESCE(transformation_version_id,''), COALESCE(delivery_payload_id,''), state, attempt_count, COALESCE(next_attempt_at, 'epoch'::timestamptz)`, tenantID, deliveryID)
	item, err := scanDelivery(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Delivery{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Delivery{}, err
	}
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,$4,$5,$6,$7)`, mustID("aud"), tenantID, actorID, "delivery.retry_requested", "delivery", deliveryID, reason)
	return item, nil
}

func (s *Store) CancelDelivery(ctx context.Context, tenantID, deliveryID, actorID, reason string) (domain.Delivery, error) {
	row := s.pool.QueryRow(ctx, `UPDATE deliveries SET state='canceled', locked_by=NULL, lock_expires_at=NULL WHERE tenant_id=$1 AND id=$2 AND state NOT IN ('succeeded','dead_lettered','canceled') RETURNING id, tenant_id, event_id, endpoint_id, COALESCE(route_id,''), COALESCE(route_version_id,''), COALESCE(subscription_id,''), COALESCE(subscription_version_id,''), COALESCE(retry_policy_id,''), COALESCE(replay_job_id,''), COALESCE(adapter_version_id,''), COALESCE(normalized_envelope_id,''), COALESCE(transformation_version_id,''), COALESCE(delivery_payload_id,''), state, attempt_count, COALESCE(next_attempt_at, 'epoch'::timestamptz)`, tenantID, deliveryID)
	item, err := scanDelivery(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Delivery{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Delivery{}, err
	}
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'delivery.canceled','delivery',$4,$5)`, mustID("aud"), tenantID, actorID, deliveryID, reason)
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
	metrics := domain.OpsMetrics{DeliveriesByState: map[string]int64{}, ReplayJobsByState: map[string]int64{}}
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
	if err := scanCounts(ctx, s.pool, "SELECT state, count(*) FROM deliveries"+predicate+" GROUP BY state", args, metrics.DeliveriesByState); err != nil {
		return metrics, err
	}
	if err := scanCounts(ctx, s.pool, "SELECT state, count(*) FROM replay_jobs"+predicate+" GROUP BY state", args, metrics.ReplayJobsByState); err != nil {
		return metrics, err
	}
	return metrics, nil
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

func (s *Store) ListRetentionPolicies(ctx context.Context, tenantID string, limit int) ([]domain.RetentionPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, resource_type, source_id, retention_days, state, created_by, created_at, updated_at
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
		INSERT INTO retention_policies(id, tenant_id, resource_type, source_id, retention_days, state, created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (tenant_id, resource_type, source_id) DO UPDATE
		SET retention_days=EXCLUDED.retention_days, state=EXCLUDED.state, updated_at=now()
		RETURNING id, tenant_id, resource_type, source_id, retention_days, state, created_by, created_at, updated_at`,
		id, tenantID, req.ResourceType, req.SourceID, req.RetentionDays, req.State, actorID,
	).Scan(&item.ID, &item.TenantID, &item.ResourceType, &item.SourceID, &item.RetentionDays, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.RetentionPolicy{}, err
	}
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'retention_policy.upserted','retention_policy',$4,$5)`, mustID("aud"), tenantID, actorID, item.ID, item.ResourceType)
	return item, nil
}

func (s *Store) UpdateRetentionPolicy(ctx context.Context, tenantID, policyID, actorID string, req app.UpdateRetentionPolicyRequest) (domain.RetentionPolicy, error) {
	var existing domain.RetentionPolicy
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, resource_type, source_id, retention_days, state, created_by, created_at, updated_at
		FROM retention_policies
		WHERE tenant_id=$1 AND id=$2`, tenantID, policyID).
		Scan(&existing.ID, &existing.TenantID, &existing.ResourceType, &existing.SourceID, &existing.RetentionDays, &existing.State, &existing.CreatedBy, &existing.CreatedAt, &existing.UpdatedAt)
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
	err = s.pool.QueryRow(ctx, `
		UPDATE retention_policies
		SET source_id=$1, retention_days=$2, state=$3, updated_at=now()
		WHERE tenant_id=$4 AND id=$5
		RETURNING id, tenant_id, resource_type, source_id, retention_days, state, created_by, created_at, updated_at`,
		existing.SourceID, existing.RetentionDays, existing.State, tenantID, policyID,
	).Scan(&existing.ID, &existing.TenantID, &existing.ResourceType, &existing.SourceID, &existing.RetentionDays, &existing.State, &existing.CreatedBy, &existing.CreatedAt, &existing.UpdatedAt)
	if err != nil {
		return domain.RetentionPolicy{}, err
	}
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'retention_policy.updated','retention_policy',$4,$5)`, mustID("aud"), tenantID, actorID, policyID, existing.ResourceType)
	return existing, nil
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
	bundle, err := evidence.BuildTarGzipBundle(evidence.Manifest{
		ExportID:             id,
		TenantID:             tenantID,
		CreatedAt:            now,
		From:                 req.From,
		To:                   req.To,
		IncludeRawPayloads:   req.IncludeRawPayloads,
		IncludeTimelines:     req.IncludeTimelines,
		IncludePayloadBodies: req.IncludePayloadBodies,
	}, files)
	if err != nil {
		return domain.EvidenceExport{}, err
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
			_ = s.objectStore.Delete(context.Background(), objectBucket, objectKey)
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
			_ = s.objectStore.Delete(context.Background(), objectBucket, objectKey)
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
				_ = s.objectStore.Delete(context.Background(), objectBucket, objectKey)
			}
			return domain.EvidenceExport{}, err
		}
	}
	reason := req.Reason
	if reason == "" {
		reason = "audit export"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'audit_export.created','audit_export',$4,$5)`, mustID("aud"), tenantID, actorID, id, reason); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(context.Background(), objectBucket, objectKey)
		}
		return domain.EvidenceExport{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		if objectWritten {
			_ = s.objectStore.Delete(context.Background(), objectBucket, objectKey)
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
			return app.EvidenceExportDownload{}, err
		}
	}
	if len(body) == 0 {
		return app.EvidenceExportDownload{}, app.ErrGone
	}
	if evidence.SHA256(body) != out.SHA256 {
		return app.EvidenceExportDownload{}, errors.New("audit export bundle hash mismatch")
	}
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'audit_export.downloaded','audit_export',$4,'')`, mustID("aud"), tenantID, actorID, exportID)
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
		SELECT id, tenant_id, resource_type, source_id, retention_days, state, created_by, created_at, updated_at
		FROM retention_policies
		WHERE state='active'
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

func (s *Store) ReleaseDeadLetter(ctx context.Context, tenantID, entryID, actorID, reason string) (app.ReplayJob, error) {
	var deliveryID, eventID string
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(delivery_id,''), COALESCE(event_id,'') FROM dead_letter_entries WHERE tenant_id=$1 AND id=$2 AND state='open'`, tenantID, entryID).Scan(&deliveryID, &eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ReplayJob{}, app.ErrNotFound
	}
	if err != nil {
		return app.ReplayJob{}, err
	}
	req := app.ReplayRequest{DeliveryID: deliveryID, EventID: eventID, Reason: reason}
	job, err := s.CreateReplay(ctx, tenantID, actorID, req)
	if err != nil {
		return app.ReplayJob{}, err
	}
	if _, err := s.pool.Exec(ctx, `UPDATE dead_letter_entries SET state='released' WHERE tenant_id=$1 AND id=$2`, tenantID, entryID); err != nil {
		return app.ReplayJob{}, err
	}
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'dead_letter.released','dead_letter_entry',$4,$5)`, mustID("aud"), tenantID, actorID, entryID, reason)
	return job, nil
}

func (s *Store) BulkReleaseDeadLetter(ctx context.Context, tenantID string, entryIDs []string, actorID, reason string) ([]app.ReplayJob, error) {
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
		job, err := s.ReleaseDeadLetter(ctx, tenantID, entryID, actorID, reason)
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
	var eventID string
	err := s.pool.QueryRow(ctx, `UPDATE quarantine_entries SET state='approved' WHERE tenant_id=$1 AND id=$2 AND state='open' RETURNING COALESCE(event_id,'')`, tenantID, entryID).Scan(&eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, app.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'quarantine.approved','quarantine_entry',$4,$5)`, mustID("aud"), tenantID, actorID, entryID, reason)
	if routeAfterRelease && eventID != "" {
		if _, err := s.createDeliveriesForEvent(ctx, tenantID, eventID); err != nil {
			return nil, err
		}
	}
	return map[string]any{"id": entryID, "event_id": eventID, "state": "approved"}, nil
}

func (s *Store) RejectQuarantine(ctx context.Context, tenantID, entryID, actorID, reason string) (map[string]any, error) {
	var eventID string
	err := s.pool.QueryRow(ctx, `UPDATE quarantine_entries SET state='rejected' WHERE tenant_id=$1 AND id=$2 AND state='open' RETURNING COALESCE(event_id,'')`, tenantID, entryID).Scan(&eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, app.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'quarantine.rejected','quarantine_entry',$4,$5)`, mustID("aud"), tenantID, actorID, entryID, reason)
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

func (s *Store) CreateReplay(ctx context.Context, tenantID, actorID string, req app.ReplayRequest) (app.ReplayJob, error) {
	if req.ConfigMode == "" {
		req.ConfigMode = app.ReplayConfigCurrent
	}
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
	if _, err := tx.Exec(ctx, `INSERT INTO replay_jobs(id, tenant_id, state, scope_hash, scope_json, reason, created_by, total_items, config_mode, rate_limit_per_minute) VALUES($1,$2,'scheduled',$3,$4,$5,$6,$7,$8,$9)`, id, tenantID, scopeHash, scopeBytes, req.Reason, actorID, dryRun.WouldCreateDeliveries, req.ConfigMode, req.RateLimitPerMinute); err != nil {
		return app.ReplayJob{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO outbox(id, tenant_id, kind, resource_id, payload) VALUES($1,$2,'replay_job',$3,$4)`, mustID("out"), tenantID, id, scopeBytes); err != nil {
		return app.ReplayJob{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'replay.created','replay_job',$4,$5)`, mustID("aud"), tenantID, actorID, id, req.Reason); err != nil {
		return app.ReplayJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.ReplayJob{}, err
	}
	return app.ReplayJob{ID: id, State: "scheduled", ScopeHash: scopeHash, ConfigMode: req.ConfigMode, RateLimitPerMinute: req.RateLimitPerMinute, TotalItems: dryRun.WouldCreateDeliveries}, nil
}

func (s *Store) ListReplayJobs(ctx context.Context, tenantID string, limit int) ([]app.ReplayJob, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, state, scope_hash, config_mode, rate_limit_per_minute, total_items, processed_items, failed_items FROM replay_jobs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.ReplayJob
	for rows.Next() {
		var item app.ReplayJob
		if err := rows.Scan(&item.ID, &item.State, &item.ScopeHash, &item.ConfigMode, &item.RateLimitPerMinute, &item.TotalItems, &item.ProcessedItems, &item.FailedItems); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
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
	var item app.ReplayJob
	extra := ""
	if state == "paused" {
		extra = ", paused_at=now()"
	}
	if state == "canceled" {
		extra = ", canceled_at=now()"
	}
	err := s.pool.QueryRow(ctx, `UPDATE replay_jobs SET state=$1`+extra+` WHERE tenant_id=$2 AND id=$3 AND state NOT IN ('completed','canceled') RETURNING id, state, scope_hash, config_mode, rate_limit_per_minute, total_items, processed_items, failed_items`, state, tenantID, replayJobID).
		Scan(&item.ID, &item.State, &item.ScopeHash, &item.ConfigMode, &item.RateLimitPerMinute, &item.TotalItems, &item.ProcessedItems, &item.FailedItems)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ReplayJob{}, app.ErrNotFound
	}
	if err != nil {
		return app.ReplayJob{}, err
	}
	_, _ = s.pool.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,$4,'replay_job',$5,$6)`, mustID("aud"), tenantID, actorID, action, replayJobID, reason)
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
	rows, err := tx.Query(ctx, `
		UPDATE outbox
		SET state='in_progress', locked_by=$1, lock_expires_at=now() + interval '60 seconds'
		WHERE id IN (
			SELECT id FROM outbox
			WHERE state='pending' AND available_at <= now()
			ORDER BY available_at ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, tenant_id, kind, resource_id`, workerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []worker.OutboxItem
	for rows.Next() {
		var item worker.OutboxItem
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Kind, &item.ResourceID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
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

func (s *Store) ProcessOutbox(ctx context.Context, item worker.OutboxItem) error {
	switch item.Kind {
	case "route_event":
		_, err := s.createDeliveriesForEvent(ctx, item.TenantID, item.ResourceID)
		return err
	case "replay_job":
		return s.createReplayDeliveries(ctx, item.TenantID, item.ResourceID)
	default:
		return nil
	}
}

func (s *Store) createDeliveriesForEvent(ctx context.Context, tenantID, eventID string) (int, error) {
	return s.createDeliveriesForEventWithOptions(ctx, tenantID, eventID, deliveryCreationOptions{})
}

type deliveryCreationOptions struct {
	ReplayJobID        string
	ConfigMode         string
	RateLimitPerMinute int
}

func (s *Store) createDeliveriesForEventWithOptions(ctx context.Context, tenantID, eventID string, opts deliveryCreationOptions) (int, error) {
	event, err := s.GetEvent(ctx, tenantID, eventID)
	if err != nil {
		return 0, err
	}
	if !event.Verified {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(ctx, tx)
	created := 0

	subRows, err := tx.Query(ctx, `
		SELECT s.id, s.endpoint_id, s.active_version_id, COALESCE(NULLIF(e.retry_policy_id,''),''), COALESCE(NULLIF(s.transformation_version_id,''),'')
		FROM subscriptions s
		JOIN endpoints e ON e.tenant_id=s.tenant_id AND e.id=s.endpoint_id
		WHERE s.tenant_id=$1 AND s.state='active' AND $2 = ANY(s.event_types)`, tenantID, event.Type)
	if err != nil {
		return 0, err
	}
	for subRows.Next() {
		var subID, endpointID, subscriptionVersionID, retryPolicyID, transformationVersionID string
		if err := subRows.Scan(&subID, &endpointID, &subscriptionVersionID, &retryPolicyID, &transformationVersionID); err != nil {
			subRows.Close()
			return 0, err
		}
		deliveryID := mustID("del")
		if _, err := tx.Exec(ctx, `INSERT INTO deliveries(id, tenant_id, event_id, endpoint_id, subscription_id, subscription_version_id, retry_policy_id, replay_job_id, transformation_version_id, state, next_attempt_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'scheduled',$10)`, deliveryID, tenantID, eventID, endpointID, subID, subscriptionVersionID, retryPolicyID, opts.ReplayJobID, transformationVersionID, scheduledDeliveryAt(created, opts.RateLimitPerMinute)); err != nil {
			subRows.Close()
			return 0, err
		}
		payloadID, normalizedID, adapterVersionID, err := s.createDeliveryPayload(ctx, tx, tenantID, eventID, deliveryID, transformationVersionID)
		if err != nil {
			subRows.Close()
			return 0, err
		}
		if opts.ReplayJobID != "" {
			if err := insertReplayDecisionEvidence(ctx, tx, replayEvidence{
				tenantID: tenantID, replayJobID: opts.ReplayJobID, eventID: eventID, newDeliveryID: deliveryID,
				configMode: opts.ConfigMode, subscriptionVersionID: subscriptionVersionID, retryPolicyID: retryPolicyID,
				adapterVersionID: adapterVersionID, normalizedEnvelopeID: normalizedID, transformationVersionID: transformationVersionID, deliveryPayloadID: payloadID,
			}); err != nil {
				subRows.Close()
				return 0, err
			}
		}
		created++
	}
	subRows.Close()
	if err := subRows.Err(); err != nil {
		return 0, err
	}

	routeRows, err := tx.Query(ctx, `
		SELECT r.id, r.endpoint_id, r.active_version_id, COALESCE(NULLIF(r.retry_policy_id,''), NULLIF(e.retry_policy_id,''), ''), COALESCE(NULLIF(r.transformation_version_id,''),'')
		FROM routes r
		JOIN endpoints e ON e.tenant_id=r.tenant_id AND e.id=r.endpoint_id
		WHERE r.tenant_id=$1 AND r.source_id=$2 AND r.state='active' AND $3 = ANY(r.event_types)
		ORDER BY r.priority ASC`, tenantID, event.SourceID, event.Type)
	if err != nil {
		return 0, err
	}
	for routeRows.Next() {
		var routeID, endpointID, routeVersionID, retryPolicyID, transformationVersionID string
		if err := routeRows.Scan(&routeID, &endpointID, &routeVersionID, &retryPolicyID, &transformationVersionID); err != nil {
			routeRows.Close()
			return 0, err
		}
		deliveryID := mustID("del")
		if _, err := tx.Exec(ctx, `INSERT INTO deliveries(id, tenant_id, event_id, endpoint_id, route_id, route_version_id, retry_policy_id, replay_job_id, transformation_version_id, state, next_attempt_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'scheduled',$10)`, deliveryID, tenantID, eventID, endpointID, routeID, routeVersionID, retryPolicyID, opts.ReplayJobID, transformationVersionID, scheduledDeliveryAt(created, opts.RateLimitPerMinute)); err != nil {
			routeRows.Close()
			return 0, err
		}
		payloadID, normalizedID, adapterVersionID, err := s.createDeliveryPayload(ctx, tx, tenantID, eventID, deliveryID, transformationVersionID)
		if err != nil {
			routeRows.Close()
			return 0, err
		}
		if opts.ReplayJobID != "" {
			if err := insertReplayDecisionEvidence(ctx, tx, replayEvidence{
				tenantID: tenantID, replayJobID: opts.ReplayJobID, eventID: eventID, newDeliveryID: deliveryID,
				configMode: opts.ConfigMode, routeVersionID: routeVersionID, retryPolicyID: retryPolicyID,
				adapterVersionID: adapterVersionID, normalizedEnvelopeID: normalizedID, transformationVersionID: transformationVersionID, deliveryPayloadID: payloadID,
			}); err != nil {
				routeRows.Close()
				return 0, err
			}
		}
		created++
	}
	routeRows.Close()
	if err := routeRows.Err(); err != nil {
		return 0, err
	}
	return created, tx.Commit(ctx)
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

func (s *Store) createReplayDeliveries(ctx context.Context, tenantID, replayJobID string) error {
	var scopeBytes []byte
	var state, configMode string
	var rateLimitPerMinute int
	err := s.pool.QueryRow(ctx, `SELECT scope_json, state, config_mode, rate_limit_per_minute FROM replay_jobs WHERE tenant_id=$1 AND id=$2`, tenantID, replayJobID).Scan(&scopeBytes, &state, &configMode, &rateLimitPerMinute)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return err
	}
	if state == "paused" {
		return worker.ErrDeferred
	}
	if state == "canceled" || state == "completed" {
		return nil
	}
	if _, err := s.pool.Exec(ctx, `UPDATE replay_jobs SET state='running' WHERE tenant_id=$1 AND id=$2 AND state='scheduled'`, tenantID, replayJobID); err != nil {
		return err
	}
	var req app.ReplayRequest
	if err := json.Unmarshal(scopeBytes, &req); err != nil {
		return err
	}
	created := 0
	if req.EventID != "" {
		var count int
		var err error
		if configMode == app.ReplayConfigOriginal {
			count, err = s.createDeliveriesFromOriginalEvent(ctx, tenantID, req.EventID, deliveryCreationOptions{ReplayJobID: replayJobID, ConfigMode: configMode, RateLimitPerMinute: rateLimitPerMinute})
			if err != nil {
				return err
			}
			created += count
			if count == 0 {
				if _, err := s.pool.Exec(ctx, `INSERT INTO replay_items(id, tenant_id, replay_job_id, event_id, state, config_mode, error, completed_at) VALUES($1,$2,$3,$4,'completed',$5,'no original deliveries found',now())`, mustID("rpi"), tenantID, replayJobID, req.EventID, configMode); err != nil {
					return err
				}
			}
		} else {
			count, err = s.createDeliveriesForEventWithOptions(ctx, tenantID, req.EventID, deliveryCreationOptions{ReplayJobID: replayJobID, ConfigMode: configMode, RateLimitPerMinute: rateLimitPerMinute})
			if err != nil {
				return err
			}
			created += count
			if count == 0 {
				if _, err := s.pool.Exec(ctx, `INSERT INTO replay_items(id, tenant_id, replay_job_id, event_id, state, config_mode, error, completed_at) VALUES($1,$2,$3,$4,'completed',$5,'no current route or subscription matched',now())`, mustID("rpi"), tenantID, replayJobID, req.EventID, configMode); err != nil {
					return err
				}
			}
		}
	}
	if req.DeliveryID != "" {
		count, evidence, err := s.createDeliveryFromExisting(ctx, tenantID, req.DeliveryID, deliveryCreationOptions{ReplayJobID: replayJobID, ConfigMode: configMode, RateLimitPerMinute: rateLimitPerMinute})
		if err != nil {
			return err
		}
		created += count
		if count > 0 {
			tx, err := s.pool.Begin(ctx)
			if err != nil {
				return err
			}
			if err := insertReplayDecisionEvidence(ctx, tx, evidence); err != nil {
				_ = tx.Rollback(ctx)
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
		}
	}
	_, err = s.pool.Exec(ctx, `UPDATE replay_jobs SET state='completed', processed_items=$3, completed_at=now() WHERE tenant_id=$1 AND id=$2 AND state <> 'canceled'`, tenantID, replayJobID, created)
	return err
}

func (s *Store) createDeliveryFromExisting(ctx context.Context, tenantID, deliveryID string, opts deliveryCreationOptions) (int, replayEvidence, error) {
	var eventID, endpointID, routeID, routeVersionID, subscriptionID, subscriptionVersionID, retryPolicyID, adapterVersionID, normalizedID, transformationVersionID, deliveryPayloadID string
	err := s.pool.QueryRow(ctx, `SELECT event_id, endpoint_id, COALESCE(route_id,''), COALESCE(route_version_id,''), COALESCE(subscription_id,''), COALESCE(subscription_version_id,''), COALESCE(retry_policy_id,''), COALESCE(adapter_version_id,''), COALESCE(normalized_envelope_id,''), COALESCE(transformation_version_id,''), COALESCE(delivery_payload_id,'') FROM deliveries WHERE tenant_id=$1 AND id=$2`, tenantID, deliveryID).
		Scan(&eventID, &endpointID, &routeID, &routeVersionID, &subscriptionID, &subscriptionVersionID, &retryPolicyID, &adapterVersionID, &normalizedID, &transformationVersionID, &deliveryPayloadID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, replayEvidence{}, app.ErrNotFound
	}
	if err != nil {
		return 0, replayEvidence{}, err
	}
	if opts.ConfigMode != app.ReplayConfigOriginal && (routeID != "" || subscriptionID != "") {
		current, ok, err := s.currentDeliveryReplayConfig(ctx, tenantID, routeID, subscriptionID)
		if err != nil {
			return 0, replayEvidence{}, err
		}
		if !ok {
			return 0, replayEvidence{}, nil
		}
		endpointID = current.endpointID
		routeVersionID = current.routeVersionID
		subscriptionVersionID = current.subscriptionVersionID
		retryPolicyID = current.retryPolicyID
		transformationVersionID = current.transformationVersionID
		adapterVersionID = ""
		normalizedID = ""
		deliveryPayloadID = ""
	}
	newDeliveryID := mustID("del")
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, replayEvidence{}, err
	}
	defer rollback(ctx, tx)
	if _, err = tx.Exec(ctx, `INSERT INTO deliveries(id, tenant_id, event_id, endpoint_id, route_id, route_version_id, subscription_id, subscription_version_id, retry_policy_id, replay_job_id, adapter_version_id, normalized_envelope_id, transformation_version_id, state, next_attempt_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'scheduled',$14)`, newDeliveryID, tenantID, eventID, endpointID, routeID, routeVersionID, subscriptionID, subscriptionVersionID, retryPolicyID, opts.ReplayJobID, adapterVersionID, normalizedID, transformationVersionID, scheduledDeliveryAt(0, opts.RateLimitPerMinute)); err != nil {
		return 0, replayEvidence{}, err
	}
	newPayloadID := ""
	if deliveryPayloadID != "" && opts.ConfigMode == app.ReplayConfigOriginal {
		newPayloadID, normalizedID, adapterVersionID, transformationVersionID, err = s.cloneDeliveryPayload(ctx, tx, tenantID, deliveryPayloadID, newDeliveryID)
	} else {
		newPayloadID, normalizedID, adapterVersionID, err = s.createDeliveryPayload(ctx, tx, tenantID, eventID, newDeliveryID, transformationVersionID)
	}
	if err != nil {
		return 0, replayEvidence{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, replayEvidence{}, err
	}
	return 1, replayEvidence{
		tenantID: tenantID, replayJobID: opts.ReplayJobID, eventID: eventID, originalDeliveryID: deliveryID, newDeliveryID: newDeliveryID,
		configMode: opts.ConfigMode, routeVersionID: routeVersionID, subscriptionVersionID: subscriptionVersionID, retryPolicyID: retryPolicyID,
		adapterVersionID: adapterVersionID, normalizedEnvelopeID: normalizedID, transformationVersionID: transformationVersionID, deliveryPayloadID: newPayloadID,
	}, nil
}

type currentReplayConfig struct {
	endpointID              string
	routeVersionID          string
	subscriptionVersionID   string
	retryPolicyID           string
	transformationVersionID string
}

func (s *Store) currentDeliveryReplayConfig(ctx context.Context, tenantID, routeID, subscriptionID string) (currentReplayConfig, bool, error) {
	var out currentReplayConfig
	if routeID != "" {
		err := s.pool.QueryRow(ctx, `
			SELECT r.endpoint_id, r.active_version_id,
			       COALESCE(NULLIF(r.retry_policy_id,''), NULLIF(e.retry_policy_id,''), ''),
			       COALESCE(NULLIF(r.transformation_version_id,''),'')
			FROM routes r
			JOIN endpoints e ON e.tenant_id=r.tenant_id AND e.id=r.endpoint_id
			WHERE r.tenant_id=$1 AND r.id=$2 AND r.state='active'`,
			tenantID, routeID,
		).Scan(&out.endpointID, &out.routeVersionID, &out.retryPolicyID, &out.transformationVersionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return currentReplayConfig{}, false, nil
		}
		if err != nil {
			return currentReplayConfig{}, false, err
		}
		return out, true, nil
	}
	if subscriptionID != "" {
		err := s.pool.QueryRow(ctx, `
			SELECT s.endpoint_id, s.active_version_id,
			       COALESCE(NULLIF(e.retry_policy_id,''), ''),
			       COALESCE(NULLIF(s.transformation_version_id,''),'')
			FROM subscriptions s
			JOIN endpoints e ON e.tenant_id=s.tenant_id AND e.id=s.endpoint_id
			WHERE s.tenant_id=$1 AND s.id=$2 AND s.state='active'`,
			tenantID, subscriptionID,
		).Scan(&out.endpointID, &out.subscriptionVersionID, &out.retryPolicyID, &out.transformationVersionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return currentReplayConfig{}, false, nil
		}
		if err != nil {
			return currentReplayConfig{}, false, err
		}
		return out, true, nil
	}
	return out, true, nil
}

func (s *Store) createDeliveriesFromOriginalEvent(ctx context.Context, tenantID, eventID string, opts deliveryCreationOptions) (int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, endpoint_id, COALESCE(route_id,''), COALESCE(route_version_id,''), COALESCE(subscription_id,''), COALESCE(subscription_version_id,''), COALESCE(retry_policy_id,''), COALESCE(adapter_version_id,''), COALESCE(normalized_envelope_id,''), COALESCE(transformation_version_id,''), COALESCE(delivery_payload_id,'')
		FROM deliveries
		WHERE tenant_id=$1
		  AND event_id=$2
		  AND COALESCE(replay_job_id,'') = ''
		ORDER BY created_at ASC, id ASC`,
		tenantID, eventID,
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type originalDelivery struct {
		id                      string
		endpointID              string
		routeID                 string
		routeVersionID          string
		subscriptionID          string
		subscriptionVersionID   string
		retryPolicyID           string
		adapterVersionID        string
		normalizedEnvelopeID    string
		transformationVersionID string
		deliveryPayloadID       string
	}
	var originals []originalDelivery
	for rows.Next() {
		var item originalDelivery
		if err := rows.Scan(&item.id, &item.endpointID, &item.routeID, &item.routeVersionID, &item.subscriptionID, &item.subscriptionVersionID, &item.retryPolicyID, &item.adapterVersionID, &item.normalizedEnvelopeID, &item.transformationVersionID, &item.deliveryPayloadID); err != nil {
			return 0, err
		}
		originals = append(originals, item)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(originals) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(ctx, tx)
	for i, original := range originals {
		newDeliveryID := mustID("del")
		if _, err := tx.Exec(ctx, `
			INSERT INTO deliveries(id, tenant_id, event_id, endpoint_id, route_id, route_version_id, subscription_id, subscription_version_id, retry_policy_id, replay_job_id, adapter_version_id, normalized_envelope_id, transformation_version_id, state, next_attempt_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'scheduled',$14)`,
			newDeliveryID, tenantID, eventID, original.endpointID, original.routeID, original.routeVersionID,
			original.subscriptionID, original.subscriptionVersionID, original.retryPolicyID, opts.ReplayJobID,
			original.adapterVersionID, original.normalizedEnvelopeID, original.transformationVersionID,
			scheduledDeliveryAt(i, opts.RateLimitPerMinute),
		); err != nil {
			return 0, err
		}
		newPayloadID, normalizedID, adapterVersionID, transformationVersionID, err := s.cloneDeliveryPayload(ctx, tx, tenantID, original.deliveryPayloadID, newDeliveryID)
		if err != nil {
			return 0, err
		}
		if err := insertReplayDecisionEvidence(ctx, tx, replayEvidence{
			tenantID: tenantID, replayJobID: opts.ReplayJobID, eventID: eventID, originalDeliveryID: original.id, newDeliveryID: newDeliveryID,
			configMode: opts.ConfigMode, routeVersionID: original.routeVersionID, subscriptionVersionID: original.subscriptionVersionID, retryPolicyID: original.retryPolicyID,
			adapterVersionID: adapterVersionID, normalizedEnvelopeID: normalizedID, transformationVersionID: transformationVersionID, deliveryPayloadID: newPayloadID,
		}); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(originals), nil
}

type replayEvidence struct {
	tenantID                string
	replayJobID             string
	eventID                 string
	originalDeliveryID      string
	newDeliveryID           string
	configMode              string
	routeVersionID          string
	subscriptionVersionID   string
	retryPolicyID           string
	adapterVersionID        string
	normalizedEnvelopeID    string
	transformationVersionID string
	deliveryPayloadID       string
}

func insertReplayDecisionEvidence(ctx context.Context, tx pgx.Tx, ev replayEvidence) error {
	if ev.configMode == "" {
		ev.configMode = app.ReplayConfigCurrent
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO replay_items(id, tenant_id, replay_job_id, event_id, original_delivery_id, new_delivery_id, state, config_mode,
			route_version_id, subscription_version_id, retry_policy_id, adapter_version_id, normalized_envelope_id, transformation_version_id, delivery_payload_id, completed_at)
		VALUES($1,$2,$3,$4,$5,$6,'completed',$7,$8,$9,$10,$11,$12,$13,$14,now())`,
		mustID("rpi"), ev.tenantID, ev.replayJobID, ev.eventID, ev.originalDeliveryID, ev.newDeliveryID, ev.configMode,
		ev.routeVersionID, ev.subscriptionVersionID, ev.retryPolicyID, ev.adapterVersionID, ev.normalizedEnvelopeID, ev.transformationVersionID, ev.deliveryPayloadID,
	); err != nil {
		return err
	}
	receiptDeliveryID := ev.originalDeliveryID
	if receiptDeliveryID == "" {
		receiptDeliveryID = ev.newDeliveryID
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO replay_receipts(id, tenant_id, replay_job_id, event_id, delivery_id, config_mode,
			route_version_id, subscription_version_id, retry_policy_id, adapter_version_id, normalized_envelope_id, transformation_version_id, delivery_payload_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		mustID("rrc"), ev.tenantID, ev.replayJobID, ev.eventID, receiptDeliveryID, ev.configMode,
		ev.routeVersionID, ev.subscriptionVersionID, ev.retryPolicyID, ev.adapterVersionID, ev.normalizedEnvelopeID, ev.transformationVersionID, ev.deliveryPayloadID,
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
	rows, err := tx.Query(ctx, `
		UPDATE deliveries
		SET state='in_progress', locked_by=$1, lock_expires_at=now() + interval '60 seconds'
		WHERE id IN (
			SELECT d.id FROM deliveries d
			JOIN endpoints e ON e.tenant_id=d.tenant_id AND e.id=d.endpoint_id
			WHERE d.state='scheduled'
			  AND d.next_attempt_at <= now()
			  AND e.state='active'
			  AND (e.disabled_until IS NULL OR e.disabled_until <= now())
			ORDER BY (COALESCE(d.replay_job_id,'') <> '') ASC, d.next_attempt_at ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, tenant_id, event_id, endpoint_id, attempt_count, COALESCE(retry_policy_id,'')`, workerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []worker.DeliveryItem
	for rows.Next() {
		var item worker.DeliveryItem
		if err := rows.Scan(&item.ID, &item.TenantID, &item.EventID, &item.EndpointID, &item.AttemptCount, &item.RetryPolicyID); err != nil {
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
	var encrypted []byte
	var payloadID, payloadStatus string
	err := tx.QueryRow(ctx, `
		SELECT e.url, es.id, es.version, es.encrypted_secret, COALESCE(d.delivery_payload_id,''), COALESCE(p.body,''::bytea), COALESCE(p.storage_status,'')
		FROM deliveries d
		JOIN endpoints e ON e.tenant_id=d.tenant_id AND e.id=d.endpoint_id
		JOIN endpoint_secrets es ON es.tenant_id=e.tenant_id AND es.endpoint_id=e.id AND es.state='active'
		LEFT JOIN delivery_payloads p ON p.tenant_id=d.tenant_id AND p.id=d.delivery_payload_id
		WHERE d.tenant_id=$1 AND d.id=$2
		ORDER BY es.version DESC
		LIMIT 1`,
		item.TenantID, item.ID,
	).Scan(&item.EndpointURL, &item.SigningKeyID, &item.SigningKeyVersion, &encrypted, &payloadID, &item.Body, &payloadStatus)
	if err != nil {
		return err
	}
	if payloadID != "" && payloadStatus == domain.StorageStatusDeleted {
		return app.ErrGone
	}
	secret, err := s.box.Decrypt(encrypted)
	if err != nil {
		return err
	}
	item.SigningSecret = secret
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
	if _, err := tx.Exec(ctx, `
		INSERT INTO delivery_attempts(id, tenant_id, delivery_id, event_id, endpoint_id, request_sha256, response_sha256, attempt_no, state, response_status, response_body_truncated, failure_class, retryable, completed_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now())`,
		mustID("att"), item.TenantID, item.ID, item.EventID, item.EndpointID, requestHash, responseHash, attemptNo, state, result.StatusCode, body, failureClass, retryable,
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
	} else if retryable && attemptNo < policy.MaxAttempts {
		nextAttemptAt := time.Now().UTC().Add(policy.NextDelay(attemptNo, nil))
		if _, err := tx.Exec(ctx, `UPDATE deliveries SET state='scheduled', attempt_count=$1, next_attempt_at=$2, locked_by=NULL, lock_expires_at=NULL WHERE tenant_id=$3 AND id=$4`, attemptNo, nextAttemptAt, item.TenantID, item.ID); err != nil {
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

func scanRetentionPolicy(row rowScanner) (domain.RetentionPolicy, error) {
	var item domain.RetentionPolicy
	err := row.Scan(&item.ID, &item.TenantID, &item.ResourceType, &item.SourceID, &item.RetentionDays, &item.State, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
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

func (s *Store) timelineJSONLForExport(ctx context.Context, tenantID string, from, to time.Time) ([]byte, error) {
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
	var lines []any
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			return nil, err
		}
		items, err := s.ListEventTimeline(ctx, tenantID, eventID, 100)
		if err != nil {
			return nil, err
		}
		lines = append(lines, map[string]any{"event_id": eventID, "timeline": items})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return evidence.JSONLines(lines)
}

func (s *Store) rawPayloadsJSONLForExport(ctx context.Context, tenantID string, from, to time.Time) ([]byte, error) {
	query := `
		SELECT rp.id, rp.tenant_id, rp.event_id, rp.sha256, rp.content_type, rp.size_bytes, rp.body,
			rp.storage_backend, rp.object_bucket, rp.object_key, rp.storage_status,
			COALESCE(rp.storage_deleted_at, 'epoch'::timestamptz), rp.created_at
		FROM raw_payloads rp
		JOIN events ev ON ev.tenant_id=rp.tenant_id AND ev.raw_payload_id=rp.id
		WHERE rp.tenant_id=$1`
	args := []any{tenantID}
	if !from.IsZero() {
		args = append(args, from)
		query += fmt.Sprintf(" AND ev.received_at >= $%d", len(args))
	}
	if !to.IsZero() {
		args = append(args, to)
		query += fmt.Sprintf(" AND ev.received_at <= $%d", len(args))
	}
	query += " ORDER BY ev.received_at ASC, rp.id ASC"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lines []any
	for rows.Next() {
		var raw domain.RawPayload
		if err := rows.Scan(&raw.ID, &raw.TenantID, &raw.EventID, &raw.SHA256, &raw.ContentType, &raw.SizeBytes, &raw.Body,
			&raw.StorageBackend, &raw.ObjectBucket, &raw.ObjectKey, &raw.StorageStatus, &raw.StorageDeletedAt, &raw.CreatedAt); err != nil {
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
					return nil, err
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

func zeroTimeOmit(value time.Time) any {
	if value.Equal(time.Unix(0, 0).UTC()) {
		return nil
	}
	return value
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
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id, tenant_id, actor_id, action, resource, resource_id, reason) VALUES($1,$2,$3,'retention.run.completed','retention_policy',$4,$5)`, mustID("aud"), policy.TenantID, workerID, policy.ID, policy.ResourceType); err != nil {
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

func scanEvent(row rowScanner) (domain.Event, error) {
	var item domain.Event
	err := row.Scan(&item.ID, &item.TenantID, &item.SourceID, &item.Provider, &item.Type, &item.ProviderID, &item.RawPayloadID, &item.RawPayloadHash, &item.Verified, &item.VerifyReason, &item.DedupeKey, &item.DedupeStatus, &item.ReceivedAt, &item.TraceID)
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
	err := row.Scan(&item.ID, &item.TenantID, &item.EventID, &item.EndpointID, &item.RouteID, &item.RouteVersionID, &item.SubscriptionID, &item.SubscriptionVersionID, &item.RetryPolicyID, &item.ReplayJobID, &item.AdapterVersionID, &item.NormalizedEnvelopeID, &item.TransformationVersionID, &item.DeliveryPayloadID, &item.State, &item.AttemptCount, &item.NextAttemptAt)
	return item, err
}

func scanDeliveryAttempt(row rowScanner) (domain.DeliveryAttempt, error) {
	var item domain.DeliveryAttempt
	err := row.Scan(&item.ID, &item.TenantID, &item.DeliveryID, &item.EventID, &item.EndpointID, &item.RequestSHA256, &item.ResponseSHA256, &item.AttemptNo, &item.State, &item.ResponseStatus, &item.ResponseBodyTruncated, &item.FailureClass, &item.Retryable, &item.StartedAt, &item.CompletedAt)
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

func scheduledDeliveryAt(index, rateLimitPerMinute int) time.Time {
	return time.Now().UTC().Add(replayScheduleDelay(index, rateLimitPerMinute))
}

func replayScheduleDelay(index, rateLimitPerMinute int) time.Duration {
	if index <= 0 || rateLimitPerMinute <= 0 {
		return 0
	}
	interval := time.Minute / time.Duration(rateLimitPerMinute)
	if interval <= 0 {
		return 0
	}
	return time.Duration(index) * interval
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

func mustID(prefix string) string {
	id, err := random.Token(prefix, 18)
	if err != nil {
		panic(fmt.Sprintf("generate id: %v", err))
	}
	return id
}

var _ app.IngestStore = (*Store)(nil)
var _ app.ControlStore = (*Store)(nil)
var _ app.APIKeyLookup = (*Store)(nil)
var _ worker.OutboxStore = (*Store)(nil)
var _ worker.OutboxProcessor = (*Store)(nil)
var _ worker.DeliveryStore = (*Store)(nil)
var _ worker.RetentionStore = (*Store)(nil)
var _ = time.Now
