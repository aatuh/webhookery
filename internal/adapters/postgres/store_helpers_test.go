package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"webhookery/internal/app"
	"webhookery/internal/domain"
)

func TestStoreConstructionRejectsUnsafeLocalOptionsBeforeConnecting(t *testing.T) {
	box := &staticSecretBox{}
	tests := []struct {
		name string
		box  SecretBox
		opts StoreOptions
		want string
	}{
		{name: "missing secret box", want: "secret box is required"},
		{name: "unsupported raw storage", box: box, opts: StoreOptions{RawStorageMode: "redis"}, want: "raw storage mode must be postgres or s3"},
		{name: "s3 missing object store", box: box, opts: StoreOptions{RawStorageMode: domain.RawStorageS3, ObjectBucket: "bucket"}, want: "s3 raw storage requires object store and bucket"},
		{name: "s3 missing bucket", box: box, opts: StoreOptions{RawStorageMode: domain.RawStorageS3, ObjectStore: &fakeObjectStore{}}, want: "s3 raw storage requires object store and bucket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewWithOptions(context.Background(), "postgres://invalid", tt.box, tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q, got %v", tt.want, err)
			}
		})
	}
}

func TestStoreSecretBoxDispatchUsesTenantAndPurposeContext(t *testing.T) {
	ctx := context.Background()
	contextual := &contextualSecretBox{}
	store := &Store{box: contextual}
	ciphertext, err := store.encryptSecret(ctx, "ten_1", "provider_secret", []byte("plain"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := store.decryptSecret(ctx, "ten_1", "provider_secret", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "plain" {
		t.Fatalf("plaintext=%q want plain", string(plaintext))
	}
	if contextual.encryptTenant != "ten_1" || contextual.encryptPurpose != "provider_secret" || contextual.decryptTenant != "ten_1" || contextual.decryptPurpose != "provider_secret" {
		t.Fatalf("contextual secret box did not receive tenant and purpose: %+v", contextual)
	}

	fallback := &staticSecretBox{}
	store = &Store{box: fallback}
	ciphertext, err = store.encryptSecret(ctx, "ten_2", "fallback", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err = store.decryptSecret(ctx, "ten_2", "fallback", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "value" || !fallback.encryptCalled || !fallback.decryptCalled {
		t.Fatalf("fallback secret box not used correctly, plaintext=%q encrypt=%v decrypt=%v", string(plaintext), fallback.encryptCalled, fallback.decryptCalled)
	}
}

func TestPostgresTimeNormalizersOmitEpochSentinels(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	later := time.Date(2026, 6, 8, 12, 0, 0, 0, time.FixedZone("EET", 3*60*60))

	if zeroTimeOmit(epoch) != nil {
		t.Fatal("epoch sentinel should be omitted")
	}
	if got := manifestTime(later); got == nil || !got.Equal(later.UTC()) || got.Location() != time.UTC {
		t.Fatalf("manifest time should return UTC value, got %v", got)
	}
	if manifestTime(time.Time{}) != nil || nullableTime(time.Time{}) != nil {
		t.Fatal("zero times should be nullable")
	}
	export := normalizeEvidenceExportTimes(domain.EvidenceExport{From: epoch, To: epoch, CompletedAt: epoch})
	if !export.From.IsZero() || !export.To.IsZero() || !export.CompletedAt.IsZero() {
		t.Fatalf("evidence export epoch sentinels should normalize to zero values: %+v", export)
	}
}

func TestAdapterVersionStateMachineEnforcesGovernanceOrder(t *testing.T) {
	valid := []struct {
		current string
		action  string
		want    string
	}{
		{domain.AdapterStateDraft, "submit_tests", domain.AdapterStateAutomatedTests},
		{domain.AdapterStateAutomatedTests, "request_review", domain.AdapterStateSecurityReview},
		{domain.AdapterStateSecurityReview, "approve_staging", domain.AdapterStateStagingApproved},
		{domain.AdapterStateStagingApproved, "activate", domain.AdapterStateActive},
		{domain.AdapterStateActive, "deprecate", domain.AdapterStateDeprecated},
		{domain.AdapterStateStagingApproved, "deprecate", domain.AdapterStateDeprecated},
		{domain.AdapterStateDeprecated, "retire", domain.AdapterStateRetired},
	}
	for _, tt := range valid {
		t.Run(tt.action+" from "+tt.current, func(t *testing.T) {
			got, err := adapterVersionNextState(tt.current, tt.action)
			if err != nil || got != tt.want {
				t.Fatalf("state transition got %q, %v; want %q", got, err, tt.want)
			}
		})
	}

	invalid := []struct {
		current string
		action  string
	}{
		{domain.AdapterStateDraft, "request_review"},
		{domain.AdapterStateActive, "retire"},
		{domain.AdapterStateDeprecated, "unsupported"},
	}
	for _, tt := range invalid {
		t.Run("reject "+tt.action+" from "+tt.current, func(t *testing.T) {
			_, err := adapterVersionNextState(tt.current, tt.action)
			if !errors.Is(err, app.ErrInvalidInput) {
				t.Fatalf("expected invalid input error, got %v", err)
			}
		})
	}
}

func TestProviderReconciliationHelpersRedactAndPreserveEvidenceHeaders(t *testing.T) {
	redacted := redactProviderURL("https://api.example.test/events?api_key=one&token=two&clientSecret=three&cursor=keep")
	if strings.Contains(redacted, "one") || strings.Contains(redacted, "two") || strings.Contains(redacted, "three") {
		t.Fatalf("provider URL leaked secret query values: %s", redacted)
	}
	for _, want := range []string{"api_key=redacted", "token=redacted", "clientSecret=redacted", "cursor=keep"} {
		if !strings.Contains(redacted, want) {
			t.Fatalf("redacted URL missing %q: %s", want, redacted)
		}
	}
	if got := redactProviderURL("://not a url"); got != "://not a url" {
		t.Fatalf("malformed URL should be returned unchanged, got %q", got)
	}

	headers := headerPairsFromMap(map[string]string{"Provider-Event-ID": "evt_1"})
	if len(headers) != 2 || headers[0].Name != "Webhookery-Recovered-By" || headers[0].Value != "provider-api-reconciliation" {
		t.Fatalf("missing recovery evidence header: %+v", headers)
	}
	if !containsString([]string{"Stripe", "GitHub"}, "github") {
		t.Fatal("containsString should match case-insensitively")
	}
}

func TestPostgresDefaultingAndTenantQueryHelpers(t *testing.T) {
	if got := normalizeStringList([]string{" Admin ", "admin", "", "Viewer"}); !reflect.DeepEqual(got, []string{"admin", "viewer"}) {
		t.Fatalf("unexpected normalized string list: %#v", got)
	}
	if stateFromActive(true) != domain.StateActive || stateFromActive(false) != domain.StateDisabled {
		t.Fatal("stateFromActive returned unexpected state")
	}
	if defaultWildcard(" ") != "*" || defaultWildcard(" prod ") != "prod" {
		t.Fatal("default wildcard did not trim and default empty values")
	}
	predicate, args := tenantPredicate("ten_1")
	if predicate != " WHERE tenant_id=$1" || len(args) != 1 || args[0] != "ten_1" {
		t.Fatalf("tenant predicate lost tenant binding: %q %#v", predicate, args)
	}
	if predicate, args = tenantPredicate(""); predicate != "" || args != nil {
		t.Fatalf("empty tenant should not add predicate: %q %#v", predicate, args)
	}
	if tenantAnd("ten_1") != " AND tenant_id=$1" || tenantAnd("") != "" {
		t.Fatal("tenantAnd returned unexpected SQL fragment")
	}
	if firstNonEmpty("", "  ", "value", "other") != "value" {
		t.Fatal("firstNonEmpty should skip blank strings")
	}
}

func TestPostgresNormalizationHelpersStripEpochSentinels(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	if !normalizeProviderAdapter(domain.ProviderAdapter{RetiredAt: epoch}).RetiredAt.IsZero() {
		t.Fatal("provider adapter retired epoch should normalize to zero")
	}
	version := normalizeAdapterVersion(domain.AdapterVersion{ReviewedAt: epoch, ActivatedAt: epoch, DeprecatedAt: epoch, RetiredAt: epoch})
	if !version.ReviewedAt.IsZero() || !version.ActivatedAt.IsZero() || !version.DeprecatedAt.IsZero() || !version.RetiredAt.IsZero() {
		t.Fatalf("adapter version epoch sentinels should normalize to zero: %+v", version)
	}
	connection := normalizeProviderConnection(domain.ProviderConnection{VerifiedAt: epoch, RevokedAt: epoch})
	if connection.Config == nil || !connection.VerifiedAt.IsZero() || !connection.RevokedAt.IsZero() {
		t.Fatalf("provider connection defaults not normalized: %+v", connection)
	}
	job := normalizeReconciliationJob(domain.ReconciliationJob{WindowStart: epoch, WindowEnd: epoch, StartedAt: epoch, CompletedAt: epoch, CanceledAt: epoch})
	if !job.WindowStart.IsZero() || !job.WindowEnd.IsZero() || !job.StartedAt.IsZero() || !job.CompletedAt.IsZero() || !job.CanceledAt.IsZero() {
		t.Fatalf("reconciliation job epoch sentinels should normalize to zero: %+v", job)
	}
	if !normalizeAlertFiring(domain.AlertFiring{AcknowledgedAt: epoch, ResolvedAt: epoch}).AcknowledgedAt.IsZero() {
		t.Fatal("alert firing acknowledged epoch should normalize to zero")
	}
	if !normalizeNotificationDelivery(domain.NotificationDelivery{LastAttemptAt: epoch}).LastAttemptAt.IsZero() {
		t.Fatal("notification delivery last attempt epoch should normalize to zero")
	}
	if !normalizeSIEMDelivery(domain.SIEMDelivery{LastAttemptAt: epoch}).LastAttemptAt.IsZero() {
		t.Fatal("SIEM delivery last attempt epoch should normalize to zero")
	}
}

func TestPostgresScannerHelpersApplyDefaultsAndConversions(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	metric, err := scanMetricRollup(fakeScanner{values: []any{
		"met_1", "ten_1", "delivery.failures", now, 60, []byte(`{"endpoint_id":"ep_1"}`), "hash", 12.5, "rollup", now, now,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if metric.Dimensions["endpoint_id"] != "ep_1" {
		t.Fatalf("metric dimensions not decoded: %+v", metric)
	}
	if _, err := scanMetricRollup(fakeScanner{values: []any{
		"met_1", "ten_1", "delivery.failures", now, 60, []byte(`{`), "hash", 12.5, "rollup", now, now,
	}}); err == nil {
		t.Fatal("invalid metric dimensions JSON should fail")
	}

	rule, err := scanAlertRule(fakeScanner{values: []any{
		"arl_1", "ten_1", "failed deliveries", "metric_threshold", "delivery.failures", 5.0, ">=", 300, []byte{}, domain.StateActive, "usr_1", now, now,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if rule.Dimensions == nil || len(rule.Dimensions) != 0 {
		t.Fatalf("empty alert dimensions should default to empty map: %+v", rule)
	}

	queue, err := scanQueueStats(fakeScanner{values: []any{"outbox", int64(3), int64(1), int64(9), int64(2), int64(3), 42.9, now}}, "ten_1")
	if err != nil {
		t.Fatal(err)
	}
	if queue.TenantID != "ten_1" || queue.OldestPendingAgeSec != 42 {
		t.Fatalf("queue scan did not apply tenant and oldest age conversion: %+v", queue)
	}

	attempt, err := scanDeliveryAttempt(fakeScanner{values: []any{
		"dla_1", "ten_1", "del_1", "evt_1", "end_1", "reqhash", "resphash", 1, "failed", 500, "truncated", "network", true, int64(1000), time.Unix(0, 0).UTC(), now, now,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !attempt.NextRetryAt.IsZero() {
		t.Fatalf("epoch next retry should normalize to zero: %+v", attempt)
	}

	notificationAttempt, err := scanNotificationDeliveryAttempt(fakeScanner{values: []any{"nda_1", "ten_1", "nd_1", 202, "success", []byte("ok"), false, "", now}})
	if err != nil {
		t.Fatal(err)
	}
	if notificationAttempt.ResponseBody != "ok" {
		t.Fatalf("notification response body not decoded: %+v", notificationAttempt)
	}
	siemAttempt, err := scanSIEMDeliveryAttempt(fakeScanner{values: []any{"sda_1", "ten_1", "sd_1", 502, "upstream", []byte("bad"), true, "failed", now}})
	if err != nil {
		t.Fatal(err)
	}
	if siemAttempt.ResponseBody != "bad" {
		t.Fatalf("SIEM response body not decoded: %+v", siemAttempt)
	}
}

func TestAlertComparatorContract(t *testing.T) {
	tests := []struct {
		observed   float64
		comparator string
		threshold  float64
		want       bool
	}{
		{2, ">", 1, true},
		{1, ">", 1, false},
		{1, ">=", 1, true},
		{0, "<", 1, true},
		{1, "<=", 1, true},
		{1, "==", 1, true},
		{1, "!=", 1, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%g %s %g", tt.observed, tt.comparator, tt.threshold), func(t *testing.T) {
			if got := compareAlertValue(tt.observed, tt.comparator, tt.threshold); got != tt.want {
				t.Fatalf("compareAlertValue got %v want %v", got, tt.want)
			}
		})
	}
}

func TestNullableJSONAndRetrySeedHelpers(t *testing.T) {
	if nullableJSON(nil) != nil {
		t.Fatal("empty JSON should be nullable")
	}
	if nullableJSON(json.RawMessage(`{"ok":true}`)) != `{"ok":true}` {
		t.Fatal("non-empty JSON should be passed through as string")
	}
	if deliveryRetrySeed("ten_1", "del_1", "evt_1", "end_1") == deliveryRetrySeed("ten_1", "del_2", "evt_1", "end_1") {
		t.Fatal("delivery retry seed should include delivery identity")
	}
}

type staticSecretBox struct {
	encryptCalled bool
	decryptCalled bool
}

func (b *staticSecretBox) Encrypt(plaintext []byte) ([]byte, error) {
	b.encryptCalled = true
	return append([]byte("static:"), plaintext...), nil
}

func (b *staticSecretBox) Decrypt(ciphertext []byte) ([]byte, error) {
	b.decryptCalled = true
	return bytesAfterPrefix(ciphertext, "static:"), nil
}

type contextualSecretBox struct {
	encryptTenant   string
	encryptPurpose  string
	decryptTenant   string
	decryptPurpose  string
	encryptedSecret []byte
}

func (b *contextualSecretBox) Encrypt(plaintext []byte) ([]byte, error) {
	return append([]byte("unused:"), plaintext...), nil
}

func (b *contextualSecretBox) Decrypt(ciphertext []byte) ([]byte, error) {
	return bytesAfterPrefix(ciphertext, "unused:"), nil
}

func (b *contextualSecretBox) EncryptWithContext(_ context.Context, tenantID, purpose string, plaintext []byte) ([]byte, error) {
	b.encryptTenant = tenantID
	b.encryptPurpose = purpose
	b.encryptedSecret = append([]byte("ctx:"), plaintext...)
	return append([]byte(nil), b.encryptedSecret...), nil
}

func (b *contextualSecretBox) DecryptWithContext(_ context.Context, tenantID, purpose string, ciphertext []byte) ([]byte, error) {
	b.decryptTenant = tenantID
	b.decryptPurpose = purpose
	return bytesAfterPrefix(ciphertext, "ctx:"), nil
}

func bytesAfterPrefix(value []byte, prefix string) []byte {
	if !strings.HasPrefix(string(value), prefix) {
		return nil
	}
	return append([]byte(nil), value[len(prefix):]...)
}

type fakeScanner struct {
	values []any
	err    error
}

func (s fakeScanner) Scan(dest ...any) error {
	if s.err != nil {
		return s.err
	}
	if len(dest) != len(s.values) {
		return fmt.Errorf("scan dest count %d does not match values %d", len(dest), len(s.values))
	}
	for i, value := range s.values {
		target := reflect.ValueOf(dest[i])
		if target.Kind() != reflect.Ptr || target.IsNil() {
			return fmt.Errorf("scan target %d is not a pointer", i)
		}
		source := reflect.ValueOf(value)
		if source.Type().AssignableTo(target.Elem().Type()) {
			target.Elem().Set(source)
			continue
		}
		if source.Type().ConvertibleTo(target.Elem().Type()) {
			target.Elem().Set(source.Convert(target.Elem().Type()))
			continue
		}
		return fmt.Errorf("cannot assign %T to %T", value, dest[i])
	}
	return nil
}
