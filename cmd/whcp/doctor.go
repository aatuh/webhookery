package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"webhookery/internal/adapters/deliveryhttp"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
)

func runDoctor(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp doctor <production|pilot>")
	}
	switch args[0] {
	case "production":
		if len(args) != 1 {
			return fmt.Errorf("usage: whcp doctor production")
		}
		findings := productionDoctorFindings(os.Getenv)
		writeDoctorFindings(os.Stdout, findings)
		if blockers := countDoctorBlockers(findings); blockers > 0 {
			return fmt.Errorf("production doctor found %d blocker(s)", blockers)
		}
		return nil
	case "pilot":
		return runPilotDoctor(args[1:])
	default:
		return fmt.Errorf("usage: whcp doctor <production|pilot>")
	}
}

func runPilotDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor pilot", flag.ContinueOnError)
	noNetwork := fs.Bool("no-network", false, "skip safe network connectivity checks")
	timeout := fs.Duration("timeout", 3*time.Second, "network check timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: whcp doctor pilot [--no-network] [--timeout duration]")
	}
	findings := pilotDoctorFindings(os.Getenv, pilotDoctorOptions{
		Network:       !*noNetwork,
		Timeout:       *timeout,
		DBCheck:       checkPilotDatabase,
		ReceiverCheck: checkPilotReceiver,
	})
	writeDoctorFindings(os.Stdout, findings)
	if blockers := countDoctorBlockers(findings); blockers > 0 {
		return fmt.Errorf("pilot doctor found %d blocker(s)", blockers)
	}
	return nil
}

type pilotDoctorOptions struct {
	Network       bool
	Timeout       time.Duration
	DBCheck       func(context.Context, string, time.Duration) (pilotDatabaseStatus, error)
	ReceiverCheck func(context.Context, string, time.Duration) error
}

type pilotDatabaseStatus struct {
	AppliedMigrations  int
	ExpectedMigrations int
	PendingOutbox      int
	InProgressOutbox   int
	RetentionPolicies  int
	AuditChainEntries  int
}

func pilotDoctorFindings(getenv func(string) string, opts pilotDoctorOptions) []doctorFinding {
	env := func(name string) string { return strings.TrimSpace(getenv(name)) }
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if opts.DBCheck == nil {
		opts.DBCheck = checkPilotDatabase
	}
	if opts.ReceiverCheck == nil {
		opts.ReceiverCheck = checkPilotReceiver
	}
	var findings []doctorFinding
	add := func(severity, check, message string) {
		findings = append(findings, doctorFinding{Severity: severity, Check: check, Message: message})
	}

	switch env("WEBHOOKERY_ENVIRONMENT") {
	case "production":
		add("ok", "environment", "production mode is explicit for pilot")
	case "development", "":
		add("warning", "environment", "development environment is acceptable only for local pilot drills")
	default:
		add("warning", "environment", "custom environment name is configured; confirm release evidence labels")
	}

	databaseURL := env("WEBHOOKERY_DATABASE_URL")
	switch {
	case databaseURL == "":
		add("blocker", "database", "WEBHOOKERY_DATABASE_URL is required for pilot readiness")
	case containsUnsafePlaceholder(databaseURL):
		add("blocker", "database", "database URL contains placeholder material")
	case strings.Contains(strings.ToLower(databaseURL), "sslmode=disable"):
		add("warning", "database", "database TLS appears disabled; use only on a private trusted pilot network")
	default:
		add("ok", "database", "database URL is configured")
	}

	addSecretBoxFindings(add, env, false)
	addRawStorageFindings(add, env, false)
	addBootstrapFinding(add, env)
	addProviderProofFinding(add, env)

	if databaseURL != "" && !containsUnsafePlaceholder(databaseURL) {
		if !opts.Network {
			add("warning", "database-connectivity", "PostgreSQL connectivity skipped because --no-network is set")
			add("warning", "migrations", "migration-state check skipped because --no-network is set")
			add("warning", "queue", "outbox health check skipped because --no-network is set")
			add("warning", "audit-chain", "audit-chain metadata check skipped because --no-network is set")
			add("warning", "retention", "retention policy check skipped because --no-network is set")
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			status, err := opts.DBCheck(ctx, databaseURL, timeout)
			cancel()
			if err != nil {
				add("blocker", "database-connectivity", "PostgreSQL connectivity or metadata query failed")
			} else {
				addPilotDatabaseFindings(add, status)
			}
		}
	}

	addReceiverConnectivityFinding(add, env, opts)
	return findings
}

func productionDoctorFindings(getenv func(string) string) []doctorFinding {
	env := func(name string) string { return strings.TrimSpace(getenv(name)) }
	var findings []doctorFinding
	add := func(severity, check, message string) {
		findings = append(findings, doctorFinding{Severity: severity, Check: check, Message: message})
	}

	if env("WEBHOOKERY_ENVIRONMENT") != "production" {
		add("blocker", "environment", "WEBHOOKERY_ENVIRONMENT must be production for this doctor")
	} else {
		add("ok", "environment", "production mode is explicit")
	}

	databaseURL := env("WEBHOOKERY_DATABASE_URL")
	switch {
	case databaseURL == "":
		add("blocker", "database", "WEBHOOKERY_DATABASE_URL is required")
	case containsUnsafePlaceholder(databaseURL):
		add("blocker", "database", "database URL contains placeholder material")
	case strings.Contains(strings.ToLower(databaseURL), "sslmode=disable"):
		add("warning", "database", "database TLS appears disabled; use only on a private trusted network")
	default:
		add("ok", "database", "database URL is configured")
	}

	tlsCert := env("WEBHOOKERY_TLS_CERT_FILE")
	tlsKey := env("WEBHOOKERY_TLS_KEY_FILE")
	switch {
	case tlsCert == "" && tlsKey == "":
		add("blocker", "tls", "production API listener requires WEBHOOKERY_TLS_CERT_FILE and WEBHOOKERY_TLS_KEY_FILE")
	case tlsCert == "" || tlsKey == "":
		add("blocker", "tls", "WEBHOOKERY_TLS_CERT_FILE and WEBHOOKERY_TLS_KEY_FILE must be configured together")
	default:
		add("ok", "tls", "API TLS certificate and key paths are configured")
	}
	if env("WEBHOOKERY_PRODUCER_MTLS_CLIENT_CA_FILE") != "" {
		if tlsCert == "" || tlsKey == "" {
			add("blocker", "producer-mtls", "producer mTLS client CA requires app-side TLS")
		} else {
			add("ok", "producer-mtls", "producer mTLS client CA is configured")
		}
	} else {
		add("warning", "producer-mtls", "producer mTLS is disabled")
	}

	addSecretBoxFindings(add, env, true)
	addRawStorageFindings(add, env, true)
	addBootstrapFinding(add, env)

	return findings
}

func addSecretBoxFindings(add func(string, string, string), env func(string) string, production bool) {
	secretBoxMode := envDefaultValue(env("WEBHOOKERY_SECRET_BOX_MODE"), "local")
	switch secretBoxMode {
	case "local":
		master := env("WEBHOOKERY_MASTER_KEY_BASE64")
		if master == "" {
			add("blocker", "secret-box", "local secret box requires WEBHOOKERY_MASTER_KEY_BASE64")
		} else if weak, reason := weakLocalMasterKey(master); weak {
			add("blocker", "secret-box", reason)
		} else if production {
			add("warning", "secret-box", "local secret box is configured; prefer Vault Transit or AWS KMS for shared production operations")
		} else {
			add("warning", "secret-box", "local secret box is configured; document custody before pilot traffic")
		}
	case "vault-transit":
		if env("WEBHOOKERY_VAULT_ADDR") == "" || env("WEBHOOKERY_VAULT_TOKEN") == "" || env("WEBHOOKERY_VAULT_TRANSIT_KEY") == "" {
			add("blocker", "secret-box", "Vault Transit mode requires Vault address, token, and transit key")
		} else {
			add("ok", "secret-box", "Vault Transit secret box is configured")
		}
	case "aws-kms":
		if env("WEBHOOKERY_AWS_REGION") == "" || env("WEBHOOKERY_AWS_KMS_KEY_ID") == "" {
			add("blocker", "secret-box", "AWS KMS mode requires AWS region and KMS key id")
		} else {
			add("ok", "secret-box", "AWS KMS secret box is configured with redacted key custody")
		}
		if strings.HasPrefix(strings.ToLower(env("WEBHOOKERY_AWS_KMS_ENDPOINT")), "http://") {
			add("warning", "secret-box", "AWS KMS endpoint override is non-TLS; use only for local emulators")
		}
	default:
		add("blocker", "secret-box", "WEBHOOKERY_SECRET_BOX_MODE must be local, vault-transit, or aws-kms")
	}
}

func addRawStorageFindings(add func(string, string, string), env func(string) string, production bool) {
	rawStorageMode := envDefaultValue(env("WEBHOOKERY_RAW_STORAGE_MODE"), domain.RawStoragePostgres)
	switch rawStorageMode {
	case domain.RawStoragePostgres:
		add("ok", "raw-storage", "PostgreSQL raw payload storage is configured")
	case domain.RawStorageS3:
		if env("WEBHOOKERY_OBJECT_STORAGE_ENDPOINT") == "" || env("WEBHOOKERY_OBJECT_STORAGE_BUCKET") == "" ||
			env("WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY") == "" || env("WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY") == "" {
			add("blocker", "raw-storage", "S3 raw storage requires endpoint, bucket, access key, and secret key")
		} else if containsUnsafePlaceholder(env("WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY")) || containsUnsafePlaceholder(env("WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY")) {
			add("blocker", "raw-storage", "object storage credentials contain placeholder material")
		} else if production && strings.EqualFold(envDefaultValue(env("WEBHOOKERY_OBJECT_STORAGE_USE_SSL"), "true"), "false") {
			add("blocker", "raw-storage", "S3 raw storage must use TLS in production")
		} else if strings.EqualFold(envDefaultValue(env("WEBHOOKERY_OBJECT_STORAGE_USE_SSL"), "true"), "false") {
			add("warning", "raw-storage", "S3 raw storage has TLS disabled; use only for controlled local object-store pilots")
		} else {
			add("ok", "raw-storage", "S3 raw payload storage is configured with TLS")
		}
	default:
		add("blocker", "raw-storage", "WEBHOOKERY_RAW_STORAGE_MODE must be postgres or s3")
	}
}

func addBootstrapFinding(add func(string, string, string), env func(string) string) {
	bootstrapHash := env("WEBHOOKERY_BOOTSTRAP_API_KEY_HASH")
	bootstrapPrefix := strings.ToLower(env("WEBHOOKERY_BOOTSTRAP_API_KEY_PREFIX"))
	switch {
	case bootstrapHash == "":
		add("ok", "bootstrap", "no bootstrap API key hash is configured")
	case containsUnsafePlaceholder(bootstrapHash) || strings.Contains(bootstrapPrefix, "change") || strings.Contains(bootstrapPrefix, "dev"):
		add("blocker", "bootstrap", "bootstrap API key appears to use development placeholder material")
	default:
		add("warning", "bootstrap", "bootstrap API key is configured; rotate or remove it after initial tenant setup")
	}
}

func addProviderProofFinding(add func(string, string, string), env func(string) string) {
	manifestPath := envDefaultValue(env("WEBHOOKERY_PROVIDER_PROOF_MANIFEST_PATH"), "docs/provider-proof-manifest.json")
	// #nosec G304 -- doctor reads an operator-selected local metadata file and never prints its content.
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		add("warning", "provider-proof", "provider proof manifest was not found; run make provider-proof-check from a repository checkout")
		return
	}
	var manifest struct {
		SchemaVersion       string `json:"schema_version"`
		NoLiveProviderCalls bool   `json:"no_live_provider_calls"`
		Proofs              []struct {
			Provider string `json:"provider"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil || manifest.SchemaVersion != "provider-proof-v1" || !manifest.NoLiveProviderCalls {
		add("warning", "provider-proof", "provider proof manifest is present but not valid for pilot readiness")
		return
	}
	if len(manifest.Proofs) == 0 {
		add("warning", "provider-proof", "provider proof manifest has no provider proof entries")
		return
	}
	add("ok", "provider-proof", "provider proof metadata is present; run make provider-proof-check for freshness")
}

func addPilotDatabaseFindings(add func(string, string, string), status pilotDatabaseStatus) {
	add("ok", "database-connectivity", "PostgreSQL connectivity succeeded")
	switch {
	case status.ExpectedMigrations == 0:
		add("warning", "migrations", "local migration files were not found; run make rc-check from a repository checkout")
	case status.AppliedMigrations < status.ExpectedMigrations:
		add("blocker", "migrations", fmt.Sprintf("database has %d applied migrations; repository has %d migration files", status.AppliedMigrations, status.ExpectedMigrations))
	case status.AppliedMigrations > status.ExpectedMigrations:
		add("blocker", "migrations", fmt.Sprintf("database has %d applied migrations; repository has %d migration files", status.AppliedMigrations, status.ExpectedMigrations))
	default:
		add("ok", "migrations", fmt.Sprintf("database has %d applied migrations matching repository files", status.AppliedMigrations))
	}
	if status.PendingOutbox == 0 && status.InProgressOutbox == 0 {
		add("ok", "queue", "durable outbox has no pending or in-progress work")
	} else {
		add("warning", "queue", fmt.Sprintf("durable outbox has pending=%d in_progress=%d; inspect worker health before pilot", status.PendingOutbox, status.InProgressOutbox))
	}
	if status.RetentionPolicies == 0 {
		add("warning", "retention", "no retention policies are configured; define pilot retention before real provider data")
	} else {
		add("ok", "retention", fmt.Sprintf("%d retention policy row(s) found", status.RetentionPolicies))
	}
	if status.AuditChainEntries == 0 {
		add("warning", "audit-chain", "no audit-chain entries found yet; run an evidence drill before pilot traffic")
	} else {
		add("ok", "audit-chain", fmt.Sprintf("%d audit-chain entrie(s) found; run whcp audit verify-chain for full verification", status.AuditChainEntries))
	}
}

func addReceiverConnectivityFinding(add func(string, string, string), env func(string) string, opts pilotDoctorOptions) {
	receiverURL := env("WEBHOOKERY_PILOT_RECEIVER_CHECK_URL")
	if receiverURL == "" {
		add("warning", "receiver-connectivity", "receiver connectivity not configured; set WEBHOOKERY_PILOT_RECEIVER_CHECK_URL only for explicit pilot checks")
		return
	}
	if !strings.EqualFold(env("WEBHOOKERY_PILOT_ALLOW_RECEIVER_CHECK"), "true") {
		add("warning", "receiver-connectivity", "receiver URL is configured but WEBHOOKERY_PILOT_ALLOW_RECEIVER_CHECK=true is required")
		return
	}
	if !opts.Network {
		add("warning", "receiver-connectivity", "receiver connectivity skipped because --no-network is set")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	err := opts.ReceiverCheck(ctx, receiverURL, opts.Timeout)
	cancel()
	if err != nil {
		var policyErr ssrf.PolicyError
		if errors.As(err, &policyErr) {
			add("blocker", "receiver-connectivity", "receiver URL failed SSRF policy validation")
			return
		}
		add("warning", "receiver-connectivity", "receiver connectivity check failed; inspect endpoint test output")
		return
	}
	add("ok", "receiver-connectivity", "receiver connectivity check succeeded")
}

func writeDoctorFindings(w io.Writer, findings []doctorFinding) {
	for _, finding := range findings {
		_, _ = fmt.Fprintf(w, "%s: %s - %s\n", finding.Severity, finding.Check, finding.Message)
	}
}

func countDoctorBlockers(findings []doctorFinding) int {
	count := 0
	for _, finding := range findings {
		if finding.Severity == "blocker" {
			count++
		}
	}
	return count
}

func checkPilotDatabase(ctx context.Context, databaseURL string, timeout time.Duration) (pilotDatabaseStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return pilotDatabaseStatus{}, err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return pilotDatabaseStatus{}, err
	}
	status := pilotDatabaseStatus{}
	files, err := filepath.Glob(filepath.Join("migrations", "*.up.sql"))
	if err == nil {
		status.ExpectedMigrations = len(files)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&status.AppliedMigrations); err != nil {
		return status, err
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE state='pending'").Scan(&status.PendingOutbox); err != nil {
		return status, err
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE state='in_progress'").Scan(&status.InProgressOutbox); err != nil {
		return status, err
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM retention_policies WHERE state='active'").Scan(&status.RetentionPolicies); err != nil {
		return status, err
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_chain_entries").Scan(&status.AuditChainEntries); err != nil {
		return status, err
	}
	return status, nil
}

func checkPilotReceiver(ctx context.Context, rawURL string, timeout time.Duration) error {
	validator := ssrf.Validator{}
	if result := validator.Validate(ctx, rawURL, ssrf.DefaultPolicy()); !result.Allowed {
		return ssrf.PolicyError{Reasons: result.BlockedReasons}
	}
	client := deliveryhttp.HTTPClient(timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("receiver returned server error")
	}
	return nil
}

func envDefaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func containsUnsafePlaceholder(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "change-me") || strings.Contains(lower, "changeme") || strings.Contains(lower, "example")
}

func weakLocalMasterKey(value string) (bool, string) {
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return true, "WEBHOOKERY_MASTER_KEY_BASE64 must be base64 encoded 32 bytes"
	}
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return true, "WEBHOOKERY_MASTER_KEY_BASE64 uses the documented zero-value example key"
	}
	return false, ""
}
