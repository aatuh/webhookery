package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"webhookery/internal/domain"
)

func runDoctor(args []string) error {
	if len(args) != 1 || args[0] != "production" {
		return fmt.Errorf("usage: whcp doctor production")
	}
	findings := productionDoctorFindings(os.Getenv)
	writeDoctorFindings(os.Stdout, findings)
	if blockers := countDoctorBlockers(findings); blockers > 0 {
		return fmt.Errorf("production doctor found %d blocker(s)", blockers)
	}
	return nil
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

	secretBoxMode := envDefaultValue(env("WEBHOOKERY_SECRET_BOX_MODE"), "local")
	switch secretBoxMode {
	case "local":
		master := env("WEBHOOKERY_MASTER_KEY_BASE64")
		if master == "" {
			add("blocker", "secret-box", "local secret box requires WEBHOOKERY_MASTER_KEY_BASE64")
		} else if weak, reason := weakLocalMasterKey(master); weak {
			add("blocker", "secret-box", reason)
		} else {
			add("warning", "secret-box", "local secret box is configured; prefer Vault Transit or AWS KMS for shared production operations")
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
		} else if strings.EqualFold(envDefaultValue(env("WEBHOOKERY_OBJECT_STORAGE_USE_SSL"), "true"), "false") {
			add("blocker", "raw-storage", "S3 raw storage must use TLS in production")
		} else {
			add("ok", "raw-storage", "S3 raw payload storage is configured with TLS")
		}
	default:
		add("blocker", "raw-storage", "WEBHOOKERY_RAW_STORAGE_MODE must be postgres or s3")
	}

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

	return findings
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
