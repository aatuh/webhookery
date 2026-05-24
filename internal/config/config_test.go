package config

import "testing"

func TestLoadDefaultsRawStorageToPostgres(t *testing.T) {
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://example")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RawStorageMode != "postgres" {
		t.Fatalf("raw storage mode=%q want postgres", cfg.RawStorageMode)
	}
}

func TestLoadRequiresS3SettingsWhenS3ModeEnabled(t *testing.T) {
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://example")
	t.Setenv("WEBHOOKERY_RAW_STORAGE_MODE", "s3")

	if _, err := Load(); err == nil {
		t.Fatal("expected s3 configuration error")
	}
}

func TestLoadRejectsInvalidRawStorageMode(t *testing.T) {
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://example")
	t.Setenv("WEBHOOKERY_RAW_STORAGE_MODE", "memory")

	if _, err := Load(); err == nil {
		t.Fatal("expected invalid raw storage mode error")
	}
}

func TestLoadRequiresVaultTransitSettings(t *testing.T) {
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://example")
	t.Setenv("WEBHOOKERY_SECRET_BOX_MODE", "vault-transit")
	t.Setenv("WEBHOOKERY_VAULT_TOKEN", "vault-token")

	if _, err := Load(); err == nil {
		t.Fatal("expected missing vault transit configuration error")
	}
}

func TestLoadRequiresAWSKMSSettings(t *testing.T) {
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://example")
	t.Setenv("WEBHOOKERY_SECRET_BOX_MODE", "aws-kms")
	t.Setenv("WEBHOOKERY_AWS_REGION", "us-east-1")

	if _, err := Load(); err == nil {
		t.Fatal("expected missing aws kms key configuration error")
	}
}

func TestLoadAcceptsAWSKMSSettingsWithoutLocalMasterKey(t *testing.T) {
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://example")
	t.Setenv("WEBHOOKERY_SECRET_BOX_MODE", "aws-kms")
	t.Setenv("WEBHOOKERY_AWS_REGION", "us-east-1")
	t.Setenv("WEBHOOKERY_AWS_KMS_KEY_ID", "arn:aws:kms:us-east-1:123456789012:key/abcd")
	t.Setenv("WEBHOOKERY_AWS_KMS_ENDPOINT", "http://localhost:4566")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SecretBoxMode != "aws-kms" || cfg.AWSRegion != "us-east-1" || cfg.AWSKMSKeyID == "" || cfg.MasterKeyBase64 != "" {
		t.Fatalf("unexpected aws kms config mode=%q region=%q key_set=%v master_key_set=%v", cfg.SecretBoxMode, cfg.AWSRegion, cfg.AWSKMSKeyID != "", cfg.MasterKeyBase64 != "")
	}
}

func TestLoadAcceptsVaultTransitWithoutLocalMasterKey(t *testing.T) {
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://example")
	t.Setenv("WEBHOOKERY_SECRET_BOX_MODE", "vault-transit")
	t.Setenv("WEBHOOKERY_VAULT_ADDR", "https://vault.example")
	t.Setenv("WEBHOOKERY_VAULT_TOKEN", "vault-token")
	t.Setenv("WEBHOOKERY_VAULT_TRANSIT_KEY", "webhookery")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SecretBoxMode != "vault-transit" || cfg.VaultAddr == "" || cfg.VaultTransitKey != "webhookery" || cfg.MasterKeyBase64 != "" {
		t.Fatalf("unexpected vault transit config mode=%q addr_set=%v key=%q master_key_set=%v", cfg.SecretBoxMode, cfg.VaultAddr != "", cfg.VaultTransitKey, cfg.MasterKeyBase64 != "")
	}
}

func TestLoadRequiresTLSFilesForProducerMTLSCA(t *testing.T) {
	t.Setenv("WEBHOOKERY_DATABASE_URL", "postgres://example")
	t.Setenv("WEBHOOKERY_PRODUCER_MTLS_CLIENT_CA_FILE", "ca.pem")

	if _, err := Load(); err == nil {
		t.Fatal("expected producer mTLS CA to require API TLS certificate and key files")
	}
}
