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
