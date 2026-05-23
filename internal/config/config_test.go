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
