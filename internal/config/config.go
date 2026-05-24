package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL              string
	HTTPAddr                 string
	TLSCertFile              string
	TLSKeyFile               string
	ProducerMTLSClientCAFile string
	EnableUI                 bool
	LogLevel                 string
	Environment              string
	SecretBoxMode            string
	MasterKeyBase64          string
	VaultAddr                string
	VaultToken               string
	VaultTransitKey          string
	RawStorageMode           string
	ObjectStorageEndpoint    string
	ObjectStorageBucket      string
	ObjectStorageAccessKey   string
	ObjectStorageSecretKey   string
	ObjectStorageRegion      string
	ObjectStorageUseSSL      bool
	BootstrapTenantID        string
	BootstrapAPIKeyHash      string
	BootstrapAPIKeyPrefix    string
}

func Load() (Config, error) {
	cfg := Config{
		DatabaseURL:              os.Getenv("WEBHOOKERY_DATABASE_URL"),
		HTTPAddr:                 envDefault("WEBHOOKERY_HTTP_ADDR", ":8080"),
		TLSCertFile:              os.Getenv("WEBHOOKERY_TLS_CERT_FILE"),
		TLSKeyFile:               os.Getenv("WEBHOOKERY_TLS_KEY_FILE"),
		ProducerMTLSClientCAFile: os.Getenv("WEBHOOKERY_PRODUCER_MTLS_CLIENT_CA_FILE"),
		LogLevel:                 envDefault("WEBHOOKERY_LOG_LEVEL", "info"),
		Environment:              envDefault("WEBHOOKERY_ENVIRONMENT", "development"),
		SecretBoxMode:            envDefault("WEBHOOKERY_SECRET_BOX_MODE", "local"),
		MasterKeyBase64:          os.Getenv("WEBHOOKERY_MASTER_KEY_BASE64"),
		VaultAddr:                os.Getenv("WEBHOOKERY_VAULT_ADDR"),
		VaultToken:               os.Getenv("WEBHOOKERY_VAULT_TOKEN"),
		VaultTransitKey:          os.Getenv("WEBHOOKERY_VAULT_TRANSIT_KEY"),
		RawStorageMode:           envDefault("WEBHOOKERY_RAW_STORAGE_MODE", "postgres"),
		ObjectStorageEndpoint:    os.Getenv("WEBHOOKERY_OBJECT_STORAGE_ENDPOINT"),
		ObjectStorageBucket:      os.Getenv("WEBHOOKERY_OBJECT_STORAGE_BUCKET"),
		ObjectStorageAccessKey:   os.Getenv("WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY"),
		ObjectStorageSecretKey:   os.Getenv("WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY"),
		ObjectStorageRegion:      os.Getenv("WEBHOOKERY_OBJECT_STORAGE_REGION"),
		BootstrapTenantID:        envDefault("WEBHOOKERY_BOOTSTRAP_TENANT_ID", "ten_bootstrap"),
		BootstrapAPIKeyHash:      os.Getenv("WEBHOOKERY_BOOTSTRAP_API_KEY_HASH"),
		BootstrapAPIKeyPrefix:    os.Getenv("WEBHOOKERY_BOOTSTRAP_API_KEY_PREFIX"),
	}
	enableUI, err := strconv.ParseBool(envDefault("WEBHOOKERY_ENABLE_UI", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("WEBHOOKERY_ENABLE_UI must be boolean: %w", err)
	}
	cfg.EnableUI = enableUI
	objectSSL, err := strconv.ParseBool(envDefault("WEBHOOKERY_OBJECT_STORAGE_USE_SSL", "true"))
	if err != nil {
		return Config{}, fmt.Errorf("WEBHOOKERY_OBJECT_STORAGE_USE_SSL must be boolean: %w", err)
	}
	cfg.ObjectStorageUseSSL = objectSSL
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("WEBHOOKERY_DATABASE_URL is required")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("WEBHOOKERY_TLS_CERT_FILE and WEBHOOKERY_TLS_KEY_FILE are required together")
	}
	if cfg.ProducerMTLSClientCAFile != "" && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("WEBHOOKERY_PRODUCER_MTLS_CLIENT_CA_FILE requires WEBHOOKERY_TLS_CERT_FILE and WEBHOOKERY_TLS_KEY_FILE")
	}
	if cfg.SecretBoxMode != "local" && cfg.SecretBoxMode != "vault-transit" {
		return Config{}, fmt.Errorf("WEBHOOKERY_SECRET_BOX_MODE must be local or vault-transit")
	}
	if cfg.SecretBoxMode == "vault-transit" {
		if cfg.VaultAddr == "" || cfg.VaultToken == "" || cfg.VaultTransitKey == "" {
			return Config{}, fmt.Errorf("vault-transit secret box requires WEBHOOKERY_VAULT_ADDR, WEBHOOKERY_VAULT_TOKEN, and WEBHOOKERY_VAULT_TRANSIT_KEY")
		}
	}
	if cfg.RawStorageMode != "postgres" && cfg.RawStorageMode != "s3" {
		return Config{}, fmt.Errorf("WEBHOOKERY_RAW_STORAGE_MODE must be postgres or s3")
	}
	if cfg.RawStorageMode == "s3" {
		if cfg.ObjectStorageEndpoint == "" || cfg.ObjectStorageBucket == "" || cfg.ObjectStorageAccessKey == "" || cfg.ObjectStorageSecretKey == "" {
			return Config{}, fmt.Errorf("s3 raw storage requires WEBHOOKERY_OBJECT_STORAGE_ENDPOINT, WEBHOOKERY_OBJECT_STORAGE_BUCKET, WEBHOOKERY_OBJECT_STORAGE_ACCESS_KEY, and WEBHOOKERY_OBJECT_STORAGE_SECRET_KEY")
		}
	}
	if cfg.MasterKeyBase64 != "" {
		key, err := base64.StdEncoding.DecodeString(cfg.MasterKeyBase64)
		if err != nil || len(key) != 32 {
			return Config{}, fmt.Errorf("WEBHOOKERY_MASTER_KEY_BASE64 must be base64 encoded 32 bytes")
		}
	}
	return cfg, nil
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
