package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"webhookery/internal/adapters/crypto"
	"webhookery/internal/adapters/deliveryhttp"
	"webhookery/internal/adapters/httpapi"
	"webhookery/internal/adapters/objectstore"
	"webhookery/internal/adapters/postgres"
	"webhookery/internal/adapters/signalhttp"
	apppkg "webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/config"
	"webhookery/internal/domain"
	"webhookery/internal/ssrf"
	"webhookery/internal/worker"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func runAPI() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	store, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	openAPI, err := os.ReadFile("openapi.yaml")
	if err != nil {
		return err
	}
	server := httpapi.NewServer(httpapi.ServerConfig{
		Control:             apppkg.NewControlServiceWithRuntimeConfig(store, ssrf.Validator{}, opsRuntimeConfig(cfg)),
		Ingest:              apppkg.NewIngestService(store, apppkg.SystemClock{}),
		Auth:                runtimeAuth(cfg, store),
		SessionAuth:         apppkg.SessionAuthenticator{Lookup: store},
		ProducerAuth:        apppkg.ProducerTokenAuthenticator{Lookup: store},
		ProducerMTLSAuth:    apppkg.ProducerMTLSAuthenticator{Lookup: store},
		OpenAPI:             openAPI,
		EnableUI:            cfg.EnableUI,
		SessionCookieSecure: cfg.Environment == "production",
		Health:              store.Health,
	})
	tlsConfig, err := serverTLSConfig(cfg)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Addr: cfg.HTTPAddr, Handler: server.Routes(), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 64 << 10, TLSConfig: tlsConfig}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting api", "addr", cfg.HTTPAddr)
		if cfg.TLSCertFile != "" {
			errCh <- httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		errCh <- httpServer.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	dir := fs.String("dir", "migrations", "migration directory")
	limit := fs.Int("limit", 100, "maximum audit-chain events to backfill")
	workerID := fs.String("worker-id", "whcp-migrate", "worker id for operational leases")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: whcp migrate [--dir migrations] [--limit 100] [--worker-id whcp-migrate] <up|audit-chain-backfill>")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	switch fs.Arg(0) {
	case "up":
		return postgres.MigrateUp(context.Background(), cfg.DatabaseURL, *dir)
	case "audit-chain-backfill":
		store, err := openStore(context.Background(), cfg)
		if err != nil {
			return err
		}
		defer store.Close()
		result, err := store.BackfillAuditChain(context.Background(), *workerID, *limit)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "audit_chain_backfill lease_acquired=%t tenants_scanned=%d events_backfilled=%d more=%t\n", result.LeaseAcquired, result.TenantsScanned, result.EventsBackfilled, result.More)
		return nil
	default:
		return fmt.Errorf("usage: whcp migrate [--dir migrations] [--limit 100] [--worker-id whcp-migrate] <up|audit-chain-backfill>")
	}
}

func runWorker(args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	once := fs.Bool("once", false, "run one polling iteration")
	interval := fs.Duration("interval", 2*time.Second, "poll interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	store, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	fanout := apppkg.NewDeliveryFanoutService(store, apppkg.SystemClock{})
	reconciliation := apppkg.NewReconciliationService(store, nil)
	processor := apppkg.NewOutboxProcessorService(fanout, reconciliation)
	w := worker.Worker{
		Store:                     store,
		Processor:                 processor,
		DeliveryStore:             store,
		DeliveryClient:            deliveryAdapter{client: deliveryhttp.Client{SSRF: ssrf.Validator{}}},
		NotificationDeliveryStore: store,
		NotificationClient:        signalAdapter{client: signalhttp.Client{SSRF: ssrf.Validator{}}},
		SIEMDeliveryStore:         store,
		SIEMClient:                signalAdapter{client: signalhttp.Client{SSRF: ssrf.Validator{}}},
		RetentionStore:            store,
		MetricsStore:              store,
		AlertStore:                store,
		AuditChainBackfillStore:   store,
		WorkerID:                  "worker-" + time.Now().UTC().Format("20060102150405"),
		Limit:                     10,
	}
	if *once {
		return w.RunOnce(ctx)
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		if err := w.RunOnce(ctx); err != nil {
			slog.Error("worker iteration failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func openStore(ctx context.Context, cfg config.Config) (*postgres.Store, error) {
	box, err := secretBoxFromConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	opts := postgres.StoreOptions{RawStorageMode: cfg.RawStorageMode}
	if cfg.RawStorageMode == domain.RawStorageS3 {
		store, err := objectstore.NewS3Store(objectstore.S3Config{
			Endpoint:  cfg.ObjectStorageEndpoint,
			AccessKey: cfg.ObjectStorageAccessKey,
			SecretKey: cfg.ObjectStorageSecretKey,
			Bucket:    cfg.ObjectStorageBucket,
			Region:    cfg.ObjectStorageRegion,
			UseSSL:    cfg.ObjectStorageUseSSL,
		})
		if err != nil {
			return nil, err
		}
		opts.ObjectStore = store
		opts.ObjectBucket = store.Bucket()
	}
	return postgres.NewWithOptions(ctx, cfg.DatabaseURL, box, opts)
}

func secretBoxFromConfig(ctx context.Context, cfg config.Config) (postgres.SecretBox, error) {
	switch cfg.SecretBoxMode {
	case "", "local":
		return crypto.NewEnvelope(cfg.MasterKeyBase64)
	case "vault-transit":
		return crypto.NewVaultTransitEnvelope(crypto.VaultTransitConfig{
			Address: cfg.VaultAddr,
			Token:   cfg.VaultToken,
			KeyName: cfg.VaultTransitKey,
		})
	case "aws-kms":
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
		if err != nil {
			return nil, fmt.Errorf("load aws config: %w", err)
		}
		client := kms.NewFromConfig(awsCfg, func(opts *kms.Options) {
			if strings.TrimSpace(cfg.AWSKMSEndpoint) != "" {
				opts.BaseEndpoint = aws.String(strings.TrimSpace(cfg.AWSKMSEndpoint))
			}
		})
		return crypto.NewAWSKMSEnvelope(crypto.AWSKMSEnvelopeConfig{
			KeyID:  cfg.AWSKMSKeyID,
			Client: client,
		})
	default:
		return nil, fmt.Errorf("unsupported secret box mode %q", cfg.SecretBoxMode)
	}
}

func serverTLSConfig(cfg config.Config) (*tls.Config, error) {
	if cfg.TLSCertFile == "" && cfg.ProducerMTLSClientCAFile == "" {
		return nil, nil
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ProducerMTLSClientCAFile != "" {
		body, err := readSmallFile(cfg.ProducerMTLSClientCAFile, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("read producer mTLS client CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(body) {
			return nil, fmt.Errorf("producer mTLS client CA file did not contain certificates")
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tlsConfig, nil
}

func opsRuntimeConfig(cfg config.Config) domain.OpsConfig {
	return domain.OpsConfig{
		Environment:             cfg.Environment,
		UIEnabled:               cfg.EnableUI,
		RawStorageMode:          cfg.RawStorageMode,
		ObjectStorageConfigured: cfg.RawStorageMode == domain.RawStorageS3,
		SecretBoxMode:           cfg.SecretBoxMode,
		KeyCustodyConfigured:    cfg.SecretBoxMode != "",
		KeyCustodyKeyRef:        keyCustodyKeyRef(cfg),
		MaxIngressBodyBytes:     2 << 20,
		MaxHeaderBytes:          64 << 10,
		MaxHeaderPairs:          128,
		MaxHeaderValueBytes:     8 << 10,
	}
}

func keyCustodyKeyRef(cfg config.Config) string {
	if cfg.SecretBoxMode != "aws-kms" || strings.TrimSpace(cfg.AWSKMSKeyID) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(cfg.AWSKMSKeyID)))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

func runtimeAuth(cfg config.Config, lookup apppkg.APIKeyLookup) apppkg.Authenticator {
	authenticators := []apppkg.Authenticator{apppkg.APIKeyAuthenticator{Lookup: lookup}}
	if cfg.BootstrapAPIKeyHash != "" {
		authenticators = append(authenticators, apppkg.StaticAuthenticator{
			Hash: cfg.BootstrapAPIKeyHash,
			Actor: authz.Actor{
				ID:       "bootstrap",
				TenantID: cfg.BootstrapTenantID,
				Role:     authz.RoleOwner,
				Scopes:   []string{"*"},
			},
		})
	}
	return apppkg.MultiAuthenticator{Authenticators: authenticators}
}

func readMTLSFiles(certPath, keyPath string) (string, string, error) {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return "", "", fmt.Errorf("mtls-client-cert-file and mtls-client-key-file are required together")
	}
	cert, err := readSmallFile(certPath, 64<<10)
	if err != nil {
		return "", "", fmt.Errorf("read mTLS client certificate: %w", err)
	}
	key, err := readSmallFile(keyPath, 64<<10)
	if err != nil {
		return "", "", fmt.Errorf("read mTLS client key: %w", err)
	}
	return string(cert), string(key), nil
}

func readSmallFile(path string, max int64) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, fmt.Errorf("invalid file path")
	}
	info, err := os.Lstat(path) // #nosec G703 -- explicit local operator PEM path; symlinks, directories, and size are checked before use.
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("path must not be a symlink")
	}
	if info.Size() > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	body, err := os.ReadFile(path) // #nosec G304,G703 -- explicit local operator PEM path; no shell execution and bounded to small PEM files.
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return body, nil
}
