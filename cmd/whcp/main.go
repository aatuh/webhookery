package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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
	"webhookery/internal/evidence"
	"webhookery/internal/provider"
	"webhookery/internal/ssrf"
	"webhookery/internal/transform"
	"webhookery/internal/worker"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "api":
		return runAPI()
	case "migrate":
		return runMigrate(args[1:])
	case "worker", "scheduler":
		return runWorker(args[1:])
	case "admin":
		return runAdmin(args[1:])
	case "api-keys":
		return runAPIKeys(args[1:])
	case "producer-clients":
		return runProducerClients(args[1:])
	case "producer-mtls-identities":
		return runProducerMTLSIdentities(args[1:])
	case "key-custody":
		return runKeyCustody(args[1:])
	case "identity-providers":
		return runIdentityProviders(args[1:])
	case "scim-tokens":
		return runSCIMTokens(args[1:])
	case "role-bindings":
		return runRoleBindings(args[1:])
	case "access-policies":
		return runAccessPolicies(args[1:])
	case "authz":
		return runAuthz(args[1:])
	case "events":
		return runEvents(args[1:])
	case "sources":
		return runSources(args[1:])
	case "provider-connections":
		return runProviderConnections(args[1:])
	case "adapters":
		return runAdapters(args[1:])
	case "endpoints":
		return runEndpoints(args[1:])
	case "subscriptions":
		return runSubscriptions(args[1:])
	case "retry-policies":
		return runRetryPolicies(args[1:])
	case "routes":
		return runRoutes(args[1:])
	case "transformations":
		return runTransformations(args[1:])
	case "deliveries":
		return runDeliveries(args[1:])
	case "replay-jobs":
		return runReplayJobs(args[1:])
	case "reconciliation-jobs":
		return runReconciliationJobs(args[1:])
	case "ops":
		return runOps(args[1:])
	case "alerts":
		return runAlerts(args[1:])
	case "notification-channels":
		return runNotificationChannels(args[1:])
	case "notification-deliveries":
		return runNotificationDeliveries(args[1:])
	case "siem-sinks":
		return runSIEMSinks(args[1:])
	case "siem-deliveries":
		return runSIEMDeliveries(args[1:])
	case "audit":
		return runAudit(args[1:])
	case "retention":
		return runRetention(args[1:])
	case "schemas":
		return runSchemas(args[1:])
	case "dead-letter":
		return runDeadLetter(args[1:])
	case "quarantine":
		return runQuarantine(args[1:])
	case "signatures":
		return runSignatures(args[1:])
	default:
		return usage()
	}
}

func usage() error {
	return fmt.Errorf("usage: whcp <api|worker|scheduler|migrate|admin|api-keys|producer-clients|producer-mtls-identities|key-custody|identity-providers|scim-tokens|role-bindings|access-policies|authz|events|sources|provider-connections|adapters|endpoints|subscriptions|retry-policies|routes|transformations|deliveries|replay-jobs|reconciliation-jobs|ops|alerts|notification-channels|notification-deliveries|siem-sinks|siem-deliveries|audit|retention|schemas|dead-letter|quarantine|signatures>")
}

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
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	dir := fs.String("dir", "migrations", "migration directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || fs.Arg(0) != "up" {
		return fmt.Errorf("usage: whcp migrate [--dir migrations] up")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	return postgres.MigrateUp(context.Background(), cfg.DatabaseURL, *dir)
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
	w := worker.Worker{
		Store:                     store,
		Processor:                 store,
		DeliveryStore:             store,
		DeliveryClient:            deliveryAdapter{client: deliveryhttp.Client{SSRF: ssrf.Validator{}}},
		NotificationDeliveryStore: store,
		NotificationClient:        signalAdapter{client: signalhttp.Client{SSRF: ssrf.Validator{}}},
		SIEMDeliveryStore:         store,
		SIEMClient:                signalAdapter{client: signalhttp.Client{SSRF: ssrf.Validator{}}},
		RetentionStore:            store,
		MetricsStore:              store,
		AlertStore:                store,
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

func runAdmin(args []string) error {
	if len(args) != 2 || args[0] != "hash-key" {
		return fmt.Errorf("usage: whcp admin hash-key <api-key>")
	}
	fmt.Println(apppkg.HashToken(args[1]))
	return nil
}

func runAPIKeys(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp api-keys <create|list|revoke>")
	}
	fs := flag.NewFlagSet("api-keys "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	name := fs.String("name", "", "API key name")
	userID := fs.String("user-id", "", "user id")
	email := fs.String("email", "", "user email")
	role := fs.String("role", "operator", "membership role")
	scopes := fs.String("scopes", "events:read,deliveries:read", "comma-separated scopes")
	keyID := fs.String("key-id", "", "API key id")
	reason := fs.String("reason", "", "revocation reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/api-keys", map[string]any{"name": *name, "user_id": *userID, "email": *email, "role": *role, "scopes": splitCSV(*scopes)})
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/api-keys")
	case "revoke":
		return postJSON(*baseURL, *apiKey, "/v1/api-keys/"+url.PathEscape(*keyID)+":revoke", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp api-keys <create|list|revoke>")
	}
}

func runProducerClients(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp producer-clients <list|get|create|update|disable|rotate-secret>")
	}
	fs := flag.NewFlagSet("producer-clients "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	clientID := fs.String("client-id", "", "producer client id")
	name := fs.String("name", "", "producer client name")
	sourceID := fs.String("source-id", "", "optional bound source id")
	scopes := fs.String("scopes", "events:write", "comma-separated scopes")
	ttl := fs.Int("token-ttl-seconds", 900, "producer access token TTL in seconds")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/producer-clients")
	case "get":
		if strings.TrimSpace(*clientID) == "" {
			return fmt.Errorf("client-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/producer-clients/"+url.PathEscape(*clientID))
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/producer-clients", map[string]any{
			"name":              *name,
			"source_id":         *sourceID,
			"scopes":            splitCSV(*scopes),
			"token_ttl_seconds": *ttl,
		})
	case "update":
		if strings.TrimSpace(*clientID) == "" {
			return fmt.Errorf("client-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*sourceID) != "" {
			body["source_id"] = *sourceID
		}
		if strings.TrimSpace(*scopes) != "" {
			body["scopes"] = splitCSV(*scopes)
		}
		if *ttl != 900 {
			body["token_ttl_seconds"] = *ttl
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/producer-clients/"+url.PathEscape(*clientID), body)
	case "disable":
		if strings.TrimSpace(*clientID) == "" {
			return fmt.Errorf("client-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/producer-clients/"+url.PathEscape(*clientID), map[string]string{"reason": *reason})
	case "rotate-secret":
		if strings.TrimSpace(*clientID) == "" {
			return fmt.Errorf("client-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/producer-clients/"+url.PathEscape(*clientID)+"/secrets:rotate", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp producer-clients <list|get|create|update|disable|rotate-secret>")
	}
}

func runProducerMTLSIdentities(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp producer-mtls-identities <list|get|create|update|disable|verify>")
	}
	fs := flag.NewFlagSet("producer-mtls-identities "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	identityID := fs.String("identity-id", "", "producer mTLS identity id")
	name := fs.String("name", "", "identity name")
	sourceID := fs.String("source-id", "", "optional bound source id")
	certFile := fs.String("cert-file", "", "PEM certificate file")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	certBody := func() (string, error) {
		if strings.TrimSpace(*certFile) == "" {
			return "", fmt.Errorf("cert-file is required")
		}
		body, err := readSmallFile(*certFile, 1<<20)
		if err != nil {
			return "", err
		}
		return string(body), nil
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities")
	case "get":
		if strings.TrimSpace(*identityID) == "" {
			return fmt.Errorf("identity-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities/"+url.PathEscape(*identityID))
	case "create":
		certPEM, err := certBody()
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities", map[string]any{"name": *name, "source_id": *sourceID, "certificate_pem": certPEM})
	case "update":
		if strings.TrimSpace(*identityID) == "" {
			return fmt.Errorf("identity-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*sourceID) != "" {
			body["source_id"] = *sourceID
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities/"+url.PathEscape(*identityID), body)
	case "disable":
		if strings.TrimSpace(*identityID) == "" {
			return fmt.Errorf("identity-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities/"+url.PathEscape(*identityID), map[string]string{"reason": *reason})
	case "verify":
		if strings.TrimSpace(*identityID) == "" {
			return fmt.Errorf("identity-id is required")
		}
		certPEM, err := certBody()
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities/"+url.PathEscape(*identityID)+":verify", map[string]string{"certificate_pem": certPEM})
	default:
		return fmt.Errorf("usage: whcp producer-mtls-identities <list|get|create|update|disable|verify>")
	}
}

func runKeyCustody(args []string) error {
	if len(args) == 0 || args[0] != "test" {
		return fmt.Errorf("usage: whcp key-custody test")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	box, err := secretBoxFromConfig(cfg)
	if err != nil {
		return err
	}
	const marker = "webhookery-key-custody-test"
	ciphertext, err := box.Encrypt([]byte(marker))
	if err != nil {
		return fmt.Errorf("key custody encrypt test failed")
	}
	plaintext, err := box.Decrypt(ciphertext)
	if err != nil {
		return fmt.Errorf("key custody decrypt test failed")
	}
	if string(plaintext) != marker {
		return fmt.Errorf("key custody decrypt test returned unexpected plaintext")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"mode":       cfg.SecretBoxMode,
		"configured": true,
		"ok":         true,
		"key_ref":    keyCustodyKeyRef(cfg),
	})
}

func runIdentityProviders(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp identity-providers <list|get|create|update|disable|test>")
	}
	fs := flag.NewFlagSet("identity-providers "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	providerID := fs.String("provider-id", "", "identity provider id")
	name := fs.String("name", "", "identity provider name")
	issuerURL := fs.String("issuer-url", "", "OIDC issuer URL")
	authURL := fs.String("authorization-url", "", "OIDC authorization endpoint override")
	tokenURL := fs.String("token-url", "", "OIDC token endpoint override")
	jwksURL := fs.String("jwks-url", "", "OIDC JWKS endpoint override")
	clientID := fs.String("client-id", "", "OIDC client id")
	clientSecret := fs.String("client-secret", "", "OIDC client secret")
	redirectURI := fs.String("redirect-uri", "", "OIDC callback redirect URI")
	allowedDomains := fs.String("allowed-email-domains", "", "comma-separated allowed email domains")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/identity-providers")
	case "get":
		if strings.TrimSpace(*providerID) == "" {
			return fmt.Errorf("provider-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/identity-providers/"+url.PathEscape(*providerID))
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/identity-providers", map[string]any{
			"name":                   *name,
			"provider_type":          "oidc",
			"issuer_url":             *issuerURL,
			"authorization_endpoint": *authURL,
			"token_endpoint":         *tokenURL,
			"jwks_uri":               *jwksURL,
			"client_id":              *clientID,
			"client_secret":          *clientSecret,
			"redirect_uri":           *redirectURI,
			"allowed_email_domains":  splitCSV(*allowedDomains),
		})
	case "update":
		if strings.TrimSpace(*providerID) == "" {
			return fmt.Errorf("provider-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*issuerURL) != "" {
			body["issuer_url"] = *issuerURL
		}
		if strings.TrimSpace(*authURL) != "" {
			body["authorization_endpoint"] = *authURL
		}
		if strings.TrimSpace(*tokenURL) != "" {
			body["token_endpoint"] = *tokenURL
		}
		if strings.TrimSpace(*jwksURL) != "" {
			body["jwks_uri"] = *jwksURL
		}
		if strings.TrimSpace(*clientID) != "" {
			body["client_id"] = *clientID
		}
		if strings.TrimSpace(*clientSecret) != "" {
			body["client_secret"] = *clientSecret
		}
		if strings.TrimSpace(*redirectURI) != "" {
			body["redirect_uri"] = *redirectURI
		}
		if strings.TrimSpace(*allowedDomains) != "" {
			body["allowed_email_domains"] = splitCSV(*allowedDomains)
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/identity-providers/"+url.PathEscape(*providerID), body)
	case "disable":
		if strings.TrimSpace(*providerID) == "" {
			return fmt.Errorf("provider-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/identity-providers/"+url.PathEscape(*providerID), map[string]string{"reason": *reason})
	case "test":
		if strings.TrimSpace(*providerID) == "" {
			return fmt.Errorf("provider-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/identity-providers/"+url.PathEscape(*providerID)+":test", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp identity-providers <list|get|create|update|disable|test>")
	}
}

func runSCIMTokens(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp scim-tokens <list|create|revoke>")
	}
	fs := flag.NewFlagSet("scim-tokens "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	name := fs.String("name", "", "SCIM token name")
	tokenID := fs.String("token-id", "", "SCIM token id")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/scim-tokens")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/scim-tokens", map[string]string{"name": *name})
	case "revoke":
		if strings.TrimSpace(*tokenID) == "" {
			return fmt.Errorf("token-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/scim-tokens/"+url.PathEscape(*tokenID), map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp scim-tokens <list|create|revoke>")
	}
}

func runRoleBindings(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp role-bindings <list|create|update|disable>")
	}
	fs := flag.NewFlagSet("role-bindings "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	bindingID := fs.String("binding-id", "", "role binding id")
	principalType := fs.String("principal-type", "user", "user or group")
	principalID := fs.String("principal-id", "", "principal id")
	role := fs.String("role", "support", "role")
	resourceFamily := fs.String("resource-family", "*", "resource family")
	resourceID := fs.String("resource-id", "*", "resource id")
	environment := fs.String("environment", "*", "environment")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/role-bindings")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/role-bindings", map[string]any{"principal_type": *principalType, "principal_id": *principalID, "role": *role, "resource_family": *resourceFamily, "resource_id": *resourceID, "environment": *environment, "reason": *reason})
	case "update":
		if strings.TrimSpace(*bindingID) == "" {
			return fmt.Errorf("binding-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*role) != "" {
			body["role"] = *role
		}
		if strings.TrimSpace(*resourceFamily) != "" {
			body["resource_family"] = *resourceFamily
		}
		if strings.TrimSpace(*resourceID) != "" {
			body["resource_id"] = *resourceID
		}
		if strings.TrimSpace(*environment) != "" {
			body["environment"] = *environment
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/role-bindings/"+url.PathEscape(*bindingID), body)
	case "disable":
		if strings.TrimSpace(*bindingID) == "" {
			return fmt.Errorf("binding-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/role-bindings/"+url.PathEscape(*bindingID), map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp role-bindings <list|create|update|disable>")
	}
}

func runAccessPolicies(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp access-policies <list|create|update|disable>")
	}
	fs := flag.NewFlagSet("access-policies "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	policyID := fs.String("policy-id", "", "access policy id")
	name := fs.String("name", "", "policy name")
	action := fs.String("action", "", "action")
	effect := fs.String("effect", "deny", "allow or deny")
	resourceFamily := fs.String("resource-family", "*", "resource family")
	environment := fs.String("environment", "*", "environment")
	conditions := fs.String("conditions", "{}", "JSON policy conditions")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/access-policies")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/access-policies", map[string]any{"name": *name, "action": *action, "effect": *effect, "resource_family": *resourceFamily, "environment": *environment, "conditions": json.RawMessage(*conditions), "reason": *reason})
	case "update":
		if strings.TrimSpace(*policyID) == "" {
			return fmt.Errorf("policy-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*action) != "" {
			body["action"] = *action
		}
		if strings.TrimSpace(*effect) != "" {
			body["effect"] = *effect
		}
		if strings.TrimSpace(*resourceFamily) != "" {
			body["resource_family"] = *resourceFamily
		}
		if strings.TrimSpace(*environment) != "" {
			body["environment"] = *environment
		}
		if strings.TrimSpace(*conditions) != "" {
			body["conditions"] = json.RawMessage(*conditions)
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/access-policies/"+url.PathEscape(*policyID), body)
	case "disable":
		if strings.TrimSpace(*policyID) == "" {
			return fmt.Errorf("policy-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/access-policies/"+url.PathEscape(*policyID), map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp access-policies <list|create|update|disable>")
	}
}

func runAuthz(args []string) error {
	if len(args) == 0 || args[0] != "explain" {
		return fmt.Errorf("usage: whcp authz explain")
	}
	fs := flag.NewFlagSet("authz explain", flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	actorID := fs.String("actor-id", "", "actor id to explain")
	action := fs.String("action", "", "action")
	resourceFamily := fs.String("resource-family", "", "resource family")
	resourceID := fs.String("resource-id", "", "resource id")
	environment := fs.String("environment", "", "environment")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	return postJSON(*baseURL, *apiKey, "/v1/authz:explain", map[string]any{"actor_id": *actorID, "action": *action, "resource_family": *resourceFamily, "resource_id": *resourceID, "environment": *environment})
}

func runEvents(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp events <list|get|timeline|raw-export|normalized>")
	}
	fs := flag.NewFlagSet("events "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	eventID := fs.String("event-id", "", "event id")
	output := fs.String("output", "-", "raw output path, or '-' for stdout")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/events")
	case "get":
		return getJSON(*baseURL, *apiKey, "/v1/events/"+url.PathEscape(*eventID))
	case "timeline":
		return getJSON(*baseURL, *apiKey, "/v1/events/"+url.PathEscape(*eventID)+"/timeline")
	case "normalized":
		return getJSON(*baseURL, *apiKey, "/v1/events/"+url.PathEscape(*eventID)+"/normalized")
	case "raw-export":
		return exportRawPayload(*baseURL, *apiKey, *eventID, *output)
	default:
		return fmt.Errorf("usage: whcp events <list|get|timeline|raw-export|normalized>")
	}
}

func runSources(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp sources <list|get|create|update|delete|rotate-secret>")
	}
	fs := flag.NewFlagSet("sources "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	name := fs.String("name", "", "source name")
	providerName := fs.String("provider", "", "provider")
	secret := fs.String("secret", "", "verification secret")
	sourceID := fs.String("source-id", "", "source id")
	state := fs.String("state", "", "source state")
	graceHours := fs.Int("grace-hours", 72, "old secret grace period in hours")
	reason := fs.String("reason", "", "change reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/sources")
	case "get":
		if strings.TrimSpace(*sourceID) == "" {
			return fmt.Errorf("source-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/sources/"+url.PathEscape(*sourceID))
	case "create":
		body := map[string]string{"name": *name, "provider": *providerName, "verification_secret": *secret}
		return postJSON(*baseURL, *apiKey, "/v1/sources", body)
	case "update":
		if strings.TrimSpace(*sourceID) == "" {
			return fmt.Errorf("source-id is required")
		}
		body := map[string]string{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/sources/"+url.PathEscape(*sourceID), body)
	case "delete":
		if strings.TrimSpace(*sourceID) == "" {
			return fmt.Errorf("source-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/sources/"+url.PathEscape(*sourceID), map[string]string{"reason": *reason})
	case "rotate-secret":
		if strings.TrimSpace(*sourceID) == "" {
			return fmt.Errorf("source-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/sources/"+url.PathEscape(*sourceID)+"/secrets:rotate", map[string]any{"new_secret": *secret, "grace_period_hours": *graceHours, "reason": *reason})
	default:
		return fmt.Errorf("usage: whcp sources <list|get|create|update|delete|rotate-secret>")
	}
}

func runProviderConnections(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp provider-connections <list|get|create|verify|revoke>")
	}
	fs := flag.NewFlagSet("provider-connections "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	connectionID := fs.String("connection-id", "", "provider connection id")
	name := fs.String("name", "", "connection name")
	providerName := fs.String("provider", "", "stripe, github, shopify, or slack")
	credential := fs.String("credential", "", "provider API credential")
	credentialType := fs.String("credential-type", "api_key", "api_key or bearer_token")
	config := fs.String("config", "", "comma-separated key=value provider config")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/provider-connections")
	case "get":
		if strings.TrimSpace(*connectionID) == "" {
			return fmt.Errorf("connection-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/provider-connections/"+url.PathEscape(*connectionID))
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/provider-connections", map[string]any{
			"name":            *name,
			"provider":        *providerName,
			"credential":      *credential,
			"credential_type": *credentialType,
			"config":          parseKeyValueCSV(*config),
		})
	case "verify":
		if strings.TrimSpace(*connectionID) == "" {
			return fmt.Errorf("connection-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/provider-connections/"+url.PathEscape(*connectionID)+":verify", map[string]string{"reason": *reason})
	case "revoke":
		if strings.TrimSpace(*connectionID) == "" {
			return fmt.Errorf("connection-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/provider-connections/"+url.PathEscape(*connectionID)+":revoke", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp provider-connections <list|get|create|verify|revoke>")
	}
}

func runEndpoints(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp endpoints <list|get|validate-url|create|update|delete|test|rotate-secret>")
	}
	fs := flag.NewFlagSet("endpoints "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	rawURL := fs.String("url", "", "endpoint URL")
	name := fs.String("name", "", "endpoint name")
	endpointID := fs.String("endpoint-id", "", "endpoint id")
	state := fs.String("state", "", "endpoint state")
	reason := fs.String("reason", "", "operator reason")
	retryPolicyID := fs.String("retry-policy-id", "", "retry policy id")
	mtlsClientCertFile := fs.String("mtls-client-cert-file", "", "PEM client certificate for endpoint mTLS")
	mtlsClientKeyFile := fs.String("mtls-client-key-file", "", "PEM client private key for endpoint mTLS")
	graceHours := fs.Int("grace-hours", 72, "old signing secret grace period in hours")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/endpoints")
	case "get":
		if strings.TrimSpace(*endpointID) == "" {
			return fmt.Errorf("endpoint-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/endpoints/"+url.PathEscape(*endpointID))
	case "validate-url":
		return postJSON(*baseURL, *apiKey, "/v1/endpoints:validate-url", map[string]string{"url": *rawURL})
	case "create":
		body := map[string]string{"name": *name, "url": *rawURL, "retry_policy_id": *retryPolicyID}
		if *mtlsClientCertFile != "" || *mtlsClientKeyFile != "" {
			cert, key, err := readMTLSFiles(*mtlsClientCertFile, *mtlsClientKeyFile)
			if err != nil {
				return err
			}
			body["mtls_client_cert_pem"] = cert
			body["mtls_client_key_pem"] = key
		}
		return postJSON(*baseURL, *apiKey, "/v1/endpoints", body)
	case "update":
		if strings.TrimSpace(*endpointID) == "" {
			return fmt.Errorf("endpoint-id is required")
		}
		body := map[string]string{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*rawURL) != "" {
			body["url"] = *rawURL
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		if strings.TrimSpace(*retryPolicyID) != "" {
			body["retry_policy_id"] = *retryPolicyID
		}
		return patchJSON(*baseURL, *apiKey, "/v1/endpoints/"+url.PathEscape(*endpointID), body)
	case "delete":
		if strings.TrimSpace(*endpointID) == "" {
			return fmt.Errorf("endpoint-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/endpoints/"+url.PathEscape(*endpointID), map[string]string{"reason": *reason})
	case "test":
		if strings.TrimSpace(*endpointID) == "" {
			return fmt.Errorf("endpoint-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/endpoints/"+url.PathEscape(*endpointID)+":test", map[string]string{"reason": *reason})
	case "rotate-secret":
		if strings.TrimSpace(*endpointID) == "" {
			return fmt.Errorf("endpoint-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/endpoints/"+url.PathEscape(*endpointID)+"/secrets:rotate", map[string]any{"grace_period_hours": *graceHours, "reason": *reason})
	default:
		return fmt.Errorf("usage: whcp endpoints <list|get|validate-url|create|update|delete|test|rotate-secret>")
	}
}

func runSubscriptions(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp subscriptions <list|get|create|update|delete>")
	}
	fs := flag.NewFlagSet("subscriptions "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	subscriptionID := fs.String("subscription-id", "", "subscription id")
	endpointID := fs.String("endpoint-id", "", "endpoint id")
	eventTypes := fs.String("event-types", "", "comma-separated event types")
	payloadFormat := fs.String("payload-format", "", "payload format")
	transformationID := fs.String("transformation-id", "", "optional transformation id")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/subscriptions")
	case "get":
		if strings.TrimSpace(*subscriptionID) == "" {
			return fmt.Errorf("subscription-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/subscriptions/"+url.PathEscape(*subscriptionID))
	case "create":
		body := map[string]any{
			"endpoint_id":       *endpointID,
			"event_types":       splitCSV(*eventTypes),
			"transformation_id": *transformationID,
		}
		if strings.TrimSpace(*payloadFormat) != "" {
			body["payload_format"] = *payloadFormat
		}
		return postJSON(*baseURL, *apiKey, "/v1/subscriptions", body)
	case "update":
		if strings.TrimSpace(*subscriptionID) == "" {
			return fmt.Errorf("subscription-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*endpointID) != "" {
			body["endpoint_id"] = *endpointID
		}
		if strings.TrimSpace(*eventTypes) != "" {
			body["event_types"] = splitCSV(*eventTypes)
		}
		if strings.TrimSpace(*payloadFormat) != "" {
			body["payload_format"] = *payloadFormat
		}
		if strings.TrimSpace(*transformationID) != "" {
			body["transformation_id"] = *transformationID
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/subscriptions/"+url.PathEscape(*subscriptionID), body)
	case "delete":
		if strings.TrimSpace(*subscriptionID) == "" {
			return fmt.Errorf("subscription-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/subscriptions/"+url.PathEscape(*subscriptionID), map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp subscriptions <list|get|create|update|delete>")
	}
}

func runRetryPolicies(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp retry-policies <list|get|create|update|delete>")
	}
	fs := flag.NewFlagSet("retry-policies "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	retryPolicyID := fs.String("retry-policy-id", "", "retry policy id")
	name := fs.String("name", "", "retry policy name")
	maxAttempts := fs.Int("max-attempts", -1, "maximum attempts")
	maxDurationSeconds := fs.Int("max-duration-seconds", -1, "maximum retry duration in seconds")
	initialDelaySeconds := fs.Int("initial-delay-seconds", -1, "initial retry delay in seconds")
	maxDelaySeconds := fs.Int("max-delay-seconds", -1, "maximum retry delay in seconds")
	rateLimitPerMinute := fs.Int("rate-limit-per-minute", -1, "optional replay/delivery rate hint")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/retry-policies")
	case "get":
		if strings.TrimSpace(*retryPolicyID) == "" {
			return fmt.Errorf("retry-policy-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/retry-policies/"+url.PathEscape(*retryPolicyID))
	case "create":
		body := map[string]any{
			"name":                  *name,
			"max_attempts":          valueOrDefault(*maxAttempts, 12),
			"max_duration_seconds":  valueOrDefault(*maxDurationSeconds, int((72*time.Hour)/time.Second)),
			"initial_delay_seconds": valueOrDefault(*initialDelaySeconds, 10),
			"max_delay_seconds":     valueOrDefault(*maxDelaySeconds, int((6*time.Hour)/time.Second)),
			"rate_limit_per_minute": valueOrDefault(*rateLimitPerMinute, 0),
			"state":                 valueOrDefaultString(*state, domain.StateActive),
		}
		return postJSON(*baseURL, *apiKey, "/v1/retry-policies", body)
	case "update":
		if strings.TrimSpace(*retryPolicyID) == "" {
			return fmt.Errorf("retry-policy-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if *maxAttempts >= 0 {
			body["max_attempts"] = *maxAttempts
		}
		if *maxDurationSeconds >= 0 {
			body["max_duration_seconds"] = *maxDurationSeconds
		}
		if *initialDelaySeconds >= 0 {
			body["initial_delay_seconds"] = *initialDelaySeconds
		}
		if *maxDelaySeconds >= 0 {
			body["max_delay_seconds"] = *maxDelaySeconds
		}
		if *rateLimitPerMinute >= 0 {
			body["rate_limit_per_minute"] = *rateLimitPerMinute
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/retry-policies/"+url.PathEscape(*retryPolicyID), body)
	case "delete":
		if strings.TrimSpace(*retryPolicyID) == "" {
			return fmt.Errorf("retry-policy-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/retry-policies/"+url.PathEscape(*retryPolicyID), map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp retry-policies <list|get|create|update|delete>")
	}
}

func runRoutes(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp routes <list|get|create|update|delete|activate|dry-run|versions>")
	}
	fs := flag.NewFlagSet("routes "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	routeID := fs.String("route-id", "", "route id")
	sourceID := fs.String("source-id", "", "source id")
	endpointID := fs.String("endpoint-id", "", "endpoint id")
	eventTypes := fs.String("event-types", "", "comma-separated event types")
	eventID := fs.String("event-id", "", "event id")
	reason := fs.String("reason", "", "change reason")
	name := fs.String("name", "", "route name")
	priority := fs.Int("priority", -1, "route priority")
	state := fs.String("state", "", "draft, active, or inactive")
	retryPolicyID := fs.String("retry-policy-id", "", "retry policy id")
	transformationID := fs.String("transformation-id", "", "optional transformation id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/routes")
	case "get":
		if strings.TrimSpace(*routeID) == "" {
			return fmt.Errorf("route-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/routes/"+url.PathEscape(*routeID))
	case "create":
		body := map[string]any{"name": *name, "source_id": *sourceID, "endpoint_id": *endpointID, "event_types": splitCSV(*eventTypes), "retry_policy_id": *retryPolicyID, "transformation_id": *transformationID}
		if *priority >= 0 {
			body["priority"] = *priority
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return postJSON(*baseURL, *apiKey, "/v1/routes", body)
	case "update":
		if strings.TrimSpace(*routeID) == "" {
			return fmt.Errorf("route-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*sourceID) != "" {
			body["source_id"] = *sourceID
		}
		if strings.TrimSpace(*endpointID) != "" {
			body["endpoint_id"] = *endpointID
		}
		if strings.TrimSpace(*eventTypes) != "" {
			body["event_types"] = splitCSV(*eventTypes)
		}
		if *priority >= 0 {
			body["priority"] = *priority
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		if strings.TrimSpace(*retryPolicyID) != "" {
			body["retry_policy_id"] = *retryPolicyID
		}
		if strings.TrimSpace(*transformationID) != "" {
			body["transformation_id"] = *transformationID
		}
		return patchJSON(*baseURL, *apiKey, "/v1/routes/"+url.PathEscape(*routeID), body)
	case "delete":
		if strings.TrimSpace(*routeID) == "" {
			return fmt.Errorf("route-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/routes/"+url.PathEscape(*routeID), map[string]string{"reason": *reason})
	case "activate":
		if strings.TrimSpace(*routeID) == "" {
			return fmt.Errorf("route-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/routes/"+url.PathEscape(*routeID)+":activate", map[string]string{"reason": *reason})
	case "dry-run":
		if strings.TrimSpace(*routeID) == "" {
			return fmt.Errorf("route-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/routes/"+url.PathEscape(*routeID)+":dry-run", map[string]string{"event_id": *eventID})
	case "versions":
		if strings.TrimSpace(*routeID) == "" {
			return fmt.Errorf("route-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/routes/"+url.PathEscape(*routeID)+"/versions")
	default:
		return fmt.Errorf("usage: whcp routes <list|get|create|update|delete|activate|dry-run|versions>")
	}
}

func runTransformations(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp transformations <list|create|version|activate|dry-run>")
	}
	fs := flag.NewFlagSet("transformations "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	transformationID := fs.String("transformation-id", "", "transformation id")
	versionID := fs.String("version-id", "", "transformation version id")
	name := fs.String("name", "", "transformation name")
	operationsPath := fs.String("operations-file", "", "JSON operations file")
	payloadPath := fs.String("payload-file", "", "JSON payload file for local dry-run")
	reason := fs.String("reason", "", "activation reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/transformations")
	case "create":
		operations, err := readOptionalOperatorFile(*operationsPath)
		if err != nil {
			return err
		}
		body := map[string]any{"name": *name}
		if strings.TrimSpace(operations) != "" {
			body["operations"] = json.RawMessage(operations)
		}
		return postJSON(*baseURL, *apiKey, "/v1/transformations", body)
	case "version":
		if strings.TrimSpace(*transformationID) == "" {
			return fmt.Errorf("transformation-id is required")
		}
		operations, err := readRequiredOperatorFile(*operationsPath, "operations-file")
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/transformations/"+url.PathEscape(*transformationID)+"/versions", map[string]any{"operations": json.RawMessage(operations)})
	case "activate":
		if strings.TrimSpace(*transformationID) == "" || strings.TrimSpace(*versionID) == "" {
			return fmt.Errorf("transformation-id and version-id are required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/transformations/"+url.PathEscape(*transformationID)+"/versions/"+url.PathEscape(*versionID)+":activate", map[string]string{"reason": *reason})
	case "dry-run":
		payload, err := readRequiredOperatorFile(*payloadPath, "payload-file")
		if err != nil {
			return err
		}
		operations, err := readRequiredOperatorFile(*operationsPath, "operations-file")
		if err != nil {
			return err
		}
		ops, err := transform.ParseOperations([]byte(operations))
		if err != nil {
			return err
		}
		out, err := transform.Apply([]byte(payload), ops)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(out, '\n'))
		return err
	default:
		return fmt.Errorf("usage: whcp transformations <list|create|version|activate|dry-run>")
	}
}

func runDeliveries(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp deliveries <list|attempts|retry|cancel>")
	}
	fs := flag.NewFlagSet("deliveries "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	deliveryID := fs.String("delivery-id", "", "delivery id")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/deliveries")
	case "attempts":
		return getJSON(*baseURL, *apiKey, "/v1/deliveries/"+url.PathEscape(*deliveryID)+"/attempts")
	case "retry":
		return postJSON(*baseURL, *apiKey, "/v1/deliveries/"+url.PathEscape(*deliveryID)+":retry", map[string]string{"reason": *reason})
	case "cancel":
		return postJSON(*baseURL, *apiKey, "/v1/deliveries/"+url.PathEscape(*deliveryID)+":cancel", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp deliveries <list|attempts|retry|cancel>")
	}
}

func runReplayJobs(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp replay-jobs <list|dry-run|create|approve|pause|resume|cancel>")
	}
	fs := flag.NewFlagSet("replay-jobs "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	replayJobID := fs.String("replay-job-id", "", "replay job id")
	eventID := fs.String("event-id", "", "event id")
	deliveryID := fs.String("delivery-id", "", "delivery id")
	endpointID := fs.String("endpoint-id", "", "endpoint id")
	reason := fs.String("reason", "", "operator reason")
	configMode := fs.String("config-mode", apppkg.ReplayConfigCurrent, "current or original")
	rateLimitPerMinute := fs.Int("rate-limit-per-minute", 0, "optional replay rate limit")
	requireApproval := fs.Bool("require-approval", false, "create job in pending approval state")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/replay-jobs")
	case "dry-run":
		return postJSON(*baseURL, *apiKey, "/v1/replay-jobs:dry-run", map[string]any{"event_id": *eventID, "delivery_id": *deliveryID, "endpoint_id": *endpointID, "reason": *reason, "config_mode": *configMode, "rate_limit_per_minute": *rateLimitPerMinute})
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/replay-jobs", map[string]any{"event_id": *eventID, "delivery_id": *deliveryID, "endpoint_id": *endpointID, "reason": *reason, "config_mode": *configMode, "rate_limit_per_minute": *rateLimitPerMinute, "require_approval": *requireApproval})
	case "approve":
		return postJSON(*baseURL, *apiKey, "/v1/replay-jobs/"+url.PathEscape(*replayJobID)+":approve", map[string]string{"reason": *reason})
	case "pause":
		return postJSON(*baseURL, *apiKey, "/v1/replay-jobs/"+url.PathEscape(*replayJobID)+":pause", map[string]string{"reason": *reason})
	case "resume":
		return postJSON(*baseURL, *apiKey, "/v1/replay-jobs/"+url.PathEscape(*replayJobID)+":resume", map[string]string{"reason": *reason})
	case "cancel":
		return postJSON(*baseURL, *apiKey, "/v1/replay-jobs/"+url.PathEscape(*replayJobID)+":cancel", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp replay-jobs <list|dry-run|create|approve|pause|resume|cancel>")
	}
}

func runReconciliationJobs(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp reconciliation-jobs <list|get|items|dry-run|create|cancel>")
	}
	fs := flag.NewFlagSet("reconciliation-jobs "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	jobID := fs.String("job-id", "", "reconciliation job id")
	connectionID := fs.String("connection-id", "", "provider connection id")
	scopeObjectID := fs.String("scope-object-id", "", "provider-specific object or event scope")
	fromRaw := fs.String("from", "", "RFC3339 lower bound")
	toRaw := fs.String("to", "", "RFC3339 upper bound")
	captureMissing := fs.Bool("capture-missing", false, "capture recoverable missing provider events")
	routeRecovered := fs.Bool("route-recovered", false, "route recovered events after durable capture")
	redeliverFailed := fs.Bool("redeliver-failed", false, "request provider redelivery for failed deliveries when supported")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/reconciliation-jobs")
	case "get":
		if strings.TrimSpace(*jobID) == "" {
			return fmt.Errorf("job-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/reconciliation-jobs/"+url.PathEscape(*jobID))
	case "items":
		if strings.TrimSpace(*jobID) == "" {
			return fmt.Errorf("job-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/reconciliation-jobs/"+url.PathEscape(*jobID)+"/items")
	case "dry-run", "create":
		from, err := parseOptionalTime(*fromRaw)
		if err != nil {
			return err
		}
		to, err := parseOptionalTime(*toRaw)
		if err != nil {
			return err
		}
		body := map[string]any{
			"connection_id":    *connectionID,
			"scope_object_id":  *scopeObjectID,
			"window_start":     nullableCLITime(from),
			"window_end":       nullableCLITime(to),
			"capture_missing":  *captureMissing,
			"route_recovered":  *routeRecovered,
			"redeliver_failed": *redeliverFailed,
			"reason":           *reason,
		}
		if args[0] == "dry-run" {
			return postJSON(*baseURL, *apiKey, "/v1/reconciliation-jobs:dry-run", body)
		}
		return postJSON(*baseURL, *apiKey, "/v1/reconciliation-jobs", body)
	case "cancel":
		if strings.TrimSpace(*jobID) == "" {
			return fmt.Errorf("job-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/reconciliation-jobs/"+url.PathEscape(*jobID)+":cancel", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp reconciliation-jobs <list|get|items|dry-run|create|cancel>")
	}
}

func runOps(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp ops <metrics|rollups|storage|config|endpoint-health|workers|worker|queues>")
	}
	fs := flag.NewFlagSet("ops "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	workerID := fs.String("worker-id", "", "worker id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "metrics":
		return getJSON(*baseURL, *apiKey, "/v1/ops/metrics")
	case "rollups":
		return getJSON(*baseURL, *apiKey, "/v1/ops/metrics/rollups")
	case "storage":
		return getJSON(*baseURL, *apiKey, "/v1/ops/storage")
	case "config":
		return getJSON(*baseURL, *apiKey, "/v1/ops/config")
	case "endpoint-health":
		return getJSON(*baseURL, *apiKey, "/v1/endpoint-health")
	case "workers":
		return getJSON(*baseURL, *apiKey, "/v1/ops/workers")
	case "worker":
		if strings.TrimSpace(*workerID) == "" {
			return fmt.Errorf("worker-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/ops/workers/"+url.PathEscape(*workerID))
	case "queues":
		return getJSON(*baseURL, *apiKey, "/v1/ops/queues")
	default:
		return fmt.Errorf("usage: whcp ops <metrics|rollups|storage|config|endpoint-health|workers|worker|queues>")
	}
}

func runAlerts(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp alerts <list|create|update|disable|firings|ack>")
	}
	fs := flag.NewFlagSet("alerts "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	alertID := fs.String("alert-id", "", "alert rule id")
	firingID := fs.String("firing-id", "", "alert firing id")
	name := fs.String("name", "", "alert name")
	ruleType := fs.String("rule-type", "", "alert rule type")
	metricName := fs.String("metric-name", "", "optional metric name override")
	threshold := fs.Float64("threshold", 0, "threshold")
	comparator := fs.String("comparator", ">=", "threshold comparator")
	windowSeconds := fs.Int("window-seconds", 300, "evaluation window seconds")
	state := fs.String("state", "", "state filter or rule state")
	channelIDs := fs.String("channel-ids", "", "comma-separated notification channel ids")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/alerts")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/alerts", map[string]any{
			"name":           *name,
			"rule_type":      *ruleType,
			"metric_name":    *metricName,
			"threshold":      *threshold,
			"comparator":     *comparator,
			"window_seconds": *windowSeconds,
			"state":          *state,
			"channel_ids":    splitCSV(*channelIDs),
		})
	case "update":
		if strings.TrimSpace(*alertID) == "" {
			return fmt.Errorf("alert-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if *threshold != 0 {
			body["threshold"] = *threshold
		}
		if strings.TrimSpace(*comparator) != "" {
			body["comparator"] = *comparator
		}
		if *windowSeconds != 0 {
			body["window_seconds"] = *windowSeconds
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		if strings.TrimSpace(*channelIDs) != "" {
			body["channel_ids"] = splitCSV(*channelIDs)
		}
		return patchJSON(*baseURL, *apiKey, "/v1/alerts/"+url.PathEscape(*alertID), body)
	case "disable":
		if strings.TrimSpace(*alertID) == "" {
			return fmt.Errorf("alert-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/alerts/"+url.PathEscape(*alertID), map[string]any{"reason": *reason})
	case "firings":
		path := "/v1/alert-firings"
		if strings.TrimSpace(*state) != "" {
			path += "?state=" + url.QueryEscape(*state)
		}
		return getJSON(*baseURL, *apiKey, path)
	case "ack":
		if strings.TrimSpace(*firingID) == "" {
			return fmt.Errorf("firing-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/alert-firings/"+url.PathEscape(*firingID)+":acknowledge", map[string]any{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp alerts <list|create|update|disable|firings|ack>")
	}
}

func runNotificationChannels(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp notification-channels <list|create|update|disable|test>")
	}
	fs := flag.NewFlagSet("notification-channels "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	channelID := fs.String("channel-id", "", "notification channel id")
	name := fs.String("name", "", "channel name")
	targetURL := fs.String("url", "", "HTTPS webhook receiver URL")
	secret := fs.String("signing-secret", "", "HMAC signing secret")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/notification-channels")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/notification-channels", map[string]any{
			"name":           *name,
			"channel_type":   domain.NotificationChannelWebhook,
			"url":            *targetURL,
			"signing_secret": *secret,
		})
	case "update":
		if strings.TrimSpace(*channelID) == "" {
			return fmt.Errorf("channel-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*targetURL) != "" {
			body["url"] = *targetURL
		}
		if strings.TrimSpace(*secret) != "" {
			body["signing_secret"] = *secret
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/notification-channels/"+url.PathEscape(*channelID), body)
	case "disable":
		if strings.TrimSpace(*channelID) == "" {
			return fmt.Errorf("channel-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/notification-channels/"+url.PathEscape(*channelID), map[string]any{"reason": *reason})
	case "test":
		if strings.TrimSpace(*channelID) == "" {
			return fmt.Errorf("channel-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/notification-channels/"+url.PathEscape(*channelID)+":test", map[string]any{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp notification-channels <list|create|update|disable|test>")
	}
}

func runNotificationDeliveries(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp notification-deliveries <list|attempts|retry>")
	}
	fs := flag.NewFlagSet("notification-deliveries "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	deliveryID := fs.String("delivery-id", "", "notification delivery id")
	state := fs.String("state", "", "delivery state filter")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		path := "/v1/notification-deliveries"
		if strings.TrimSpace(*state) != "" {
			path += "?state=" + url.QueryEscape(*state)
		}
		return getJSON(*baseURL, *apiKey, path)
	case "attempts":
		if strings.TrimSpace(*deliveryID) == "" {
			return fmt.Errorf("delivery-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/notification-deliveries/"+url.PathEscape(*deliveryID)+"/attempts")
	case "retry":
		if strings.TrimSpace(*deliveryID) == "" {
			return fmt.Errorf("delivery-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/notification-deliveries/"+url.PathEscape(*deliveryID)+":retry", map[string]any{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp notification-deliveries <list|attempts|retry>")
	}
}

func runSIEMSinks(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp siem-sinks <list|create|update|disable|test>")
	}
	fs := flag.NewFlagSet("siem-sinks "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	sinkID := fs.String("sink-id", "", "SIEM sink id")
	name := fs.String("name", "", "sink name")
	targetURL := fs.String("url", "", "HTTPS SIEM receiver URL")
	secret := fs.String("signing-secret", "", "HMAC signing secret")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/siem-sinks")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/siem-sinks", map[string]any{
			"name":           *name,
			"sink_type":      domain.SIEMSinkWebhook,
			"url":            *targetURL,
			"signing_secret": *secret,
		})
	case "update":
		if strings.TrimSpace(*sinkID) == "" {
			return fmt.Errorf("sink-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*targetURL) != "" {
			body["url"] = *targetURL
		}
		if strings.TrimSpace(*secret) != "" {
			body["signing_secret"] = *secret
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/siem-sinks/"+url.PathEscape(*sinkID), body)
	case "disable":
		if strings.TrimSpace(*sinkID) == "" {
			return fmt.Errorf("sink-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/siem-sinks/"+url.PathEscape(*sinkID), map[string]any{"reason": *reason})
	case "test":
		if strings.TrimSpace(*sinkID) == "" {
			return fmt.Errorf("sink-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/siem-sinks/"+url.PathEscape(*sinkID)+":test", map[string]any{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp siem-sinks <list|create|update|disable|test>")
	}
}

func runSIEMDeliveries(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp siem-deliveries <list|attempts|retry>")
	}
	fs := flag.NewFlagSet("siem-deliveries "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	deliveryID := fs.String("delivery-id", "", "SIEM delivery id")
	state := fs.String("state", "", "delivery state filter")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		path := "/v1/siem-deliveries"
		if strings.TrimSpace(*state) != "" {
			path += "?state=" + url.QueryEscape(*state)
		}
		return getJSON(*baseURL, *apiKey, path)
	case "attempts":
		if strings.TrimSpace(*deliveryID) == "" {
			return fmt.Errorf("delivery-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/siem-deliveries/"+url.PathEscape(*deliveryID)+"/attempts")
	case "retry":
		if strings.TrimSpace(*deliveryID) == "" {
			return fmt.Errorf("delivery-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/siem-deliveries/"+url.PathEscape(*deliveryID)+":retry", map[string]any{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp siem-deliveries <list|attempts|retry>")
	}
}

func runAudit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp audit <export|export-status|download|chain-head|verify-chain|anchor|anchors|verify-bundle>")
	}
	fs := flag.NewFlagSet("audit "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	exportID := fs.String("export-id", "", "audit export id")
	fromRaw := fs.String("from", "", "RFC3339 lower bound")
	toRaw := fs.String("to", "", "RFC3339 upper bound")
	includeRaw := fs.Bool("include-raw", false, "include raw payload bodies when authorized")
	includePayloads := fs.Bool("include-payloads", false, "include normalized and delivery payload bodies when authorized")
	includeTimelines := fs.Bool("include-timelines", false, "include event, receipt, delivery, and audit timelines")
	reason := fs.String("reason", "", "operator reason")
	output := fs.String("output", "", "download output path")
	filePath := fs.String("file", "", "local evidence bundle path")
	anchorID := fs.String("anchor-id", "", "audit chain anchor id")
	fromSequence := fs.Int64("from-sequence", 0, "optional audit chain start sequence")
	toSequence := fs.Int64("to-sequence", 0, "optional audit chain end sequence")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "export":
		from, err := parseOptionalTime(*fromRaw)
		if err != nil {
			return err
		}
		to, err := parseOptionalTime(*toRaw)
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/audit-events:export", map[string]any{
			"from":                   nullableCLITime(from),
			"to":                     nullableCLITime(to),
			"include_raw_payloads":   *includeRaw,
			"include_payload_bodies": *includePayloads,
			"include_timelines":      *includeTimelines,
			"reason":                 *reason,
		})
	case "export-status":
		if strings.TrimSpace(*exportID) == "" {
			return fmt.Errorf("export-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/audit-exports/"+url.PathEscape(*exportID))
	case "download":
		if strings.TrimSpace(*exportID) == "" {
			return fmt.Errorf("export-id is required")
		}
		return downloadAuditExport(*baseURL, *apiKey, *exportID, *output)
	case "chain-head":
		return getJSON(*baseURL, *apiKey, "/v1/audit-chain/head")
	case "verify-chain":
		return postJSON(*baseURL, *apiKey, "/v1/audit-chain:verify", map[string]any{"from_sequence": *fromSequence, "to_sequence": *toSequence})
	case "anchor":
		return postJSON(*baseURL, *apiKey, "/v1/audit-chain:anchor", map[string]any{"from_sequence": *fromSequence, "to_sequence": *toSequence, "reason": *reason})
	case "anchors":
		if strings.TrimSpace(*anchorID) != "" {
			return getJSON(*baseURL, *apiKey, "/v1/audit-chain/anchors/"+url.PathEscape(*anchorID))
		}
		return getJSON(*baseURL, *apiKey, "/v1/audit-chain/anchors")
	case "verify-bundle":
		return verifyEvidenceBundleFile(*filePath)
	default:
		return fmt.Errorf("usage: whcp audit <export|export-status|download|chain-head|verify-chain|anchor|anchors|verify-bundle>")
	}
}

func runRetention(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp retention <list|create|update>")
	}
	fs := flag.NewFlagSet("retention "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	policyID := fs.String("policy-id", "", "retention policy id")
	resourceType := fs.String("resource-type", domain.RetentionResourceRawPayload, "raw_payload, normalized_envelope_data, delivery_payload, or audit_event")
	sourceID := fs.String("source-id", "", "optional source id for raw payload retention")
	retentionDays := fs.Int("retention-days", 0, "retention period in days")
	state := fs.String("state", "", "active or disabled")
	legalHold := fs.Bool("legal-hold", false, "put policy on legal hold")
	clearLegalHold := fs.Bool("clear-legal-hold", false, "clear policy legal hold")
	holdReason := fs.String("hold-reason", "", "legal hold reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	visited := map[string]bool{}
	fs.Visit(func(flag *flag.Flag) {
		visited[flag.Name] = true
	})
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/admin/retention-policies")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/admin/retention-policies", map[string]any{
			"resource_type":  *resourceType,
			"source_id":      *sourceID,
			"retention_days": *retentionDays,
			"state":          *state,
			"legal_hold":     *legalHold,
			"hold_reason":    *holdReason,
		})
	case "update":
		if strings.TrimSpace(*policyID) == "" {
			return fmt.Errorf("policy-id is required")
		}
		body := map[string]any{}
		if *retentionDays > 0 {
			body["retention_days"] = *retentionDays
		}
		if *state != "" {
			body["state"] = *state
		}
		if *sourceID != "" {
			body["source_id"] = *sourceID
		}
		if visited["legal-hold"] {
			body["legal_hold"] = *legalHold
		}
		if *clearLegalHold {
			body["legal_hold"] = false
			body["hold_reason"] = ""
		}
		if *holdReason != "" {
			body["hold_reason"] = *holdReason
		}
		return patchJSON(*baseURL, *apiKey, "/v1/admin/retention-policies/"+url.PathEscape(*policyID), body)
	default:
		return fmt.Errorf("usage: whcp retention <list|create|update>")
	}
}

func runSchemas(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp schemas <event-type-create|event-type-list|event-type-get|event-type-update|event-type-delete|schema-create|schema-list|schema-get|schema-update|schema-delete|validate|check-compat>")
	}
	fs := flag.NewFlagSet("schemas "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	name := fs.String("name", "", "event type name")
	description := fs.String("description", "", "event type description")
	state := fs.String("state", "", "event type or schema state")
	reason := fs.String("reason", "", "operator reason")
	version := fs.String("version", "", "schema version")
	schemaPath := fs.String("schema-file", "", "JSON schema file")
	payloadPath := fs.String("payload-file", "", "JSON payload file")
	newSchemaPath := fs.String("new-schema-file", "", "candidate JSON schema file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "event-type-create":
		return postJSON(*baseURL, *apiKey, "/v1/event-types", map[string]string{"name": *name, "description": *description})
	case "event-type-list":
		return getJSON(*baseURL, *apiKey, "/v1/event-types")
	case "event-type-get":
		if strings.TrimSpace(*name) == "" {
			return fmt.Errorf("name is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name))
	case "event-type-update":
		if strings.TrimSpace(*name) == "" {
			return fmt.Errorf("name is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*description) != "" {
			body["description"] = *description
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name), body)
	case "event-type-delete":
		if strings.TrimSpace(*name) == "" {
			return fmt.Errorf("name is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name), map[string]string{"reason": *reason})
	case "schema-create":
		body, err := os.ReadFile(*schemaPath) // #nosec G304,G703 -- CLI reads an operator-selected schema file.
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas", map[string]string{"version": *version, "schema": string(body)})
	case "schema-list":
		if strings.TrimSpace(*name) == "" {
			return fmt.Errorf("name is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas")
	case "schema-get":
		if strings.TrimSpace(*name) == "" || strings.TrimSpace(*version) == "" {
			return fmt.Errorf("name and version are required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas/"+url.PathEscape(*version))
	case "schema-update":
		if strings.TrimSpace(*name) == "" || strings.TrimSpace(*version) == "" {
			return fmt.Errorf("name and version are required")
		}
		return patchJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas/"+url.PathEscape(*version), map[string]string{"state": *state, "reason": *reason})
	case "schema-delete":
		if strings.TrimSpace(*name) == "" || strings.TrimSpace(*version) == "" {
			return fmt.Errorf("name and version are required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas/"+url.PathEscape(*version), map[string]string{"reason": *reason})
	case "validate":
		body, err := os.ReadFile(*payloadPath) // #nosec G304,G703 -- CLI reads an operator-selected payload file.
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas/"+url.PathEscape(*version)+":validate", map[string]string{"payload": string(body)})
	case "check-compat":
		body, err := os.ReadFile(*newSchemaPath) // #nosec G304,G703 -- CLI reads an operator-selected schema file.
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas/"+url.PathEscape(*version)+":check-compatibility", map[string]string{"new_schema": string(body)})
	default:
		return fmt.Errorf("usage: whcp schemas <event-type-create|event-type-list|event-type-get|event-type-update|event-type-delete|schema-create|schema-list|schema-get|schema-update|schema-delete|validate|check-compat>")
	}
}

func runDeadLetter(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp dead-letter <list|release|bulk-release>")
	}
	fs := flag.NewFlagSet("dead-letter "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	entryID := fs.String("entry-id", "", "dead-letter entry id")
	entryIDs := fs.String("entry-ids", "", "comma-separated dead-letter entry ids")
	reason := fs.String("reason", "", "release reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/dead-letter")
	case "release":
		return postJSON(*baseURL, *apiKey, "/v1/dead-letter/"+url.PathEscape(*entryID)+":release", map[string]string{"reason": *reason})
	case "bulk-release":
		return postJSON(*baseURL, *apiKey, "/v1/dead-letter:bulk-release", map[string]any{"entry_ids": splitCSV(*entryIDs), "reason": *reason})
	default:
		return fmt.Errorf("usage: whcp dead-letter <list|release|bulk-release>")
	}
}

func runQuarantine(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp quarantine <approve|reject>")
	}
	fs := flag.NewFlagSet("quarantine "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	entryID := fs.String("entry-id", "", "quarantine entry id")
	reason := fs.String("reason", "", "decision reason")
	routeAfterRelease := fs.Bool("route-after-release", false, "create route work after approval")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "approve":
		return postJSON(*baseURL, *apiKey, "/v1/quarantine/"+url.PathEscape(*entryID)+":approve", map[string]any{"reason": *reason, "route_after_release": *routeAfterRelease})
	case "reject":
		return postJSON(*baseURL, *apiKey, "/v1/quarantine/"+url.PathEscape(*entryID)+":reject", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp quarantine <approve|reject>")
	}
}

func runAdapters(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp adapters <list|get|create|versions|version-create|vector-create|transition>")
	}
	fs := flag.NewFlagSet("adapters "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	adapterID := fs.String("adapter-id", "", "adapter id")
	versionID := fs.String("version-id", "", "adapter version id")
	name := fs.String("name", "", "adapter name")
	kind := fs.String("kind", domain.AdapterKindDeclarative, "adapter kind")
	version := fs.String("version", "", "adapter version")
	definitionPath := fs.String("definition-file", "", "declarative adapter definition JSON file")
	requestPath := fs.String("request-file", "", "adapter test-vector request JSON file")
	expectedPath := fs.String("expected-file", "", "adapter test-vector expected JSON file")
	action := fs.String("action", "", "transition action")
	reason := fs.String("reason", "", "audit reason")
	riskLevel := fs.String("risk-level", "", "risk level")
	packageSHA := fs.String("package-sha256", "", "plugin package sha256")
	packageSignature := fs.String("package-signature", "", "plugin package signature")
	sbomSHA := fs.String("sbom-sha256", "", "plugin SBOM sha256")
	provenanceURL := fs.String("provenance-url", "", "provenance URL")
	description := fs.String("description", "", "description")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/adapters")
	case "get":
		return getJSON(*baseURL, *apiKey, "/v1/adapters/"+url.PathEscape(*adapterID))
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/adapters", map[string]any{"name": *name, "kind": *kind, "description": *description, "risk_level": *riskLevel, "provenance_url": *provenanceURL})
	case "versions":
		return getJSON(*baseURL, *apiKey, "/v1/adapters/"+url.PathEscape(*adapterID)+"/versions")
	case "version-create":
		definition, err := readOptionalOperatorFile(*definitionPath)
		if err != nil {
			return err
		}
		body := map[string]any{"version": *version, "reason": *reason, "risk_level": *riskLevel, "package_sha256": *packageSHA, "package_signature": *packageSignature, "sbom_sha256": *sbomSHA, "provenance_url": *provenanceURL}
		if definition != "" {
			body["definition"] = json.RawMessage(definition)
		}
		return postJSON(*baseURL, *apiKey, "/v1/adapters/"+url.PathEscape(*adapterID)+"/versions", body)
	case "vector-create":
		requestBody, err := readRequiredOperatorFile(*requestPath, "request-file")
		if err != nil {
			return err
		}
		expectedBody, err := readRequiredOperatorFile(*expectedPath, "expected-file")
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/adapters/"+url.PathEscape(*adapterID)+"/versions/"+url.PathEscape(*versionID)+"/test-vectors", map[string]any{"name": *name, "request": json.RawMessage(requestBody), "expected": json.RawMessage(expectedBody)})
	case "transition":
		return postJSON(*baseURL, *apiKey, "/v1/adapters/"+url.PathEscape(*adapterID)+"/versions/"+url.PathEscape(*versionID)+":transition", map[string]string{"action": *action, "reason": *reason})
	default:
		return fmt.Errorf("usage: whcp adapters <list|get|create|versions|version-create|vector-create|transition>")
	}
}

func runSignatures(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("usage: whcp signatures verify --provider PROVIDER --secret SECRET --body FILE --header 'Name: value'")
	}
	fs := flag.NewFlagSet("signatures verify", flag.ContinueOnError)
	providerName := fs.String("provider", "", "provider")
	secret := fs.String("secret", "", "secret")
	bodyPath := fs.String("body", "", "body file")
	header := fs.String("header", "", "header as 'Name: value'")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	body, err := os.ReadFile(*bodyPath)
	if err != nil {
		return err
	}
	name, value, ok := strings.Cut(*header, ":")
	if !ok {
		return fmt.Errorf("header must be formatted as 'Name: value'")
	}
	adapter, ok := provider.BuiltInRegistry().Adapter(*providerName)
	if !ok {
		return fmt.Errorf("unknown provider %q", *providerName)
	}
	result := adapter.Verify(provider.VerifyInput{
		RawBody: body,
		Headers: map[string][]string{strings.ToLower(strings.TrimSpace(name)): {strings.TrimSpace(value)}},
		Secret:  []byte(*secret),
		Now:     time.Now().UTC(),
	})
	out := json.NewEncoder(os.Stdout)
	out.SetIndent("", "  ")
	return out.Encode(result)
}

func openStore(ctx context.Context, cfg config.Config) (*postgres.Store, error) {
	box, err := secretBoxFromConfig(cfg)
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

func secretBoxFromConfig(cfg config.Config) (postgres.SecretBox, error) {
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
		awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(cfg.AWSRegion))
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

type deliveryAdapter struct {
	client deliveryhttp.Client
}

func (d deliveryAdapter) Deliver(ctx context.Context, rawURL string, body []byte, secret []byte, keyID string, keyVersion int, mtlsCertPEM, mtlsKeyPEM []byte) (worker.DeliveryResult, error) {
	client := d.client
	client.Secret = secret
	client.SigningKeyID = keyID
	client.SigningKeyVersion = keyVersion
	client.MTLSClientCertPEM = mtlsCertPEM
	client.MTLSClientKeyPEM = mtlsKeyPEM
	result, err := client.Deliver(ctx, rawURL, body)
	return worker.DeliveryResult{
		StatusCode:        result.StatusCode,
		ResponseBody:      result.ResponseBody,
		ResponseTruncated: result.ResponseTruncated,
		FailureClass:      result.FailureClass,
	}, err
}

type signalAdapter struct {
	client signalhttp.Client
}

func (s signalAdapter) Deliver(ctx context.Context, rawURL string, body []byte, secret []byte) (worker.SignalDeliveryResult, error) {
	result, err := s.client.Deliver(ctx, rawURL, body, secret)
	return worker.SignalDeliveryResult{
		StatusCode:        result.StatusCode,
		ResponseBody:      result.ResponseBody,
		ResponseTruncated: result.ResponseTruncated,
		FailureClass:      result.FailureClass,
	}, err
}

func getJSON(baseURL, apiKey, path string) error {
	endpoint, err := apiEndpoint(baseURL, path)
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	// #nosec G704 -- operator-supplied CLI API URL; not reachable from untrusted remote input.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func postJSON(baseURL, apiKey, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint, err := apiEndpoint(baseURL, path)
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	// #nosec G704 -- operator-supplied CLI API URL; not reachable from untrusted remote input.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func patchJSON(baseURL, apiKey, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint, err := apiEndpoint(baseURL, path)
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequest(http.MethodPatch, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	// #nosec G704 -- operator-supplied CLI API URL; not reachable from untrusted remote input.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func deleteJSON(baseURL, apiKey, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint, err := apiEndpoint(baseURL, path)
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequest(http.MethodDelete, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	// #nosec G704 -- operator-supplied CLI API URL; not reachable from untrusted remote input.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func downloadAuditExport(baseURL, apiKey, exportID, outputPath string) error {
	endpoint, err := apiEndpoint(baseURL, "/v1/audit-exports/"+url.PathEscape(exportID)+":download")
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	// #nosec G704 -- operator-supplied CLI API URL; not reachable from untrusted remote input.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("audit export download failed with status %d", resp.StatusCode)
	}
	if outputPath == "" {
		outputPath = exportID + ".tar.gz"
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return writePrivateFile(outputPath, body)
}

func verifyEvidenceBundleFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("file is required")
	}
	body, err := os.ReadFile(path) // #nosec G304,G703 -- CLI verifies an operator-selected local evidence bundle.
	if err != nil {
		return err
	}
	result, err := evidence.VerifyTarGzipBundle(body)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func exportRawPayload(baseURL, apiKey, eventID, outputPath string) error {
	if strings.TrimSpace(eventID) == "" {
		return fmt.Errorf("event-id is required")
	}
	endpoint, err := apiEndpoint(baseURL, "/v1/events/"+url.PathEscape(eventID)+"/raw")
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	// #nosec G704 -- operator-supplied CLI API URL; not reachable from untrusted remote input.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var payload struct {
		BodyBase64 string `json:"body_base64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("raw export failed with status %d", resp.StatusCode)
	}
	raw, err := base64.StdEncoding.DecodeString(payload.BodyBase64)
	if err != nil {
		return err
	}
	if outputPath == "" || outputPath == "-" {
		_, err = os.Stdout.Write(raw)
		return err
	}
	return writePrivateFile(outputPath, raw)
}

func readRequiredOperatorFile(path, flagName string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%s is required", flagName)
	}
	body, err := os.ReadFile(path) // #nosec G304,G703 -- CLI reads an operator-selected local file.
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func readOptionalOperatorFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	return readRequiredOperatorFile(path, "file")
}

func writePrivateFile(outputPath string, body []byte) error {
	if strings.TrimSpace(outputPath) == "" || outputPath == "-" {
		return fmt.Errorf("output path is required")
	}
	if info, err := os.Lstat(outputPath); err == nil { // #nosec G304,G703 -- CLI checks an operator-selected path before writing.
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink: %s", outputPath)
		}
	}
	return os.WriteFile(outputPath, body, 0o600) // #nosec G304,G306,G703 -- CLI writes operator-selected export files with private permissions.
}

func apiEndpoint(baseURL, path string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("base-url must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("base-url must include a host and must not include credentials")
	}
	return parsed.String() + path, nil
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func valueOrDefault(value, fallback int) int {
	if value < 0 {
		return fallback
	}
	return value
}

func valueOrDefaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func parseKeyValueCSV(value string) map[string]string {
	out := map[string]string{}
	for _, part := range splitCSV(value) {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(val)
	}
	return out
}

func parseOptionalTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("time must be RFC3339: %w", err)
	}
	return parsed.UTC(), nil
}

func nullableCLITime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
