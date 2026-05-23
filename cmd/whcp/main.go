package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
	apppkg "webhookery/internal/app"
	"webhookery/internal/authz"
	"webhookery/internal/config"
	"webhookery/internal/domain"
	"webhookery/internal/evidence"
	"webhookery/internal/provider"
	"webhookery/internal/ssrf"
	"webhookery/internal/transform"
	"webhookery/internal/worker"
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
	case "events":
		return runEvents(args[1:])
	case "sources":
		return runSources(args[1:])
	case "provider-connections":
		return runProviderConnections(args[1:])
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
	return fmt.Errorf("usage: whcp <api|worker|scheduler|migrate|admin|api-keys|events|sources|provider-connections|endpoints|subscriptions|retry-policies|routes|transformations|deliveries|replay-jobs|reconciliation-jobs|ops|audit|retention|schemas|dead-letter|quarantine|signatures>")
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
		Control:  apppkg.NewControlService(store, ssrf.Validator{}),
		Ingest:   apppkg.NewIngestService(store, apppkg.SystemClock{}),
		Auth:     runtimeAuth(cfg, store),
		OpenAPI:  openAPI,
		EnableUI: cfg.EnableUI,
		Health:   store.Health,
	})
	httpServer := &http.Server{Addr: cfg.HTTPAddr, Handler: server.Routes(), ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting api", "addr", cfg.HTTPAddr)
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
		Store:          store,
		Processor:      store,
		DeliveryStore:  store,
		DeliveryClient: deliveryAdapter{client: deliveryhttp.Client{SSRF: ssrf.Validator{}}},
		RetentionStore: store,
		WorkerID:       "worker-" + time.Now().UTC().Format("20060102150405"),
		Limit:          10,
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
		return fmt.Errorf("usage: whcp sources <create|rotate-secret>")
	}
	fs := flag.NewFlagSet("sources "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	name := fs.String("name", "", "source name")
	providerName := fs.String("provider", "", "provider")
	secret := fs.String("secret", "", "verification secret")
	sourceID := fs.String("source-id", "", "source id")
	graceHours := fs.Int("grace-hours", 72, "old secret grace period in hours")
	reason := fs.String("reason", "", "rotation reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "create":
		body := map[string]string{"name": *name, "provider": *providerName, "verification_secret": *secret}
		return postJSON(*baseURL, *apiKey, "/v1/sources", body)
	case "rotate-secret":
		if strings.TrimSpace(*sourceID) == "" {
			return fmt.Errorf("source-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/sources/"+url.PathEscape(*sourceID)+"/secrets:rotate", map[string]any{"new_secret": *secret, "grace_period_hours": *graceHours, "reason": *reason})
	default:
		return fmt.Errorf("usage: whcp sources <create|rotate-secret>")
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
		return fmt.Errorf("usage: whcp endpoints <validate-url|create|test|rotate-secret>")
	}
	fs := flag.NewFlagSet("endpoints "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	rawURL := fs.String("url", "", "endpoint URL")
	name := fs.String("name", "", "endpoint name")
	endpointID := fs.String("endpoint-id", "", "endpoint id")
	reason := fs.String("reason", "", "operator reason")
	retryPolicyID := fs.String("retry-policy-id", "", "retry policy id")
	graceHours := fs.Int("grace-hours", 72, "old signing secret grace period in hours")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "validate-url":
		return postJSON(*baseURL, *apiKey, "/v1/endpoints:validate-url", map[string]string{"url": *rawURL})
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/endpoints", map[string]string{"name": *name, "url": *rawURL, "retry_policy_id": *retryPolicyID})
	case "test":
		return postJSON(*baseURL, *apiKey, "/v1/endpoints/"+url.PathEscape(*endpointID)+":test", map[string]string{"reason": *reason})
	case "rotate-secret":
		return postJSON(*baseURL, *apiKey, "/v1/endpoints/"+url.PathEscape(*endpointID)+"/secrets:rotate", map[string]any{"grace_period_hours": *graceHours, "reason": *reason})
	default:
		return fmt.Errorf("usage: whcp endpoints <validate-url|create|test|rotate-secret>")
	}
}

func runSubscriptions(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return fmt.Errorf("usage: whcp subscriptions create --base-url URL --api-key KEY --endpoint-id ID --event-types type[,type]")
	}
	fs := flag.NewFlagSet("subscriptions create", flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	endpointID := fs.String("endpoint-id", "", "endpoint id")
	eventTypes := fs.String("event-types", "", "comma-separated event types")
	transformationID := fs.String("transformation-id", "", "optional transformation id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	return postJSON(*baseURL, *apiKey, "/v1/subscriptions", map[string]any{
		"endpoint_id":       *endpointID,
		"event_types":       splitCSV(*eventTypes),
		"transformation_id": *transformationID,
	})
}

func runRetryPolicies(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp retry-policies <list|create>")
	}
	fs := flag.NewFlagSet("retry-policies "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	name := fs.String("name", "", "retry policy name")
	maxAttempts := fs.Int("max-attempts", 12, "maximum attempts")
	maxDurationSeconds := fs.Int("max-duration-seconds", int((72*time.Hour)/time.Second), "maximum retry duration in seconds")
	initialDelaySeconds := fs.Int("initial-delay-seconds", 10, "initial retry delay in seconds")
	maxDelaySeconds := fs.Int("max-delay-seconds", int((6*time.Hour)/time.Second), "maximum retry delay in seconds")
	rateLimitPerMinute := fs.Int("rate-limit-per-minute", 0, "optional replay/delivery rate hint")
	state := fs.String("state", "active", "active or disabled")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/retry-policies")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/retry-policies", map[string]any{
			"name":                  *name,
			"max_attempts":          *maxAttempts,
			"max_duration_seconds":  *maxDurationSeconds,
			"initial_delay_seconds": *initialDelaySeconds,
			"max_delay_seconds":     *maxDelaySeconds,
			"rate_limit_per_minute": *rateLimitPerMinute,
			"state":                 *state,
		})
	default:
		return fmt.Errorf("usage: whcp retry-policies <list|create>")
	}
}

func runRoutes(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp routes <create|activate|dry-run|versions>")
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
	retryPolicyID := fs.String("retry-policy-id", "", "retry policy id")
	transformationID := fs.String("transformation-id", "", "optional transformation id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/routes", map[string]any{"name": *name, "source_id": *sourceID, "endpoint_id": *endpointID, "event_types": splitCSV(*eventTypes), "retry_policy_id": *retryPolicyID, "transformation_id": *transformationID})
	case "activate":
		return postJSON(*baseURL, *apiKey, "/v1/routes/"+*routeID+":activate", map[string]string{"reason": *reason})
	case "dry-run":
		return postJSON(*baseURL, *apiKey, "/v1/routes/"+*routeID+":dry-run", map[string]string{"event_id": *eventID})
	case "versions":
		return getJSON(*baseURL, *apiKey, "/v1/routes/"+url.PathEscape(*routeID)+"/versions")
	default:
		return fmt.Errorf("usage: whcp routes <create|activate|dry-run|versions>")
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
		return fmt.Errorf("usage: whcp ops <metrics|endpoint-health>")
	}
	fs := flag.NewFlagSet("ops "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "metrics":
		return getJSON(*baseURL, *apiKey, "/v1/ops/metrics")
	case "endpoint-health":
		return getJSON(*baseURL, *apiKey, "/v1/endpoint-health")
	default:
		return fmt.Errorf("usage: whcp ops <metrics|endpoint-health>")
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
		return fmt.Errorf("usage: whcp schemas <event-type-create|schema-create|validate|check-compat>")
	}
	fs := flag.NewFlagSet("schemas "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	name := fs.String("name", "", "event type name")
	description := fs.String("description", "", "event type description")
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
	case "schema-create":
		body, err := os.ReadFile(*schemaPath) // #nosec G304,G703 -- CLI reads an operator-selected schema file.
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas", map[string]string{"version": *version, "schema": string(body)})
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
		return fmt.Errorf("usage: whcp schemas <event-type-create|schema-create|validate|check-compat>")
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
	box, err := crypto.NewEnvelope(cfg.MasterKeyBase64)
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

type deliveryAdapter struct {
	client deliveryhttp.Client
}

func (d deliveryAdapter) Deliver(ctx context.Context, rawURL string, body []byte, secret []byte, keyID string, keyVersion int) (worker.DeliveryResult, error) {
	client := d.client
	client.Secret = secret
	client.SigningKeyID = keyID
	client.SigningKeyVersion = keyVersion
	result, err := client.Deliver(ctx, rawURL, body)
	return worker.DeliveryResult{
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
