package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	apppkg "webhookery/internal/app"
)

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
