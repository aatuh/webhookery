package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"webhookery/internal/domain"
)

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

func runDeadLetter(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp dead-letter <list|release|bulk-release>")
	}
	fs := flag.NewFlagSet("dead-letter "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	entryID := fs.String("entry-id", "", "dead-letter entry id")
	entryIDs := fs.String("entry-ids", "", "comma-separated dead-letter entry ids")
	reasonCode := fs.String("reason-code", "", "structured replay reason code")
	reason := fs.String("reason", "", "release reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/dead-letter")
	case "release":
		if strings.TrimSpace(*reasonCode) == "" {
			return fmt.Errorf("reason-code is required")
		}
		if strings.TrimSpace(*reason) == "" {
			return fmt.Errorf("reason is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/dead-letter/"+url.PathEscape(*entryID)+":release", map[string]string{"reason_code": *reasonCode, "reason": *reason})
	case "bulk-release":
		if strings.TrimSpace(*reasonCode) == "" {
			return fmt.Errorf("reason-code is required")
		}
		if strings.TrimSpace(*reason) == "" {
			return fmt.Errorf("reason is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/dead-letter:bulk-release", map[string]any{"entry_ids": splitCSV(*entryIDs), "reason_code": *reasonCode, "reason": *reason})
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
