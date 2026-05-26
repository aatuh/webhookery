package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"webhookery/internal/domain"
	"webhookery/internal/transform"
)

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
