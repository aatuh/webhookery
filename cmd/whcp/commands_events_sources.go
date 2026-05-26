package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

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
