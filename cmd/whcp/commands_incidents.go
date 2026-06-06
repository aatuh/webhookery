package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func runIncidents(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp incidents <list|get|create|add-event|remove-event|generate-report|report|export>")
	}
	fs := flag.NewFlagSet("incidents "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	incidentID := fs.String("incident-id", "", "incident id")
	eventID := fs.String("event-id", "", "event id")
	title := fs.String("title", "", "incident title")
	reason := fs.String("reason", "", "operator reason")
	format := fs.String("format", "markdown", "report format: markdown or json")
	output := fs.String("output", "-", "output path, or '-' for stdout")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/incidents")
	case "get":
		if strings.TrimSpace(*incidentID) == "" {
			return fmt.Errorf("incident-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/incidents/"+url.PathEscape(*incidentID))
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/incidents", map[string]string{"title": *title, "reason": *reason})
	case "add-event":
		if strings.TrimSpace(*incidentID) == "" || strings.TrimSpace(*eventID) == "" {
			return fmt.Errorf("incident-id and event-id are required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/incidents/"+url.PathEscape(*incidentID)+"/events", map[string]string{"event_id": *eventID, "reason": *reason})
	case "remove-event":
		if strings.TrimSpace(*incidentID) == "" || strings.TrimSpace(*eventID) == "" {
			return fmt.Errorf("incident-id and event-id are required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/incidents/"+url.PathEscape(*incidentID)+"/events/"+url.PathEscape(*eventID), map[string]string{"reason": *reason})
	case "generate-report":
		if strings.TrimSpace(*incidentID) == "" {
			return fmt.Errorf("incident-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/incidents/"+url.PathEscape(*incidentID)+"/generate-report", map[string]string{"reason": *reason})
	case "report":
		return downloadIncidentReport(*baseURL, *apiKey, *incidentID, *format, *output)
	case "export":
		if strings.TrimSpace(*incidentID) == "" {
			return fmt.Errorf("incident-id is required")
		}
		if strings.TrimSpace(*output) == "" || *output == "-" {
			return postJSON(*baseURL, *apiKey, "/v1/incidents/"+url.PathEscape(*incidentID)+"/evidence-export", map[string]string{"reason": *reason})
		}
		return createAndDownloadIncidentExport(*baseURL, *apiKey, *incidentID, *reason, *output)
	default:
		return fmt.Errorf("usage: whcp incidents <list|get|create|add-event|remove-event|generate-report|report|export>")
	}
}
