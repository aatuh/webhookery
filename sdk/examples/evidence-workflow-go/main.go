package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"webhookery/pkg/client"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	baseURL, err := requiredEnv("WEBHOOKERY_BASE_URL")
	if err != nil {
		return err
	}
	apiKey, err := requiredEnv("WEBHOOKERY_API_KEY")
	if err != nil {
		return err
	}
	sourceID, err := requiredEnv("WEBHOOKERY_SOURCE_ID")
	if err != nil {
		return err
	}
	output := strings.TrimSpace(os.Getenv("WEBHOOKERY_EVIDENCE_OUTPUT"))
	if output == "" {
		output = "evidence-workflow.tar.gz"
	}

	sdkClient, err := client.New(baseURL, apiKey)
	if err != nil {
		return err
	}
	rest := restClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 30 * time.Second},
	}

	eventID := "evt_sdk_evidence_" + time.Now().UTC().Format("20060102T150405Z")
	ingest, err := sdkClient.CreateEvent(ctx, client.ProductEvent{
		ID:       eventID,
		Type:     "sdk.evidence.demo",
		SourceID: sourceID,
		Data: map[string]any{
			"sanitized": true,
		},
	}, client.WithIdempotencyKey(eventID))
	if err != nil {
		return err
	}
	if strings.TrimSpace(ingest.EventID) != "" {
		eventID = ingest.EventID
	}

	var incident struct {
		ID string `json:"id"`
	}
	if err := rest.doJSON(ctx, http.MethodPost, "/v1/incidents", map[string]string{
		"title":  "SDK evidence workflow",
		"reason": "local SDK evidence example",
	}, &incident); err != nil {
		return err
	}
	if incident.ID == "" {
		return errors.New("incident response did not include id")
	}

	if err := rest.doJSON(ctx, http.MethodPost, "/v1/incidents/"+url.PathEscape(incident.ID)+"/events", map[string]string{
		"event_id": eventID,
		"reason":   "attach SDK-created event to evidence workflow",
	}, nil); err != nil {
		return err
	}
	if err := rest.doJSON(ctx, http.MethodPost, "/v1/incidents/"+url.PathEscape(incident.ID)+"/generate-report", map[string]string{
		"reason": "generate SDK example report",
	}, nil); err != nil {
		return err
	}

	var export struct {
		ID string `json:"id"`
	}
	if err := rest.doJSON(ctx, http.MethodPost, "/v1/incidents/"+url.PathEscape(incident.ID)+"/evidence-export", map[string]string{
		"reason": "create SDK example evidence export",
	}, &export); err != nil {
		return err
	}
	if export.ID == "" {
		return errors.New("evidence export response did not include id")
	}
	if err := rest.download(ctx, "/v1/audit-exports/"+url.PathEscape(export.ID)+":download", output); err != nil {
		return err
	}

	verification, err := sdkClient.VerifyAuditChain(ctx, client.AuditChainVerifyRequest{})
	if err != nil {
		return err
	}
	if !verification.Valid {
		return errors.New("audit chain did not verify after evidence workflow")
	}

	fmt.Printf("wrote evidence bundle to %s\n", output)
	return nil
}

type restClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func (c restClient) doJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint(c.baseURL, path), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return problemError(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c restClient) download(ctx context.Context, path, output string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint(c.baseURL, path), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return problemError(resp)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil && filepath.Dir(output) != "." {
		return err
	}
	return os.WriteFile(output, body, 0o600)
}

func endpoint(baseURL, path string) string {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		panic(err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		panic("WEBHOOKERY_BASE_URL must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil {
		panic("WEBHOOKERY_BASE_URL must include a host and no credentials")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + path
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func problemError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var p struct {
		Code       string `json:"code"`
		StableCode string `json:"stable_code"`
		RequestID  string `json:"request_id"`
	}
	_ = json.Unmarshal(raw, &p)
	code := strings.TrimSpace(p.StableCode)
	if code == "" {
		code = strings.TrimSpace(p.Code)
	}
	if code == "" {
		code = "unknown_error"
	}
	if p.RequestID != "" {
		return fmt.Errorf("webhookery API returned HTTP %d (%s, request_id=%s)", resp.StatusCode, code, p.RequestID)
	}
	return fmt.Errorf("webhookery API returned HTTP %d (%s)", resp.StatusCode, code)
}

func requiredEnv(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}
