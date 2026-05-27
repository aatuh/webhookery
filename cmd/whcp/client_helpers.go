package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"webhookery/internal/evidence"
)

func getJSON(baseURL, apiKey, path string) error {
	endpoint, err := apiEndpoint(baseURL, path)
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
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
	return writeHTTPResponse(resp)
}

func getJSONDecode(baseURL, apiKey, path string, dst any) error {
	endpoint, err := apiEndpoint(baseURL, path)
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
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
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return problemResponseError("request failed", resp.StatusCode, responseBody)
	}
	return json.Unmarshal(responseBody, dst)
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
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(raw))
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
	return writeHTTPResponse(resp)
}

func postJSONDecode(baseURL, apiKey, path string, body, dst any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint, err := apiEndpoint(baseURL, path)
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(raw))
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
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return problemResponseError("request failed", resp.StatusCode, responseBody)
	}
	return json.Unmarshal(responseBody, dst)
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
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPatch, endpoint, bytes.NewReader(raw))
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
	return writeHTTPResponse(resp)
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
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, endpoint, bytes.NewReader(raw))
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
	return writeHTTPResponse(resp)
}

func downloadAuditExport(baseURL, apiKey, exportID, outputPath string) error {
	endpoint, err := apiEndpoint(baseURL, "/v1/audit-exports/"+url.PathEscape(exportID)+":download")
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
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
	if outputPath == "" {
		outputPath = exportID + ".tar.gz"
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return problemResponseError("audit export download failed", resp.StatusCode, body)
	}
	return writePrivateFile(outputPath, body)
}

func downloadIncidentReport(baseURL, apiKey, incidentID, format, outputPath string) error {
	if strings.TrimSpace(incidentID) == "" {
		return fmt.Errorf("incident-id is required")
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "markdown"
	}
	if format != "markdown" && format != "json" {
		return fmt.Errorf("format must be markdown or json")
	}
	endpoint, err := apiEndpoint(baseURL, "/v1/incidents/"+url.PathEscape(incidentID)+"/report?format="+url.QueryEscape(format))
	if err != nil {
		return err
	}
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return problemResponseError("incident report download failed", resp.StatusCode, body)
	}
	if outputPath == "" || outputPath == "-" {
		_, err = os.Stdout.Write(body)
		return err
	}
	return writePrivateFile(outputPath, body)
}

func writeHTTPResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := os.Stdout.Write(body); err != nil {
			return err
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return problemResponseError("request failed", resp.StatusCode, body)
	}
	return nil
}

func problemResponseError(prefix string, status int, body []byte) error {
	var p struct {
		Code       string `json:"code"`
		StableCode string `json:"stable_code"`
		RequestID  string `json:"request_id"`
	}
	_ = json.Unmarshal(body, &p)
	code := strings.TrimSpace(p.StableCode)
	if code == "" {
		code = strings.TrimSpace(p.Code)
	}
	if code == "" {
		code = "unknown_error"
	}
	if requestID := strings.TrimSpace(p.RequestID); requestID != "" {
		return fmt.Errorf("%s with status %d (%s, request_id=%s)", prefix, status, code, requestID)
	}
	return fmt.Errorf("%s with status %d (%s)", prefix, status, code)
}

func createAndDownloadIncidentExport(baseURL, apiKey, incidentID, reason, outputPath string) error {
	var export struct {
		ID string `json:"id"`
	}
	if err := postJSONDecode(baseURL, apiKey, "/v1/incidents/"+url.PathEscape(incidentID)+"/evidence-export", map[string]string{"reason": reason}, &export); err != nil {
		return err
	}
	if strings.TrimSpace(export.ID) == "" {
		return fmt.Errorf("incident evidence export response did not include id")
	}
	return downloadAuditExport(baseURL, apiKey, export.ID, outputPath)
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

func exportRawPayload(baseURL, apiKey, eventID, reason, outputPath string) error {
	if strings.TrimSpace(eventID) == "" {
		return fmt.Errorf("event-id is required")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("reason is required")
	}
	endpoint, err := apiEndpoint(baseURL, "/v1/events/"+url.PathEscape(eventID)+"/raw")
	if err != nil {
		return err
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	query := parsedEndpoint.Query()
	query.Set("reason", reason)
	parsedEndpoint.RawQuery = query.Encode()
	endpoint = parsedEndpoint.String()
	// #nosec G107,G704 -- CLI connects only to the operator-supplied Webhookery API URL after scheme/host validation.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
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
