package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	ErrorRetryable    = "retryable"
	ErrorRateLimited  = "rate_limited"
	ErrorForbidden    = "forbidden"
	ErrorNotFound     = "not_found"
	ErrorUnsupported  = "unsupported"
	ErrorInvalidInput = "invalid_input"

	ProviderStripe  = "stripe"
	ProviderGitHub  = "github"
	ProviderShopify = "shopify"
	ProviderSlack   = "slack"
)

var (
	ErrUnsupported  = errors.New("unsupported provider reconciliation capability")
	ErrInvalidInput = errors.New("invalid reconciliation input")
)

type ProviderError struct {
	Class      string
	StatusCode int
	Message    string
	RetryAfter time.Duration
}

func (e ProviderError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Class
}

type Capabilities struct {
	Provider             string   `json:"provider"`
	CanScanEvents        bool     `json:"can_scan_events"`
	CanLookupObject      bool     `json:"can_lookup_object"`
	CanCaptureMissing    bool     `json:"can_capture_missing"`
	CanRequestRedelivery bool     `json:"can_request_redelivery"`
	RecoveryWindowDays   int      `json:"recovery_window_days,omitempty"`
	RequiredConfig       []string `json:"required_config,omitempty"`
	Limitations          []string `json:"limitations,omitempty"`
}

type Connection struct {
	ID             string
	Provider       string
	CredentialType string
	Credential     string
	Config         map[string]string
}

type ScanRequest struct {
	Connection      Connection
	WindowStart     time.Time
	WindowEnd       time.Time
	ScopeObjectID   string
	Cursor          string
	CaptureMissing  bool
	RedeliverFailed bool
}

type ProviderObject struct {
	ID             string
	ObjectType     string
	EventType      string
	CreatedAt      time.Time
	StatusCode     int
	Failed         bool
	Recoverable    bool
	Redeliverable  bool
	RawBody        []byte
	RequestHeaders map[string]string
	Metadata       map[string]any
}

type Evidence struct {
	Method     string
	URL        string
	StatusCode int
	Body       []byte
	Error      string
}

type ScanResult struct {
	Objects     []ProviderObject
	Evidence    []Evidence
	NextCursor  string
	Unsupported bool
	Limitations []string
}

type Adapter interface {
	Name() string
	Capabilities(config map[string]string) Capabilities
	ValidateConnection(ctx context.Context, conn Connection) error
	Scan(ctx context.Context, req ScanRequest) (ScanResult, error)
	Lookup(ctx context.Context, conn Connection, objectID string) (ProviderObject, []Evidence, error)
	RequestRedelivery(ctx context.Context, conn Connection, objectID string) ([]Evidence, error)
}

type Registry struct {
	adapters map[string]Adapter
}

func BuiltInRegistry(client *http.Client) Registry {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return Registry{adapters: map[string]Adapter{
		ProviderStripe:  StripeAdapter{Client: client},
		ProviderGitHub:  GitHubAdapter{Client: client},
		ProviderShopify: UnsupportedAdapter{Provider: ProviderShopify, Cap: ShopifyCapabilities()},
		ProviderSlack:   UnsupportedAdapter{Provider: ProviderSlack, Cap: SlackCapabilities()},
	}}
}

func (r Registry) Adapter(provider string) (Adapter, bool) {
	adapter, ok := r.adapters[strings.ToLower(strings.TrimSpace(provider))]
	return adapter, ok
}

func ClassifyHTTPError(status int, body []byte) ProviderError {
	class := ErrorRetryable
	switch {
	case status == http.StatusTooManyRequests:
		class = ErrorRateLimited
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		class = ErrorForbidden
	case status == http.StatusNotFound:
		class = ErrorNotFound
	case status >= 400 && status < 500:
		class = ErrorInvalidInput
	}
	return ProviderError{Class: class, StatusCode: status, Message: safeErrorMessage(body)}
}

func RedactCredential(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "****"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

func safeErrorMessage(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if len(body) > 256 {
		body = body[:256]
	}
	msg := string(body)
	for _, prefix := range []string{"sk_", "ghp_", "github_pat_", "xoxb-", "shpat_"} {
		if strings.Contains(msg, prefix) {
			return "provider request failed"
		}
	}
	return strings.TrimSpace(msg)
}

func bearerHeader(conn Connection) string {
	token := strings.TrimSpace(conn.Credential)
	if token == "" {
		return ""
	}
	return "Bearer " + token
}

func configValue(config map[string]string, key, fallback string) string {
	if config == nil {
		return fallback
	}
	if value := strings.TrimSpace(config[key]); value != "" {
		return value
	}
	return fallback
}

func providerBaseURL(config map[string]string, fallback string, allowedHosts map[string]bool) (string, error) {
	raw := configValue(config, "base_url", fallback)
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", ProviderError{Class: ErrorInvalidInput, Message: "invalid provider base_url"}
	}
	host := strings.ToLower(parsed.Hostname())
	if configValue(config, "allow_test_base_url", "false") == "true" {
		if (host == "localhost" || host == "127.0.0.1" || host == "::1") && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.User == nil {
			return strings.TrimRight(parsed.String(), "/"), nil
		}
		return "", ProviderError{Class: ErrorInvalidInput, Message: "test provider base_url must be localhost"}
	}
	if parsed.Scheme != "https" || parsed.User != nil || !allowedHosts[host] {
		return "", ProviderError{Class: ErrorInvalidInput, Message: "provider base_url must use an official HTTPS provider API host"}
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func requiredConfig(config map[string]string, names ...string) error {
	var missing []string
	for _, name := range names {
		if strings.TrimSpace(config[name]) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return ProviderError{Class: ErrorInvalidInput, Message: "missing provider connection config: " + strings.Join(missing, ", ")}
	}
	return nil
}

func decodeJSON(body []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	return dec.Decode(dst)
}

func doProviderRequest(ctx context.Context, client *http.Client, req *http.Request, token string) (Evidence, error) {
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	resp, err := client.Do(req) // #nosec G704 -- req URLs are built from providerBaseURL allowlists or explicit localhost-only test overrides.
	if err != nil {
		return Evidence{Method: req.Method, URL: req.URL.String(), Error: "provider request failed"}, ProviderError{Class: ErrorRetryable, Message: "provider request failed"}
	}
	defer func() { _ = resp.Body.Close() }()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	evidence := Evidence{Method: req.Method, URL: req.URL.String(), StatusCode: resp.StatusCode, Body: body}
	if readErr != nil {
		evidence.Error = "provider response read failed"
		return evidence, ProviderError{Class: ErrorRetryable, StatusCode: resp.StatusCode, Message: "provider response read failed"}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return evidence, ClassifyHTTPError(resp.StatusCode, body)
	}
	return evidence, nil
}

type StripeAdapter struct {
	Client *http.Client
}

func (StripeAdapter) Name() string { return ProviderStripe }

func (StripeAdapter) Capabilities(map[string]string) Capabilities {
	return Capabilities{
		Provider:           ProviderStripe,
		CanScanEvents:      true,
		CanLookupObject:    true,
		CanCaptureMissing:  true,
		RecoveryWindowDays: 30,
		RequiredConfig:     []string{"source_id"},
		Limitations:        []string{"Stripe Events API list/retrieve access is limited to events from the past 30 days."},
	}
}

func (a StripeAdapter) ValidateConnection(ctx context.Context, conn Connection) error {
	_, _, err := a.stripeGET(ctx, conn, "/v1/events", url.Values{"limit": {"1"}})
	return err
}

func (a StripeAdapter) Scan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	if err := enforceStripeWindow(req.WindowStart, req.WindowEnd); err != nil {
		return ScanResult{}, err
	}
	values := url.Values{"limit": {"100"}}
	if !req.WindowStart.IsZero() {
		values.Set("created[gte]", strconv.FormatInt(req.WindowStart.Unix(), 10))
	}
	if !req.WindowEnd.IsZero() {
		values.Set("created[lte]", strconv.FormatInt(req.WindowEnd.Unix(), 10))
	}
	if req.Cursor != "" {
		values.Set("starting_after", req.Cursor)
	}
	if req.ScopeObjectID != "" {
		values.Set("type", req.ScopeObjectID)
	}
	body, evidence, err := a.stripeGET(ctx, req.Connection, "/v1/events", values)
	if err != nil {
		return ScanResult{Evidence: []Evidence{evidence}}, err
	}
	var parsed struct {
		Data    []json.RawMessage `json:"data"`
		HasMore bool              `json:"has_more"`
	}
	if err := decodeJSON(body, &parsed); err != nil {
		return ScanResult{Evidence: []Evidence{evidence}}, ProviderError{Class: ErrorRetryable, Message: "decode stripe events response"}
	}
	out := ScanResult{Evidence: []Evidence{evidence}}
	for _, raw := range parsed.Data {
		var item map[string]any
		if err := decodeJSON(raw, &item); err != nil {
			continue
		}
		id, _ := item["id"].(string)
		eventType, _ := item["type"].(string)
		created := unixTime(item["created"])
		out.Objects = append(out.Objects, ProviderObject{
			ID:          id,
			ObjectType:  "event",
			EventType:   eventType,
			CreatedAt:   created,
			Recoverable: true,
			RawBody:     append([]byte(nil), raw...),
			Metadata:    map[string]any{"provider": ProviderStripe, "event_type": eventType},
		})
		out.NextCursor = id
	}
	if !parsed.HasMore {
		out.NextCursor = ""
	}
	return out, nil
}

func (a StripeAdapter) Lookup(ctx context.Context, conn Connection, objectID string) (ProviderObject, []Evidence, error) {
	body, evidence, err := a.stripeGET(ctx, conn, "/v1/events/"+url.PathEscape(objectID), nil)
	if err != nil {
		return ProviderObject{}, []Evidence{evidence}, err
	}
	var item map[string]any
	if err := decodeJSON(body, &item); err != nil {
		return ProviderObject{}, []Evidence{evidence}, ProviderError{Class: ErrorRetryable, Message: "decode stripe event response"}
	}
	eventType, _ := item["type"].(string)
	return ProviderObject{
		ID:          objectID,
		ObjectType:  "event",
		EventType:   eventType,
		CreatedAt:   unixTime(item["created"]),
		Recoverable: true,
		RawBody:     body,
		Metadata:    map[string]any{"provider": ProviderStripe, "event_type": eventType},
	}, []Evidence{evidence}, nil
}

func (a StripeAdapter) RequestRedelivery(context.Context, Connection, string) ([]Evidence, error) {
	return nil, ErrUnsupported
}

func (a StripeAdapter) stripeGET(ctx context.Context, conn Connection, path string, values url.Values) ([]byte, Evidence, error) {
	base, err := providerBaseURL(conn.Config, "https://api.stripe.com", map[string]bool{"api.stripe.com": true})
	if err != nil {
		return nil, Evidence{}, err
	}
	rawURL := base + path
	if len(values) > 0 {
		rawURL += "?" + values.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, Evidence{}, err
	}
	req.Header.Set("Stripe-Version", configValue(conn.Config, "stripe_version", ""))
	evidence, err := doProviderRequest(ctx, a.Client, req, bearerHeader(conn))
	return evidence.Body, evidence, err
}

func enforceStripeWindow(start, end time.Time) error {
	now := time.Now().UTC()
	if !start.IsZero() && start.Before(now.AddDate(0, 0, -30)) {
		return ProviderError{Class: ErrorInvalidInput, Message: "stripe event reconciliation cannot scan events older than 30 days"}
	}
	if !end.IsZero() && end.Before(now.AddDate(0, 0, -30)) {
		return ProviderError{Class: ErrorInvalidInput, Message: "stripe event reconciliation cannot scan events older than 30 days"}
	}
	return nil
}

type GitHubAdapter struct {
	Client *http.Client
}

func (GitHubAdapter) Name() string { return ProviderGitHub }

func (GitHubAdapter) Capabilities(map[string]string) Capabilities {
	return Capabilities{
		Provider:             ProviderGitHub,
		CanScanEvents:        true,
		CanLookupObject:      true,
		CanCaptureMissing:    true,
		CanRequestRedelivery: true,
		RecoveryWindowDays:   3,
		RequiredConfig:       []string{"owner", "repo", "hook_id", "source_id"},
		Limitations:          []string{"GitHub recent webhook delivery details are available for the recent delivery window exposed by GitHub."},
	}
}

func (a GitHubAdapter) ValidateConnection(ctx context.Context, conn Connection) error {
	if err := requiredConfig(conn.Config, "owner", "repo", "hook_id"); err != nil {
		return err
	}
	_, _, err := a.githubGET(ctx, conn, deliveriesPath(conn), url.Values{"per_page": {"1"}})
	return err
}

func (a GitHubAdapter) Scan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	if err := requiredConfig(req.Connection.Config, "owner", "repo", "hook_id"); err != nil {
		return ScanResult{}, err
	}
	values := url.Values{"per_page": {"100"}}
	if req.Cursor != "" {
		values.Set("cursor", req.Cursor)
	}
	if req.RedeliverFailed {
		values.Set("status", "failure")
	}
	body, evidence, err := a.githubGET(ctx, req.Connection, deliveriesPath(req.Connection), values)
	if err != nil {
		return ScanResult{Evidence: []Evidence{evidence}}, err
	}
	var parsed []map[string]any
	if err := decodeJSON(body, &parsed); err != nil {
		return ScanResult{Evidence: []Evidence{evidence}}, ProviderError{Class: ErrorRetryable, Message: "decode github deliveries response"}
	}
	out := ScanResult{Evidence: []Evidence{evidence}}
	for _, item := range parsed {
		id := fmt.Sprint(item["id"])
		guid, _ := item["guid"].(string)
		if guid == "" {
			guid = id
		}
		status := intFromAny(item["status_code"])
		eventType, _ := item["event"].(string)
		out.Objects = append(out.Objects, ProviderObject{
			ID:            guid,
			ObjectType:    "delivery",
			EventType:     eventType,
			StatusCode:    status,
			Failed:        status >= 400,
			Recoverable:   true,
			Redeliverable: status >= 400,
			Metadata:      map[string]any{"provider": ProviderGitHub, "delivery_id": id, "guid": guid, "status_code": status},
		})
		out.NextCursor = id
	}
	return out, nil
}

func (a GitHubAdapter) Lookup(ctx context.Context, conn Connection, objectID string) (ProviderObject, []Evidence, error) {
	path := deliveriesPath(conn) + "/" + url.PathEscape(objectID)
	body, evidence, err := a.githubGET(ctx, conn, path, nil)
	if err != nil {
		return ProviderObject{}, []Evidence{evidence}, err
	}
	var detail map[string]any
	if err := decodeJSON(body, &detail); err != nil {
		return ProviderObject{}, []Evidence{evidence}, ProviderError{Class: ErrorRetryable, Message: "decode github delivery response"}
	}
	guid, _ := detail["guid"].(string)
	if guid == "" {
		guid = objectID
	}
	eventType, _ := detail["event"].(string)
	status := intFromAny(detail["status_code"])
	rawPayload := githubPayloadBytes(detail)
	headers := githubHeaders(detail)
	return ProviderObject{
		ID:             guid,
		ObjectType:     "delivery",
		EventType:      eventType,
		StatusCode:     status,
		Failed:         status >= 400,
		Recoverable:    len(rawPayload) > 0,
		Redeliverable:  status >= 400,
		RawBody:        rawPayload,
		RequestHeaders: headers,
		Metadata:       map[string]any{"provider": ProviderGitHub, "delivery_id": objectID, "guid": guid, "status_code": status},
	}, []Evidence{evidence}, nil
}

func (a GitHubAdapter) RequestRedelivery(ctx context.Context, conn Connection, objectID string) ([]Evidence, error) {
	if err := requiredConfig(conn.Config, "owner", "repo", "hook_id"); err != nil {
		return nil, err
	}
	path := deliveriesPath(conn) + "/" + url.PathEscape(objectID) + "/attempts"
	base, err := providerBaseURL(conn.Config, "https://api.github.com", map[string]bool{"api.github.com": true})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", configValue(conn.Config, "api_version", "2026-03-10"))
	evidence, err := doProviderRequest(ctx, a.Client, req, bearerHeader(conn))
	return []Evidence{evidence}, err
}

func (a GitHubAdapter) githubGET(ctx context.Context, conn Connection, path string, values url.Values) ([]byte, Evidence, error) {
	base, err := providerBaseURL(conn.Config, "https://api.github.com", map[string]bool{"api.github.com": true})
	if err != nil {
		return nil, Evidence{}, err
	}
	rawURL := base + path
	if len(values) > 0 {
		rawURL += "?" + values.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, Evidence{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", configValue(conn.Config, "api_version", "2026-03-10"))
	evidence, err := doProviderRequest(ctx, a.Client, req, bearerHeader(conn))
	return evidence.Body, evidence, err
}

func deliveriesPath(conn Connection) string {
	return "/repos/" + url.PathEscape(conn.Config["owner"]) + "/" + url.PathEscape(conn.Config["repo"]) + "/hooks/" + url.PathEscape(conn.Config["hook_id"]) + "/deliveries"
}

func githubPayloadBytes(detail map[string]any) []byte {
	req, _ := detail["request"].(map[string]any)
	payload, ok := req["payload"]
	if !ok {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return body
}

func githubHeaders(detail map[string]any) map[string]string {
	req, _ := detail["request"].(map[string]any)
	rawHeaders, _ := req["headers"].(map[string]any)
	headers := map[string]string{}
	for key, value := range rawHeaders {
		if strings.EqualFold(key, "authorization") || strings.EqualFold(key, "x-hub-signature") || strings.EqualFold(key, "x-hub-signature-256") {
			continue
		}
		headers[key] = fmt.Sprint(value)
	}
	return headers
}

type UnsupportedAdapter struct {
	Provider string
	Cap      Capabilities
}

func (a UnsupportedAdapter) Name() string { return a.Provider }

func (a UnsupportedAdapter) Capabilities(map[string]string) Capabilities { return a.Cap }

func (a UnsupportedAdapter) ValidateConnection(context.Context, Connection) error { return nil }

func (a UnsupportedAdapter) Scan(context.Context, ScanRequest) (ScanResult, error) {
	return ScanResult{Unsupported: true, Limitations: a.Cap.Limitations}, nil
}

func (a UnsupportedAdapter) Lookup(context.Context, Connection, string) (ProviderObject, []Evidence, error) {
	return ProviderObject{}, nil, ErrUnsupported
}

func (a UnsupportedAdapter) RequestRedelivery(context.Context, Connection, string) ([]Evidence, error) {
	return nil, ErrUnsupported
}

func ShopifyCapabilities() Capabilities {
	return Capabilities{
		Provider:           ProviderShopify,
		CanScanEvents:      false,
		CanLookupObject:    false,
		CanCaptureMissing:  false,
		RecoveryWindowDays: 0,
		Limitations: []string{
			"Shopify recommends app-specific reconciliation by polling relevant resources with updated_at filters.",
			"Webhookery cannot generically recover all missed Shopify webhook payloads without topic-specific resource configuration.",
		},
	}
}

func SlackCapabilities() Capabilities {
	return Capabilities{
		Provider: ProviderSlack,
		Limitations: []string{
			"Slack Events API delivery is best-effort with bounded retries.",
			"Webhookery does not claim generic missed Slack event recovery without a configured Slack Web API sync for a specific event family.",
		},
	}
}

func unixTime(value any) time.Time {
	switch v := value.(type) {
	case json.Number:
		n, _ := v.Int64()
		return time.Unix(n, 0).UTC()
	case float64:
		return time.Unix(int64(v), 0).UTC()
	case int64:
		return time.Unix(v, 0).UTC()
	default:
		return time.Time{}
	}
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	default:
		return 0
	}
}
