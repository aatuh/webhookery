package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxErrorBodyBytes = 4096

type Client struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
}

type Option func(*Client)

func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

func New(baseURL, apiKey string, opts ...Option) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("base URL must use http or https")
	}
	if parsed.Host == "" {
		return nil, errors.New("base URL must include a host")
	}
	c := &Client{
		baseURL: parsed,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

type ProductEvent struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	SourceID string `json:"source_id"`
	Source   string `json:"source,omitempty"`
	Subject  string `json:"subject,omitempty"`
	Data     any    `json:"data,omitempty"`
	Metadata any    `json:"metadata,omitempty"`
}

type IngestResult struct {
	Accepted     bool   `json:"Accepted"`
	EventID      string `json:"EventID"`
	ReceiptID    string `json:"ReceiptID"`
	RawPayloadID string `json:"RawPayloadID"`
	TraceID      string `json:"TraceID"`
	VerifyReason string `json:"VerifyReason"`
	DedupeStatus string `json:"DedupeStatus"`
}

type AuditChainHead struct {
	TenantID           string    `json:"tenant_id"`
	Sequence           int64     `json:"sequence"`
	ChainHash          string    `json:"chain_hash"`
	LastAuditEventID   string    `json:"last_audit_event_id,omitempty"`
	UnchainedEvents    int64     `json:"unchained_events"`
	LastAnchoredAt     time.Time `json:"last_anchored_at,omitempty"`
	LastAnchorID       string    `json:"last_anchor_id,omitempty"`
	LastAnchorSequence int64     `json:"last_anchor_sequence,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
}

type AuditChainVerifyRequest struct {
	FromSequence int64 `json:"from_sequence,omitempty"`
	ToSequence   int64 `json:"to_sequence,omitempty"`
}

type AuditChainVerification struct {
	TenantID        string              `json:"tenant_id"`
	Valid           bool                `json:"valid"`
	FromSequence    int64               `json:"from_sequence"`
	ToSequence      int64               `json:"to_sequence"`
	CheckedEntries  int                 `json:"checked_entries"`
	RetainedEntries int                 `json:"retained_entries"`
	StartChainHash  string              `json:"start_chain_hash,omitempty"`
	EndChainHash    string              `json:"end_chain_hash,omitempty"`
	Failures        []AuditChainFailure `json:"failures"`
	VerifiedAt      time.Time           `json:"verified_at"`
}

type AuditChainFailure struct {
	Sequence     int64  `json:"sequence"`
	AuditEventID string `json:"audit_event_id,omitempty"`
	Kind         string `json:"kind"`
	Detail       string `json:"detail,omitempty"`
}

type RequestOption func(*http.Request)

func WithIdempotencyKey(key string) RequestOption {
	return func(req *http.Request) {
		if strings.TrimSpace(key) != "" {
			req.Header.Set("Idempotency-Key", key)
		}
	}
}

func (c *Client) CreateEvent(ctx context.Context, event ProductEvent, opts ...RequestOption) (IngestResult, error) {
	var out IngestResult
	if strings.TrimSpace(event.SourceID) == "" {
		return out, errors.New("source_id is required")
	}
	if strings.TrimSpace(event.ID) == "" {
		return out, errors.New("event id is required")
	}
	if strings.TrimSpace(event.Type) == "" {
		return out, errors.New("event type is required")
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/events", event, &out, opts...); err != nil {
		return IngestResult{}, err
	}
	return out, nil
}

func (c *Client) AuditChainHead(ctx context.Context) (AuditChainHead, error) {
	var out AuditChainHead
	if err := c.doJSON(ctx, http.MethodGet, "/v1/audit-chain/head", nil, &out); err != nil {
		return AuditChainHead{}, err
	}
	return out, nil
}

func (c *Client) VerifyAuditChain(ctx context.Context, req AuditChainVerifyRequest) (AuditChainVerification, error) {
	var out AuditChainVerification
	if err := c.doJSON(ctx, http.MethodPost, "/v1/audit-chain:verify", req, &out); err != nil {
		return AuditChainVerification{}, err
	}
	return out, nil
}

type HTTPError struct {
	StatusCode int
	Body       string
}

func (e HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("webhookery API returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("webhookery API returned HTTP %d: %s", e.StatusCode, e.Body)
}

func (c *Client) doJSON(ctx context.Context, method, path string, in, out any, opts ...RequestOption) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	for _, opt := range opts {
		opt(req)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return HTTPError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) endpoint(path string) string {
	next := *c.baseURL
	next.Path = strings.TrimRight(next.Path, "/") + path
	return next.String()
}
