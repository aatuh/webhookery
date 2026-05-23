package deliveryhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"webhookery/internal/ssrf"
	"webhookery/pkg/verifier"
)

type Client struct {
	HTTP              *http.Client
	SSRF              ssrf.Validator
	Secret            []byte
	SigningKeyID      string
	SigningKeyVersion int
	Now               func() time.Time
}

type Result struct {
	StatusCode        int
	ResponseBody      []byte
	ResponseTruncated bool
	FailureClass      string
}

func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c Client) BuildRequest(rawURL string, body []byte) (*http.Request, error) {
	validator := c.SSRF
	result := validator.Validate(context.Background(), rawURL, ssrf.DefaultPolicy())
	if !result.Allowed {
		return nil, fmt.Errorf("endpoint URL blocked: %v", result.BlockedReasons)
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	req, err := http.NewRequest(http.MethodPost, result.NormalizedURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	timestamp := fmt.Sprint(now.Unix())
	signingPayload := []byte(timestamp + "." + string(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Webhookery/0.1")
	req.Header.Set("Webhook-Timestamp", timestamp)
	req.Header.Set("Webhook-Signature", "t="+timestamp+",v1="+verifier.SignHMACSHA256Hex(c.Secret, signingPayload))
	if c.SigningKeyID != "" {
		req.Header.Set("Webhook-Signature-Key-Id", c.SigningKeyID)
	}
	if c.SigningKeyVersion > 0 {
		req.Header.Set("Webhook-Signature-Key-Version", fmt.Sprint(c.SigningKeyVersion))
	}
	return req, nil
}

func (c Client) Deliver(ctx context.Context, rawURL string, body []byte) (Result, error) {
	req, err := c.BuildRequest(rawURL, body)
	if err != nil {
		return Result{FailureClass: "policy_blocked"}, err
	}
	req = req.WithContext(ctx)
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = HTTPClient(10 * time.Second)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{FailureClass: "network_error"}, err
	}
	bodyBytes, err := readTruncated(resp.Body, 16<<10)
	if err != nil {
		return Result{StatusCode: resp.StatusCode, FailureClass: "response_read_error"}, err
	}
	return Result{
		StatusCode:        resp.StatusCode,
		ResponseBody:      bodyBytes,
		ResponseTruncated: len(bodyBytes) == 16<<10,
		FailureClass:      classify(resp.StatusCode),
	}, nil
}

func readTruncated(body io.ReadCloser, max int64) ([]byte, error) {
	defer func() { _ = body.Close() }()
	return io.ReadAll(io.LimitReader(body, max))
}

func classify(status int) string {
	switch {
	case status >= 200 && status <= 299:
		return "success"
	case status == 408 || status == 409 || status == 425 || status == 429:
		return "temporary_http"
	case status >= 500 && status <= 599:
		return "temporary_http"
	case status >= 300 && status <= 399:
		return "redirect_blocked"
	default:
		return "permanent_http"
	}
}

func repeatingReader(s string, n int) io.Reader {
	if n <= 0 {
		return bytes.NewReader(nil)
	}
	buf := bytes.Repeat([]byte(s), n)
	return bytes.NewReader(buf)
}

var ErrRedirectBlocked = errors.New("redirects disabled")
