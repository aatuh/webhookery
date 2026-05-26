package signalhttp

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
	HTTP *http.Client
	SSRF ssrf.Validator
	Now  func() time.Time
}

type Result struct {
	StatusCode        int
	ResponseBody      []byte
	ResponseTruncated bool
	FailureClass      string
}

var errUnsafeCustomTransport = errors.New("custom HTTP transport cannot enforce pinned egress")

func HTTPClient(timeout time.Duration, resolvers ...ssrf.Resolver) *http.Client {
	var resolver ssrf.Resolver
	if len(resolvers) > 0 {
		resolver = resolvers[0]
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: ssrf.NewPinnedTransport(nil, resolver, ssrf.DefaultPolicy()),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c Client) BuildRequest(ctx context.Context, rawURL string, body []byte, secret []byte) (*http.Request, error) {
	result := c.SSRF.Validate(ctx, rawURL, ssrf.DefaultPolicy())
	if !result.Allowed {
		return nil, fmt.Errorf("signal URL blocked: %v", result.BlockedReasons)
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	timestamp := fmt.Sprint(now.Unix())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, result.NormalizedURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	signingPayload := []byte(timestamp + "." + string(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Webhookery/0.1")
	req.Header.Set("Webhookery-Signal-Timestamp", timestamp)
	req.Header.Set("Webhookery-Signal-Signature", "t="+timestamp+",v1="+verifier.SignHMACSHA256Hex(secret, signingPayload))
	return req, nil
}

func (c Client) Deliver(ctx context.Context, rawURL string, body []byte, secret []byte) (Result, error) {
	req, err := c.BuildRequest(ctx, rawURL, body, secret)
	if err != nil {
		return Result{FailureClass: "policy_blocked"}, err
	}
	httpClient, err := c.httpClient()
	if err != nil {
		return Result{FailureClass: "client_configuration_error"}, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		failureClass, safeErr := safeDoError(err)
		return Result{FailureClass: failureClass}, safeErr
	}
	defer func() { _ = resp.Body.Close() }()
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

func (c Client) httpClient() (*http.Client, error) {
	if c.HTTP == nil {
		return HTTPClient(10*time.Second, c.SSRF.Resolver), nil
	}
	copy := *c.HTTP
	if copy.CheckRedirect == nil {
		copy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	switch transport := copy.Transport.(type) {
	case nil:
		copy.Transport = ssrf.NewPinnedTransport(nil, c.SSRF.Resolver, ssrf.DefaultPolicy())
	case *http.Transport:
		copy.Transport = ssrf.NewPinnedTransport(transport, c.SSRF.Resolver, ssrf.DefaultPolicy())
	default:
		return nil, errUnsafeCustomTransport
	}
	return &copy, nil
}

func safeDoError(err error) (string, error) {
	var policyErr ssrf.PolicyError
	if errors.As(err, &policyErr) {
		return "policy_blocked", policyErr
	}
	return "network_error", errors.New("signal network error")
}

func readTruncated(body io.Reader, max int64) ([]byte, error) {
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
