package deliveryhttp

import (
	"bytes"
	"context"
	"crypto/tls"
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
	MTLSClientCertPEM []byte
	MTLSClientKeyPEM  []byte
	Now               func() time.Time
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

func (c Client) BuildRequest(ctx context.Context, rawURL string, body []byte) (*http.Request, error) {
	validator := c.SSRF
	result := validator.Validate(ctx, rawURL, ssrf.DefaultPolicy())
	if !result.Allowed {
		return nil, fmt.Errorf("endpoint URL blocked: %v", result.BlockedReasons)
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, result.NormalizedURL, bytes.NewReader(body))
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
	req, err := c.BuildRequest(ctx, rawURL, body)
	if err != nil {
		return Result{FailureClass: "policy_blocked"}, err
	}
	httpClient, err := c.httpClient()
	if err != nil {
		failureClass := "client_certificate_error"
		if errors.Is(err, errUnsafeCustomTransport) {
			failureClass = "client_configuration_error"
		}
		return Result{FailureClass: failureClass}, err
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
	base, err := safeHTTPClient(c.HTTP, 10*time.Second, c.SSRF.Resolver)
	if err != nil {
		return nil, err
	}
	if len(c.MTLSClientCertPEM) == 0 && len(c.MTLSClientKeyPEM) == 0 {
		return base, nil
	}
	if len(c.MTLSClientCertPEM) == 0 || len(c.MTLSClientKeyPEM) == 0 {
		return nil, errors.New("mTLS client certificate and key are required together")
	}
	cert, err := tls.X509KeyPair(c.MTLSClientCertPEM, c.MTLSClientKeyPEM)
	if err != nil {
		return nil, err
	}
	transport, ok := base.Transport.(*http.Transport)
	if !ok {
		return nil, errUnsafeCustomTransport
	}
	transport = ssrf.NewPinnedTransport(transport, c.SSRF.Resolver, ssrf.DefaultPolicy())
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.TLSClientConfig != nil {
		tlsConfig = transport.TLSClientConfig.Clone()
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	tlsConfig.Certificates = append([]tls.Certificate{cert}, tlsConfig.Certificates...)
	transport.TLSClientConfig = tlsConfig
	base.Transport = transport
	return base, nil
}

func safeHTTPClient(base *http.Client, timeout time.Duration, resolver ssrf.Resolver) (*http.Client, error) {
	if base == nil {
		return HTTPClient(timeout, resolver), nil
	}
	copy := *base
	copy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	switch transport := copy.Transport.(type) {
	case nil:
		copy.Transport = ssrf.NewPinnedTransport(nil, resolver, ssrf.DefaultPolicy())
	case *http.Transport:
		copy.Transport = ssrf.NewPinnedTransport(transport, resolver, ssrf.DefaultPolicy())
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
	return "network_error", errors.New("delivery network error")
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

func repeatingReader(s string, n int) io.Reader {
	if n <= 0 {
		return bytes.NewReader(nil)
	}
	buf := bytes.Repeat([]byte(s), n)
	return bytes.NewReader(buf)
}

var ErrRedirectBlocked = errors.New("redirects disabled")
