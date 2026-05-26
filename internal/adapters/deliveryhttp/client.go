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

func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
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
		return Result{FailureClass: "client_certificate_error"}, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{FailureClass: "network_error"}, err
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
	if len(c.MTLSClientCertPEM) == 0 && len(c.MTLSClientKeyPEM) == 0 {
		if c.HTTP != nil {
			return c.HTTP, nil
		}
		return HTTPClient(10 * time.Second), nil
	}
	if len(c.MTLSClientCertPEM) == 0 || len(c.MTLSClientKeyPEM) == 0 {
		return nil, errors.New("mTLS client certificate and key are required together")
	}
	cert, err := tls.X509KeyPair(c.MTLSClientCertPEM, c.MTLSClientKeyPEM)
	if err != nil {
		return nil, err
	}
	base := HTTPClient(10 * time.Second)
	if c.HTTP != nil {
		copy := *c.HTTP
		base = &copy
		if base.CheckRedirect == nil {
			base.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if base.Transport != nil {
		if typed, ok := base.Transport.(*http.Transport); ok {
			transport = typed.Clone()
		}
	}
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
