package provider

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"webhookery/pkg/verifier"
)

type Adapter interface {
	Name() string
	Verify(input VerifyInput) VerifyResult
}

type VerifyInput struct {
	RawBody []byte
	Headers map[string][]string
	Secret  []byte
	Now     time.Time
}

type VerifyResult struct {
	Verified  bool
	Reason    string
	Provider  string
	Timestamp time.Time
}

type Registry struct {
	adapters map[string]Adapter
}

func BuiltInRegistry() Registry {
	return Registry{adapters: map[string]Adapter{
		"stripe":         StripeAdapter{},
		"github":         GitHubAdapter{},
		"shopify":        ShopifyAdapter{},
		"slack":          SlackAdapter{},
		"generic-hmac":   GenericHMACAdapter{},
		"cloudevents":    CloudEventsAdapter{},
		"internal":       InternalTrustedAdapter{},
		"generic-unsafe": UnsafeAdapter{},
	}}
}

func (r Registry) Adapter(name string) (Adapter, bool) {
	a, ok := r.adapters[strings.ToLower(name)]
	return a, ok
}

type StripeAdapter struct{}

func (StripeAdapter) Name() string { return "stripe" }

func (StripeAdapter) Verify(input VerifyInput) VerifyResult {
	header := firstHeader(input.Headers, "stripe-signature")
	if header == "" {
		return result("stripe", false, verifier.ReasonMissingSignature)
	}
	res := verifier.VerifyTimestampedHMAC(verifier.VerifyTimestampedHMACInput{
		Secret:          input.Secret,
		RawBody:         input.RawBody,
		Header:          header,
		Now:             input.Now,
		Tolerance:       5 * time.Minute,
		ExpectedVersion: "v1",
		Encoding:        verifier.EncodingHex,
	})
	return VerifyResult{Verified: res.Valid, Reason: res.Reason, Provider: "stripe", Timestamp: res.Timestamp}
}

type GitHubAdapter struct{}

func (GitHubAdapter) Name() string { return "github" }

func (GitHubAdapter) Verify(input VerifyInput) VerifyResult {
	header := firstHeader(input.Headers, "x-hub-signature-256")
	if header == "" {
		return result("github", false, verifier.ReasonMissingSignature)
	}
	signature, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return result("github", false, verifier.ReasonMalformedHeader)
	}
	if !verifier.VerifyHMACSHA256Hex(input.Secret, input.RawBody, signature) {
		return result("github", false, verifier.ReasonInvalidSignature)
	}
	return result("github", true, verifier.ReasonOK)
}

type ShopifyAdapter struct{}

func (ShopifyAdapter) Name() string { return "shopify" }

func (ShopifyAdapter) Verify(input VerifyInput) VerifyResult {
	header := firstHeader(input.Headers, "x-shopify-hmac-sha256")
	if header == "" {
		return result("shopify", false, verifier.ReasonMissingSignature)
	}
	if !verifier.VerifyHMACSHA256Base64(input.Secret, input.RawBody, header) {
		return result("shopify", false, verifier.ReasonInvalidSignature)
	}
	return result("shopify", true, verifier.ReasonOK)
}

type SlackAdapter struct{}

func (SlackAdapter) Name() string { return "slack" }

func (SlackAdapter) Verify(input VerifyInput) VerifyResult {
	tsHeader := firstHeader(input.Headers, "x-slack-request-timestamp")
	sigHeader := firstHeader(input.Headers, "x-slack-signature")
	if tsHeader == "" || sigHeader == "" {
		return result("slack", false, verifier.ReasonMissingSignature)
	}
	unix, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return result("slack", false, verifier.ReasonMalformedHeader)
	}
	ts := time.Unix(unix, 0)
	age := input.Now.Sub(ts)
	if age < 0 {
		age = -age
	}
	if age > 5*time.Minute {
		return VerifyResult{Provider: "slack", Reason: verifier.ReasonExpiredTimestamp, Timestamp: ts}
	}
	signature, ok := strings.CutPrefix(sigHeader, "v0=")
	if !ok {
		return result("slack", false, verifier.ReasonMalformedHeader)
	}
	payload := []byte(fmt.Sprintf("v0:%d:%s", unix, input.RawBody))
	if !verifier.VerifyHMACSHA256Hex(input.Secret, payload, signature) {
		return VerifyResult{Provider: "slack", Reason: verifier.ReasonInvalidSignature, Timestamp: ts}
	}
	return VerifyResult{Provider: "slack", Verified: true, Reason: verifier.ReasonOK, Timestamp: ts}
}

type GenericHMACAdapter struct{}

func (GenericHMACAdapter) Name() string { return "generic-hmac" }

func (GenericHMACAdapter) Verify(input VerifyInput) VerifyResult {
	header := firstHeader(input.Headers, "webhook-signature")
	if header == "" {
		return result("generic-hmac", false, verifier.ReasonMissingSignature)
	}
	signature := strings.TrimPrefix(header, "sha256=")
	if !verifier.VerifyHMACSHA256Hex(input.Secret, input.RawBody, signature) {
		return result("generic-hmac", false, verifier.ReasonInvalidSignature)
	}
	return result("generic-hmac", true, verifier.ReasonOK)
}

type CloudEventsAdapter struct{}

func (CloudEventsAdapter) Name() string { return "cloudevents" }

func (CloudEventsAdapter) Verify(input VerifyInput) VerifyResult {
	if firstHeader(input.Headers, "ce-id") != "" && firstHeader(input.Headers, "ce-type") != "" {
		return result("cloudevents", true, verifier.ReasonOK)
	}
	contentType := strings.ToLower(firstHeader(input.Headers, "content-type"))
	if strings.HasPrefix(contentType, "application/cloudevents+json") {
		var envelope struct {
			SpecVersion string `json:"specversion"`
			ID          string `json:"id"`
			Type        string `json:"type"`
			Source      string `json:"source"`
		}
		if err := json.Unmarshal(input.RawBody, &envelope); err != nil {
			return result("cloudevents", false, verifier.ReasonMalformedHeader)
		}
		if envelope.SpecVersion != "" && envelope.ID != "" && envelope.Type != "" && envelope.Source != "" {
			return result("cloudevents", true, verifier.ReasonOK)
		}
		return result("cloudevents", false, "missing_cloudevents_headers")
	}
	return result("cloudevents", false, "missing_cloudevents_headers")
}

type UnsafeAdapter struct{}

func (UnsafeAdapter) Name() string { return "generic-unsafe" }

func (UnsafeAdapter) Verify(VerifyInput) VerifyResult {
	return result("generic-unsafe", false, "unsafe_adapter_disabled")
}

type InternalTrustedAdapter struct{}

func (InternalTrustedAdapter) Name() string { return "internal" }

func (InternalTrustedAdapter) Verify(VerifyInput) VerifyResult {
	return result("internal", true, verifier.ReasonOK)
}

func result(provider string, verified bool, reason string) VerifyResult {
	return VerifyResult{Provider: provider, Verified: verified, Reason: reason}
}

func firstHeader(headers map[string][]string, name string) string {
	name = strings.ToLower(name)
	for key, values := range headers {
		if strings.ToLower(key) == name && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
