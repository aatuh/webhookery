package provider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
		"generic-jwt":    GenericJWTAdapter{},
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

type GenericJWTAdapter struct{}

func (GenericJWTAdapter) Name() string { return "generic-jwt" }

func (GenericJWTAdapter) Verify(input VerifyInput) VerifyResult {
	token := bearerToken(firstHeader(input.Headers, "authorization"))
	if token == "" {
		token = strings.TrimSpace(firstHeader(input.Headers, "webhook-jwt"))
	}
	if token == "" {
		return result("generic-jwt", false, verifier.ReasonMissingSignature)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return result("generic-jwt", false, verifier.ReasonMalformedHeader)
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}
	if !decodeJWTPart(parts[0], &header) {
		return result("generic-jwt", false, verifier.ReasonMalformedHeader)
	}
	if header.Algorithm != "HS256" {
		return result("generic-jwt", false, verifier.ReasonUnsupportedAlg)
	}
	var claims map[string]any
	if !decodeJWTPart(parts[1], &claims) {
		return result("generic-jwt", false, verifier.ReasonMalformedHeader)
	}
	signature, err := decodeBase64URL(parts[2])
	if err != nil {
		return result("generic-jwt", false, verifier.ReasonMalformedHeader)
	}
	mac := hmac.New(sha256.New, input.Secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return result("generic-jwt", false, verifier.ReasonInvalidSignature)
	}
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	exp := jwtNumericClaim(claims, "exp")
	if exp == 0 {
		return result("generic-jwt", false, verifier.ReasonMalformedHeader)
	}
	if now.Unix() >= exp {
		return VerifyResult{Provider: "generic-jwt", Reason: verifier.ReasonExpiredTimestamp, Timestamp: time.Unix(exp, 0)}
	}
	if nbf := jwtNumericClaim(claims, "nbf"); nbf != 0 && now.Unix() < nbf {
		return VerifyResult{Provider: "generic-jwt", Reason: verifier.ReasonExpiredTimestamp, Timestamp: time.Unix(nbf, 0)}
	}
	if iat := jwtNumericClaim(claims, "iat"); iat != 0 && now.Add(5*time.Minute).Unix() < iat {
		return VerifyResult{Provider: "generic-jwt", Reason: verifier.ReasonExpiredTimestamp, Timestamp: time.Unix(iat, 0)}
	}
	bodyHash, _ := claims["body_sha256"].(string)
	if !strings.EqualFold(strings.TrimSpace(bodyHash), sha256Hex(input.RawBody)) {
		return result("generic-jwt", false, verifier.ReasonInvalidSignature)
	}
	return result("generic-jwt", true, verifier.ReasonOK)
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

func bearerToken(header string) string {
	prefix, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(prefix, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

func decodeJWTPart(part string, dst any) bool {
	raw, err := decodeBase64URL(part)
	if err != nil {
		return false
	}
	return json.Unmarshal(raw, dst) == nil
}

func decodeBase64URL(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		return raw, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

func jwtNumericClaim(claims map[string]any, key string) int64 {
	switch value := claims[key].(type) {
	case float64:
		return int64(value)
	case json.Number:
		parsed, _ := value.Int64()
		return parsed
	default:
		return 0
	}
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
