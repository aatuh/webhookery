package provider

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"webhookery/internal/canonicaljson"
	"webhookery/internal/domain"
	"webhookery/pkg/verifier"
)

type DeclarativeDefinition struct {
	Name          string                     `json:"name"`
	Version       string                     `json:"version"`
	Verification  DeclarativeVerification    `json:"verification"`
	Extractors    map[string]string          `json:"extractors,omitempty"`
	Deduplication map[string]any             `json:"deduplication,omitempty"`
	Normalization DeclarativeNormalization   `json:"normalization,omitempty"`
	Metadata      map[string]json.RawMessage `json:"metadata,omitempty"`
}

type DeclarativeVerification struct {
	Type                string `json:"type"`
	SignatureHeader     string `json:"signature_header"`
	TimestampHeader     string `json:"timestamp_header,omitempty"`
	SignedPayload       string `json:"signed_payload,omitempty"`
	Encoding            string `json:"encoding,omitempty"`
	ReplayWindowSeconds int    `json:"replay_window_seconds,omitempty"`
	SignaturePrefix     string `json:"signature_prefix,omitempty"`
}

type DeclarativeNormalization struct {
	Source  string `json:"source,omitempty"`
	Subject string `json:"subject,omitempty"`
	Data    string `json:"data,omitempty"`
}

type DeclarativeAdapter struct {
	def DeclarativeDefinition
}

func NewDeclarativeAdapter(raw json.RawMessage) (DeclarativeAdapter, error) {
	def, err := ParseDeclarativeDefinition(raw)
	if err != nil {
		return DeclarativeAdapter{}, err
	}
	return DeclarativeAdapter{def: def}, nil
}

func ParseDeclarativeDefinition(raw json.RawMessage) (DeclarativeDefinition, error) {
	var def DeclarativeDefinition
	if len(raw) == 0 {
		return def, fmt.Errorf("definition is required")
	}
	if err := json.Unmarshal(raw, &def); err != nil {
		return def, err
	}
	if err := ValidateDeclarativeDefinition(def); err != nil {
		return def, err
	}
	return def, nil
}

func ValidateDeclarativeDefinition(def DeclarativeDefinition) error {
	if strings.TrimSpace(def.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.ToLower(strings.TrimSpace(def.Verification.Type)) != "hmac_sha256" {
		return fmt.Errorf("only hmac_sha256 declarative verification is supported")
	}
	if strings.TrimSpace(def.Verification.SignatureHeader) == "" {
		return fmt.Errorf("signature_header is required")
	}
	switch strings.ToLower(strings.TrimSpace(def.Verification.Encoding)) {
	case "", verifier.EncodingHex, verifier.EncodingBase64:
	default:
		return fmt.Errorf("unsupported signature encoding")
	}
	payload := strings.TrimSpace(def.Verification.SignedPayload)
	if payload == "" {
		payload = "{{raw_body}}"
	}
	switch payload {
	case "{{raw_body}}", "{{timestamp}}.{{raw_body}}", "{{timestamp}}:{{raw_body}}", "v0:{{timestamp}}:{{raw_body}}":
	default:
		return fmt.Errorf("unsupported signed_payload template")
	}
	if strings.Contains(payload, "{{timestamp}}") && strings.TrimSpace(def.Verification.TimestampHeader) == "" {
		return fmt.Errorf("timestamp_header is required by signed_payload")
	}
	if def.Verification.ReplayWindowSeconds < 0 || def.Verification.ReplayWindowSeconds > 86400 {
		return fmt.Errorf("replay_window_seconds must be between 0 and 86400")
	}
	return nil
}

func (a DeclarativeAdapter) Name() string { return strings.ToLower(a.def.Name) }

func (a DeclarativeAdapter) Verify(input VerifyInput) VerifyResult {
	header := firstHeader(input.Headers, a.def.Verification.SignatureHeader)
	if header == "" {
		return result(a.Name(), false, verifier.ReasonMissingSignature)
	}
	signature := strings.TrimSpace(header)
	if prefix := strings.TrimSpace(a.def.Verification.SignaturePrefix); prefix != "" {
		if !strings.HasPrefix(signature, prefix) {
			return result(a.Name(), false, verifier.ReasonMalformedHeader)
		}
		signature = strings.TrimPrefix(signature, prefix)
	} else {
		signature = strings.TrimPrefix(signature, "sha256=")
	}
	payloadTemplate := strings.TrimSpace(a.def.Verification.SignedPayload)
	if payloadTemplate == "" {
		payloadTemplate = "{{raw_body}}"
	}
	payload := append([]byte(nil), input.RawBody...)
	var ts time.Time
	if strings.Contains(payloadTemplate, "{{timestamp}}") {
		tsHeader := firstHeader(input.Headers, a.def.Verification.TimestampHeader)
		if tsHeader == "" {
			return result(a.Name(), false, verifier.ReasonMissingSignature)
		}
		parsed, err := parseDeclarativeTimestamp(tsHeader)
		if err != nil {
			return result(a.Name(), false, verifier.ReasonMalformedHeader)
		}
		ts = parsed
		now := input.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		age := now.Sub(ts)
		if age < 0 {
			age = -age
		}
		window := time.Duration(a.def.Verification.ReplayWindowSeconds) * time.Second
		if window > 0 && age > window {
			return VerifyResult{Provider: a.Name(), Reason: verifier.ReasonExpiredTimestamp, Timestamp: ts}
		}
		payload = []byte(strings.ReplaceAll(payloadTemplate, "{{timestamp}}", strings.TrimSpace(tsHeader)))
		payload = []byte(strings.ReplaceAll(string(payload), "{{raw_body}}", string(input.RawBody)))
	}
	ok := false
	switch strings.ToLower(strings.TrimSpace(a.def.Verification.Encoding)) {
	case "", verifier.EncodingHex:
		ok = verifier.VerifyHMACSHA256Hex(input.Secret, payload, signature)
	case verifier.EncodingBase64:
		ok = verifier.VerifyHMACSHA256Base64(input.Secret, payload, signature)
	default:
		return result(a.Name(), false, verifier.ReasonUnsupportedAlg)
	}
	if !ok {
		return VerifyResult{Provider: a.Name(), Reason: verifier.ReasonInvalidSignature, Timestamp: ts}
	}
	return VerifyResult{Provider: a.Name(), Verified: true, Reason: verifier.ReasonOK, Timestamp: ts}
}

func DeclarativeMetadata(rawDefinition json.RawMessage, rawBody []byte, headers map[string][]string) (providerEventID, eventType string) {
	def, err := ParseDeclarativeDefinition(rawDefinition)
	if err != nil {
		return "", ""
	}
	raw := parseJSONMap(rawBody)
	return declarativeValue(def.Extractors["provider_event_id"], raw, headers), declarativeValue(def.Extractors["type"], raw, headers)
}

func NormalizeDeclarative(input NormalizeInput, rawDefinition json.RawMessage) (NormalizedEnvelope, bool, error) {
	def, err := ParseDeclarativeDefinition(rawDefinition)
	if err != nil {
		return NormalizedEnvelope{}, false, err
	}
	raw := parseJSONMap(input.RawBody)
	providerID := declarativeValue(def.Extractors["provider_event_id"], raw, input.Headers)
	if providerID == "" {
		providerID = input.RawHash
	}
	eventType := declarativeValue(def.Extractors["type"], raw, input.Headers)
	if eventType == "" {
		eventType = "unknown"
	}
	accountID := declarativeValue(def.Extractors["account_id"], raw, input.Headers)
	source := renderDeclarativeTemplate(def.Normalization.Source, raw, input.Headers, map[string]string{"account_id": accountID})
	if source == "" {
		source = input.Adapter + ":" + input.SourceID
	}
	subject := declarativeValue(def.Normalization.Subject, raw, input.Headers)
	data := declarativeAny(def.Normalization.Data, raw, input.Headers)
	if data == nil {
		data = normalizedData(input.Adapter, raw, input.RawBody)
	}
	metadata := normalizedMetadata(input, raw)
	metadata["declarative_adapter"] = def.Name
	metadata["declarative_version"] = def.Version
	metadata["account_id"] = accountID
	dataJSON, err := canonicaljson.Marshal(data)
	if err != nil {
		return NormalizedEnvelope{}, false, err
	}
	metadataJSON, err := canonicaljson.Marshal(metadata)
	if err != nil {
		return NormalizedEnvelope{}, false, err
	}
	envelope := map[string]any{
		"specversion":         "1.0",
		"id":                  providerID,
		"type":                eventType,
		"source":              source,
		"subject":             subject,
		"tenant_id":           input.TenantID,
		"source_id":           input.SourceID,
		"provider":            input.Provider,
		"provider_event_id":   providerID,
		"raw_payload_hash":    input.RawHash,
		"signature_verified":  input.Verified,
		"verification_reason": input.VerifyReason,
		"data":                data,
		"metadata":            metadata,
	}
	envelopeJSON, err := canonicaljson.Marshal(envelope)
	if err != nil {
		return NormalizedEnvelope{}, false, err
	}
	return NormalizedEnvelope{
		ID:              providerID,
		Source:          source,
		Type:            eventType,
		Subject:         subject,
		Provider:        input.Provider,
		ProviderEventID: providerID,
		Envelope:        envelopeJSON,
		Data:            dataJSON,
		Metadata:        metadataJSON,
		EnvelopeHash:    domain.HashSHA256(envelopeJSON),
		DataHash:        domain.HashSHA256(dataJSON),
		MetadataHash:    domain.HashSHA256(metadataJSON),
	}, true, nil
}

func parseDeclarativeTimestamp(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if unix, err := parseInt64(raw); err == nil {
		return time.Unix(unix, 0), nil
	}
	return time.Parse(time.RFC3339, raw)
}

func parseInt64(raw string) (int64, error) {
	var out int64
	if raw == "" {
		return 0, fmt.Errorf("empty integer")
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not integer")
		}
		out = out*10 + int64(r-'0')
	}
	return out, nil
}

func parseJSONMap(raw []byte) map[string]any {
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func declarativeValue(path string, raw map[string]any, headers map[string][]string) string {
	value := declarativeAny(path, raw, headers)
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return fmt.Sprintf("%.0f", typed)
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func declarativeAny(path string, raw map[string]any, headers map[string][]string) any {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if path == "$" {
		return raw
	}
	if strings.HasPrefix(path, "$.") {
		parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
		var current any = raw
		for _, part := range parts {
			obj, ok := current.(map[string]any)
			if !ok {
				return nil
			}
			current = obj[part]
		}
		return current
	}
	if strings.HasPrefix(strings.ToLower(path), "header:") {
		return firstHeader(headers, strings.TrimSpace(path[len("header:"):]))
	}
	return path
}

func renderDeclarativeTemplate(template string, raw map[string]any, headers map[string][]string, values map[string]string) string {
	out := strings.TrimSpace(template)
	if out == "" {
		return ""
	}
	for key, value := range values {
		out = strings.ReplaceAll(out, "{{"+key+"}}", value)
	}
	for strings.Contains(out, "{{$.") {
		start := strings.Index(out, "{{$.")
		end := strings.Index(out[start:], "}}")
		if end < 0 {
			break
		}
		token := out[start : start+end+2]
		path := strings.TrimSuffix(strings.TrimPrefix(token, "{{"), "}}")
		out = strings.ReplaceAll(out, token, declarativeValue(path, raw, headers))
	}
	return out
}
