package provider

import (
	"encoding/json"
	"errors"
	"strings"

	"webhookery/internal/canonicaljson"
	"webhookery/internal/domain"
)

var ErrUnverifiedNormalization = errors.New("cannot normalize unverified provider payload")

type NormalizeInput struct {
	Adapter      string
	Provider     string
	TenantID     string
	SourceID     string
	RawBody      []byte
	Headers      map[string][]string
	Verified     bool
	VerifyReason string
	RawHash      string
}

type NormalizedEnvelope struct {
	ID              string
	Source          string
	Type            string
	Subject         string
	Provider        string
	ProviderEventID string
	Envelope        []byte
	Data            []byte
	Metadata        []byte
	EnvelopeHash    string
	DataHash        string
	MetadataHash    string
}

func Normalize(input NormalizeInput) (NormalizedEnvelope, error) {
	adapter := strings.ToLower(strings.TrimSpace(input.Adapter))
	if adapter == "" {
		adapter = strings.ToLower(strings.TrimSpace(input.Provider))
	}
	if !input.Verified && input.VerifyReason != domain.VerificationReasonProviderAPIReconcile && adapter != "generic-unsafe" {
		return NormalizedEnvelope{}, ErrUnverifiedNormalization
	}
	var raw map[string]any
	_ = json.Unmarshal(input.RawBody, &raw)
	id, eventType := providerMetadata(adapter, raw, input.Headers)
	if id == "" {
		id = input.RawHash
	}
	if eventType == "" {
		eventType = "unknown"
	}
	source := normalizedSource(adapter, input.SourceID, raw, input.Headers)
	subject := normalizedSubject(adapter, raw, input.Headers)
	data := normalizedData(adapter, raw, input.RawBody)
	metadata := normalizedMetadata(input, raw)
	dataJSON, err := canonicaljson.Marshal(data)
	if err != nil {
		return NormalizedEnvelope{}, err
	}
	metadataJSON, err := canonicaljson.Marshal(metadata)
	if err != nil {
		return NormalizedEnvelope{}, err
	}
	envelope := map[string]any{
		"specversion":         "1.0",
		"id":                  id,
		"type":                eventType,
		"source":              source,
		"subject":             subject,
		"tenant_id":           input.TenantID,
		"source_id":           input.SourceID,
		"provider":            input.Provider,
		"provider_event_id":   id,
		"raw_payload_hash":    input.RawHash,
		"signature_verified":  input.Verified,
		"verification_reason": input.VerifyReason,
		"data":                data,
		"metadata":            metadata,
	}
	envelopeJSON, err := canonicaljson.Marshal(envelope)
	if err != nil {
		return NormalizedEnvelope{}, err
	}
	return NormalizedEnvelope{
		ID:              id,
		Source:          source,
		Type:            eventType,
		Subject:         subject,
		Provider:        input.Provider,
		ProviderEventID: id,
		Envelope:        envelopeJSON,
		Data:            dataJSON,
		Metadata:        metadataJSON,
		EnvelopeHash:    domain.HashSHA256(envelopeJSON),
		DataHash:        domain.HashSHA256(dataJSON),
		MetadataHash:    domain.HashSHA256(metadataJSON),
	}, nil
}

func providerMetadata(adapter string, raw map[string]any, headers map[string][]string) (string, string) {
	switch adapter {
	case "github":
		return firstHeader(headers, "x-github-delivery"), firstHeader(headers, "x-github-event")
	case "shopify":
		return firstHeader(headers, "x-shopify-webhook-id"), firstHeader(headers, "x-shopify-topic")
	case "slack":
		id := stringValue(raw, "event_id")
		eventType := ""
		if event, ok := raw["event"].(map[string]any); ok {
			eventType, _ = event["type"].(string)
		}
		if eventType == "" {
			eventType = stringValue(raw, "type")
		}
		return id, eventType
	case "cloudevents":
		id := firstHeader(headers, "ce-id")
		eventType := firstHeader(headers, "ce-type")
		if id == "" {
			id = stringValue(raw, "id")
		}
		if eventType == "" {
			eventType = stringValue(raw, "type")
		}
		return id, eventType
	default:
		return stringValue(raw, "id"), firstNonEmpty(stringValue(raw, "type"), nestedString(raw, "event", "type"))
	}
}

func normalizedSource(adapter, sourceID string, raw map[string]any, headers map[string][]string) string {
	switch adapter {
	case "stripe":
		if account := stringValue(raw, "account"); account != "" {
			return "stripe:" + account
		}
	case "github":
		if repo := nestedString(raw, "repository", "full_name"); repo != "" {
			return "github:" + repo
		}
	case "shopify":
		if shop := firstHeader(headers, "x-shopify-shop-domain"); shop != "" {
			return "shopify:" + shop
		}
	case "slack":
		if team := stringValue(raw, "team_id"); team != "" {
			return "slack:" + team
		}
	case "cloudevents":
		if source := firstHeader(headers, "ce-source"); source != "" {
			return source
		}
		if source := stringValue(raw, "source"); source != "" {
			return source
		}
	}
	return adapter + ":" + sourceID
}

func normalizedSubject(adapter string, raw map[string]any, headers map[string][]string) string {
	switch adapter {
	case "stripe":
		if id := nestedString(raw, "data", "object", "id"); id != "" {
			return id
		}
	case "github":
		return nestedString(raw, "repository", "full_name")
	case "shopify":
		return firstHeader(headers, "x-shopify-shop-domain")
	case "slack":
		return firstNonEmpty(nestedString(raw, "event", "channel"), nestedString(raw, "event", "user"))
	case "cloudevents":
		if subject := firstHeader(headers, "ce-subject"); subject != "" {
			return subject
		}
		return stringValue(raw, "subject")
	}
	return ""
}

func normalizedData(adapter string, raw map[string]any, rawBody []byte) any {
	if adapter == "cloudevents" {
		if data, ok := raw["data"]; ok {
			return data
		}
	}
	if len(raw) > 0 {
		return raw
	}
	return string(rawBody)
}

func normalizedMetadata(input NormalizeInput, raw map[string]any) map[string]any {
	meta := map[string]any{
		"adapter":             input.Adapter,
		"provider":            input.Provider,
		"raw_payload_hash":    input.RawHash,
		"verification_reason": input.VerifyReason,
	}
	switch strings.ToLower(input.Adapter) {
	case "stripe":
		meta["api_version"] = stringValue(raw, "api_version")
		meta["livemode"] = raw["livemode"]
	case "github":
		meta["delivery"] = firstHeader(input.Headers, "x-github-delivery")
		meta["event"] = firstHeader(input.Headers, "x-github-event")
	case "shopify":
		meta["topic"] = firstHeader(input.Headers, "x-shopify-topic")
		meta["shop_domain"] = firstHeader(input.Headers, "x-shopify-shop-domain")
		meta["webhook_id"] = firstHeader(input.Headers, "x-shopify-webhook-id")
	case "slack":
		meta["team_id"] = stringValue(raw, "team_id")
		meta["api_app_id"] = stringValue(raw, "api_app_id")
		meta["event_time"] = raw["event_time"]
	case "cloudevents":
		meta["specversion"] = firstNonEmpty(firstHeader(input.Headers, "ce-specversion"), stringValue(raw, "specversion"))
		meta["datacontenttype"] = firstNonEmpty(firstHeader(input.Headers, "ce-datacontenttype"), stringValue(raw, "datacontenttype"))
	}
	return meta
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func nestedString(values map[string]any, path ...string) string {
	var current any = values
	for _, key := range path {
		obj, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = obj[key]
	}
	value, _ := current.(string)
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
