package app

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"webhookery/internal/domain"
)

func TestAdapterTransitionStateMapsGovernedActions(t *testing.T) {
	tests := map[string]string{
		"submit_tests":    domain.AdapterStateAutomatedTests,
		"request_review":  domain.AdapterStateSecurityReview,
		"approve_staging": domain.AdapterStateStagingApproved,
		"activate":        domain.AdapterStateActive,
		"deprecate":       domain.AdapterStateDeprecated,
		"retire":          domain.AdapterStateRetired,
	}
	for action, want := range tests {
		t.Run(action, func(t *testing.T) {
			got, ok := adapterTransitionState(action)
			if !ok || got != want {
				t.Fatalf("adapterTransitionState(%q)=%q,%v want %q,true", action, got, ok, want)
			}
		})
	}
	if got, ok := adapterTransitionState("skip_review"); ok || got != "" {
		t.Fatalf("unexpected unsupported action mapping: %q %v", got, ok)
	}
}

func TestProviderAdapterValidationNormalizesAndRejectsUnsafeInput(t *testing.T) {
	valid := CreateProviderAdapterRequest{Name: " ACME_Adapter-1 ", Kind: "", RiskLevel: ""}
	if err := validateProviderAdapterRequest(&valid); err != nil {
		t.Fatal(err)
	}
	if valid.Name != "acme_adapter-1" || valid.Kind != domain.AdapterKindDeclarative || valid.RiskLevel != domain.AdapterRiskMedium {
		t.Fatalf("adapter defaults were not normalized: %+v", valid)
	}

	tests := []struct {
		name string
		req  CreateProviderAdapterRequest
		want string
	}{
		{name: "missing name", req: CreateProviderAdapterRequest{Name: " "}, want: "name is required"},
		{name: "unsafe name", req: CreateProviderAdapterRequest{Name: "Acme Adapter!"}, want: "adapter name"},
		{name: "bad kind", req: CreateProviderAdapterRequest{Name: "acme", Kind: "binary"}, want: "adapter kind"},
		{name: "bad risk", req: CreateProviderAdapterRequest{Name: "acme", Kind: domain.AdapterKindDeclarative, RiskLevel: "critical"}, want: "invalid risk_level"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProviderAdapterRequest(&tt.req)
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected invalid input containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestAdapterVersionValidationRejectsInvalidJSONRiskAndSecrets(t *testing.T) {
	valid := CreateAdapterVersionRequest{Version: " v1 ", Reason: "security review", Definition: json.RawMessage(`{"rules":[{"path":"$.id"}]}`)}
	if err := validateAdapterVersionRequest(&valid); err != nil {
		t.Fatal(err)
	}
	if valid.Version != "v1" || valid.RiskLevel != domain.AdapterRiskMedium {
		t.Fatalf("adapter version defaults were not normalized: %+v", valid)
	}

	tests := []struct {
		name string
		req  CreateAdapterVersionRequest
		want string
	}{
		{name: "missing version", req: CreateAdapterVersionRequest{Reason: "publish"}, want: "version and reason"},
		{name: "missing reason", req: CreateAdapterVersionRequest{Version: "v1"}, want: "version and reason"},
		{name: "invalid definition json", req: CreateAdapterVersionRequest{Version: "v1", Reason: "publish", Definition: json.RawMessage(`{`)}, want: "definition must be valid JSON"},
		{name: "secret in definition", req: CreateAdapterVersionRequest{Version: "v1", Reason: "publish", Definition: json.RawMessage(`{"config":{"api_token":"secret"}}`)}, want: "must not include secrets"},
		{name: "nested private key", req: CreateAdapterVersionRequest{Version: "v1", Reason: "publish", Definition: json.RawMessage(`[{"private_key":"pem"}]`)}, want: "must not include secrets"},
		{name: "invalid risk", req: CreateAdapterVersionRequest{Version: "v1", Reason: "publish", RiskLevel: "severe"}, want: "invalid risk_level"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAdapterVersionRequest(&tt.req)
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected invalid input containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestAdapterTestVectorValidationRequiresJSONAndRejectsSecrets(t *testing.T) {
	valid := CreateAdapterTestVectorRequest{Name: " valid vector ", Request: json.RawMessage(`{"headers":{}}`), Expected: json.RawMessage(`{"verified":true}`)}
	if err := validateAdapterTestVectorRequest(&valid); err != nil {
		t.Fatal(err)
	}
	if valid.Name != "valid vector" {
		t.Fatalf("test vector name was not trimmed: %+v", valid)
	}

	tests := []struct {
		name string
		req  CreateAdapterTestVectorRequest
		want string
	}{
		{name: "missing fields", req: CreateAdapterTestVectorRequest{Name: "vector", Request: json.RawMessage(`{}`)}, want: "name, request, and expected"},
		{name: "invalid request", req: CreateAdapterTestVectorRequest{Name: "vector", Request: json.RawMessage(`{`), Expected: json.RawMessage(`{}`)}, want: "valid JSON"},
		{name: "invalid expected", req: CreateAdapterTestVectorRequest{Name: "vector", Request: json.RawMessage(`{}`), Expected: json.RawMessage(`{`)}, want: "valid JSON"},
		{name: "secret request", req: CreateAdapterTestVectorRequest{Name: "vector", Request: json.RawMessage(`{"headers":{"authorization_token":"secret"}}`), Expected: json.RawMessage(`{}`)}, want: "must not include secrets"},
		{name: "secret expected", req: CreateAdapterTestVectorRequest{Name: "vector", Request: json.RawMessage(`{}`), Expected: json.RawMessage(`{"password":"secret"}`)}, want: "must not include secrets"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAdapterTestVectorRequest(&tt.req)
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected invalid input containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestSensitiveAdapterFieldDetectionIgnoresMalformedOrEmptyDefinitions(t *testing.T) {
	if containsSensitiveAdapterField(nil) {
		t.Fatal("empty definition should not be treated as sensitive")
	}
	if containsSensitiveAdapterField(json.RawMessage(`{`)) {
		t.Fatal("malformed definition is handled by JSON validation and should not panic")
	}
	if containsSensitiveField([]any{map[string]any{"nested": []any{map[string]any{"clientSecret": "value"}}}}) != true {
		t.Fatal("nested sensitive field should be detected")
	}
	if containsSensitiveField(map[string]any{"safe": []any{"value"}}) {
		t.Fatal("safe fields should not be flagged as sensitive")
	}
}
