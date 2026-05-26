package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"webhookery/internal/authz"
	"webhookery/internal/domain"
)

type CreateProviderAdapterRequest struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Description   string `json:"description,omitempty"`
	RiskLevel     string `json:"risk_level,omitempty"`
	ProvenanceURL string `json:"provenance_url,omitempty"`
}

type CreateAdapterVersionRequest struct {
	Version          string          `json:"version"`
	Definition       json.RawMessage `json:"definition,omitempty"`
	PackageSHA256    string          `json:"package_sha256,omitempty"`
	PackageSignature string          `json:"package_signature,omitempty"`
	SBOMSHA256       string          `json:"sbom_sha256,omitempty"`
	ProvenanceURL    string          `json:"provenance_url,omitempty"`
	RiskLevel        string          `json:"risk_level,omitempty"`
	Reason           string          `json:"reason"`
}

type CreateAdapterTestVectorRequest struct {
	Name     string          `json:"name"`
	Purpose  string          `json:"purpose,omitempty"`
	Request  json.RawMessage `json:"request"`
	Expected json.RawMessage `json:"expected"`
}

type AdapterVersionTransitionRequest struct {
	Action      string          `json:"action"`
	Reason      string          `json:"reason"`
	TestResults json.RawMessage `json:"test_results,omitempty"`
	ReviewNotes string          `json:"review_notes,omitempty"`
}

func (s *ControlService) CreateProviderAdapter(ctx context.Context, actor authz.Actor, req CreateProviderAdapterRequest) (domain.ProviderAdapter, error) {
	if !s.authorized(ctx, actor, "security:write", "provider_adapter", "", "") {
		return domain.ProviderAdapter{}, ErrForbidden
	}
	if err := validateProviderAdapterRequest(&req); err != nil {
		return domain.ProviderAdapter{}, err
	}
	return s.store.CreateProviderAdapter(ctx, actor.TenantID, actor.ID, req)
}

func (s *ControlService) ListProviderAdapters(ctx context.Context, actor authz.Actor, limit int) ([]domain.ProviderAdapter, error) {
	if !s.authorized(ctx, actor, "sources:read", "provider_adapter", "", "") {
		return nil, ErrForbidden
	}
	return s.store.ListProviderAdapters(ctx, actor.TenantID, normalizeLimit(limit))
}

func (s *ControlService) GetProviderAdapter(ctx context.Context, actor authz.Actor, adapterID string) (domain.ProviderAdapter, error) {
	if !s.authorized(ctx, actor, "sources:read", "provider_adapter", adapterID, "") {
		return domain.ProviderAdapter{}, ErrForbidden
	}
	if strings.TrimSpace(adapterID) == "" {
		return domain.ProviderAdapter{}, fmt.Errorf("%w: adapter_id is required", ErrInvalidInput)
	}
	return s.store.GetProviderAdapter(ctx, actor.TenantID, adapterID)
}

func (s *ControlService) CreateAdapterVersion(ctx context.Context, actor authz.Actor, adapterID string, req CreateAdapterVersionRequest) (domain.AdapterVersion, error) {
	if !s.authorized(ctx, actor, "security:write", "provider_adapter", adapterID, "") {
		return domain.AdapterVersion{}, ErrForbidden
	}
	if strings.TrimSpace(adapterID) == "" {
		return domain.AdapterVersion{}, fmt.Errorf("%w: adapter_id is required", ErrInvalidInput)
	}
	if err := validateAdapterVersionRequest(&req); err != nil {
		return domain.AdapterVersion{}, err
	}
	return s.store.CreateAdapterVersion(ctx, actor.TenantID, adapterID, actor.ID, req)
}

func (s *ControlService) ListAdapterVersions(ctx context.Context, actor authz.Actor, adapterID string, limit int) ([]domain.AdapterVersion, error) {
	if !s.authorized(ctx, actor, "sources:read", "provider_adapter", adapterID, "") {
		return nil, ErrForbidden
	}
	if strings.TrimSpace(adapterID) == "" {
		return nil, fmt.Errorf("%w: adapter_id is required", ErrInvalidInput)
	}
	return s.store.ListAdapterVersions(ctx, actor.TenantID, adapterID, normalizeLimit(limit))
}

func (s *ControlService) CreateAdapterTestVector(ctx context.Context, actor authz.Actor, adapterID, versionID string, req CreateAdapterTestVectorRequest) (domain.AdapterTestVector, error) {
	if !s.authorized(ctx, actor, "security:write", "adapter_version", versionID, "") {
		return domain.AdapterTestVector{}, ErrForbidden
	}
	if strings.TrimSpace(adapterID) == "" || strings.TrimSpace(versionID) == "" {
		return domain.AdapterTestVector{}, fmt.Errorf("%w: adapter_id and version_id are required", ErrInvalidInput)
	}
	if err := validateAdapterTestVectorRequest(&req); err != nil {
		return domain.AdapterTestVector{}, err
	}
	return s.store.CreateAdapterTestVector(ctx, actor.TenantID, adapterID, versionID, actor.ID, req)
}

func (s *ControlService) TransitionAdapterVersion(ctx context.Context, actor authz.Actor, adapterID, versionID string, req AdapterVersionTransitionRequest) (domain.AdapterVersion, error) {
	if !s.authorized(ctx, actor, "security:write", "adapter_version", versionID, "") {
		return domain.AdapterVersion{}, ErrForbidden
	}
	if strings.TrimSpace(adapterID) == "" || strings.TrimSpace(versionID) == "" || strings.TrimSpace(req.Reason) == "" {
		return domain.AdapterVersion{}, fmt.Errorf("%w: adapter_id, version_id, and reason are required", ErrInvalidInput)
	}
	req.Action = strings.TrimSpace(req.Action)
	if _, ok := adapterTransitionState(req.Action); !ok {
		return domain.AdapterVersion{}, fmt.Errorf("%w: unsupported adapter version action", ErrInvalidInput)
	}
	if len(req.TestResults) != 0 && !json.Valid(req.TestResults) {
		return domain.AdapterVersion{}, fmt.Errorf("%w: test_results must be valid JSON", ErrInvalidInput)
	}
	return s.store.TransitionAdapterVersion(ctx, actor.TenantID, adapterID, versionID, actor.ID, req)
}

func validateProviderAdapterRequest(req *CreateProviderAdapterRequest) error {
	req.Name = strings.ToLower(strings.TrimSpace(req.Name))
	req.Kind = strings.ToLower(strings.TrimSpace(req.Kind))
	if req.Kind == "" {
		req.Kind = domain.AdapterKindDeclarative
	}
	req.RiskLevel = strings.ToLower(strings.TrimSpace(req.RiskLevel))
	if req.RiskLevel == "" {
		req.RiskLevel = domain.AdapterRiskMedium
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if !safeAdapterName(req.Name) {
		return fmt.Errorf("%w: adapter name must use lowercase letters, digits, dash, or underscore", ErrInvalidInput)
	}
	switch req.Kind {
	case domain.AdapterKindDeclarative, domain.AdapterKindPlugin:
	default:
		return fmt.Errorf("%w: adapter kind must be declarative or plugin", ErrInvalidInput)
	}
	if !validAdapterRisk(req.RiskLevel) {
		return fmt.Errorf("%w: invalid risk_level", ErrInvalidInput)
	}
	return nil
}

func validateAdapterVersionRequest(req *CreateAdapterVersionRequest) error {
	req.Version = strings.TrimSpace(req.Version)
	req.RiskLevel = strings.ToLower(strings.TrimSpace(req.RiskLevel))
	if req.RiskLevel == "" {
		req.RiskLevel = domain.AdapterRiskMedium
	}
	if req.Version == "" || strings.TrimSpace(req.Reason) == "" {
		return fmt.Errorf("%w: version and reason are required", ErrInvalidInput)
	}
	if len(req.Definition) != 0 && !json.Valid(req.Definition) {
		return fmt.Errorf("%w: definition must be valid JSON", ErrInvalidInput)
	}
	if containsSensitiveAdapterField(req.Definition) {
		return fmt.Errorf("%w: adapter definitions must not include secrets or tokens", ErrInvalidInput)
	}
	if !validAdapterRisk(req.RiskLevel) {
		return fmt.Errorf("%w: invalid risk_level", ErrInvalidInput)
	}
	return nil
}

func validateAdapterTestVectorRequest(req *CreateAdapterTestVectorRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Request) == 0 || len(req.Expected) == 0 {
		return fmt.Errorf("%w: name, request, and expected are required", ErrInvalidInput)
	}
	if !json.Valid(req.Request) || !json.Valid(req.Expected) {
		return fmt.Errorf("%w: request and expected must be valid JSON", ErrInvalidInput)
	}
	if containsSensitiveAdapterField(req.Request) || containsSensitiveAdapterField(req.Expected) {
		return fmt.Errorf("%w: adapter test vectors must not include secrets or tokens", ErrInvalidInput)
	}
	return nil
}

func adapterTransitionState(action string) (string, bool) {
	switch action {
	case "submit_tests":
		return domain.AdapterStateAutomatedTests, true
	case "request_review":
		return domain.AdapterStateSecurityReview, true
	case "approve_staging":
		return domain.AdapterStateStagingApproved, true
	case "activate":
		return domain.AdapterStateActive, true
	case "deprecate":
		return domain.AdapterStateDeprecated, true
	case "retire":
		return domain.AdapterStateRetired, true
	default:
		return "", false
	}
}

func validAdapterRisk(risk string) bool {
	switch risk {
	case domain.AdapterRiskLow, domain.AdapterRiskMedium, domain.AdapterRiskHigh:
		return true
	default:
		return false
	}
}

func safeAdapterName(name string) bool {
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func containsSensitiveAdapterField(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	return containsSensitiveField(value)
}

func containsSensitiveField(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "password") || strings.Contains(lower, "private_key") {
				return true
			}
			if containsSensitiveField(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if containsSensitiveField(nested) {
				return true
			}
		}
	}
	return false
}
