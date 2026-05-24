package authz

type Role string

const (
	RoleOwner     Role = "owner"
	RoleAdmin     Role = "admin"
	RoleDeveloper Role = "developer"
	RoleOperator  Role = "operator"
	RoleSecurity  Role = "security"
	RoleAuditor   Role = "auditor"
	RoleSupport   Role = "support"
)

type Actor struct {
	ID       string
	TenantID string
	Role     Role
	Scopes   []string
	SourceID string
}

type Resource struct {
	TenantID    string            `json:"tenant_id"`
	Family      string            `json:"family"`
	ID          string            `json:"id,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

type Decision struct {
	Allowed              bool     `json:"allowed"`
	Action               string   `json:"action"`
	Resource             Resource `json:"resource"`
	Reason               string   `json:"reason"`
	MatchedRole          string   `json:"matched_role,omitempty"`
	MatchedRoleBindingID string   `json:"matched_role_binding_id,omitempty"`
	MatchedPolicyRuleID  string   `json:"matched_policy_rule_id,omitempty"`
	RequiredScopes       []string `json:"required_scopes,omitempty"`
}

func Can(actor Actor, scope string, resourceTenantID string) bool {
	if actor.TenantID == "" || resourceTenantID == "" || actor.TenantID != resourceTenantID {
		return false
	}
	if !roleAllows(actor.Role, scope) {
		return false
	}
	if len(actor.Scopes) == 0 {
		return true
	}
	for _, s := range actor.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

func roleAllows(role Role, scope string) bool {
	switch role {
	case RoleOwner:
		return true
	case RoleAdmin:
		return scope != "events:raw" && scope != "security:write"
	case RoleDeveloper:
		return hasScope(scope, []string{
			"sources:read", "sources:write",
			"endpoints:read", "endpoints:write",
			"subscriptions:read", "subscriptions:write",
			"routes:read", "routes:write",
			"schemas:read", "schemas:write",
			"events:read", "events:write",
			"deliveries:read", "deliveries:retry",
			"replay:read", "replay:write",
		})
	case RoleOperator:
		return hasScope(scope, []string{
			"sources:read", "endpoints:read", "subscriptions:read", "routes:read", "schemas:read",
			"events:read", "events:write", "deliveries:read", "deliveries:retry", "replay:read", "replay:write",
			"ops:read", "ops:write",
		})
	case RoleSecurity:
		return hasScope(scope, []string{"security:read", "security:write", "audit:read", "events:read", "events:raw"})
	case RoleAuditor:
		return hasScope(scope, []string{"audit:read", "events:read", "events:raw", "deliveries:read", "replay:read", "security:read"})
	case RoleSupport:
		return hasScope(scope, []string{"events:read", "deliveries:read", "replay:read"})
	default:
		return false
	}
}

func hasScope(scope string, allowed []string) bool {
	for _, item := range allowed {
		if item == scope {
			return true
		}
	}
	return false
}
