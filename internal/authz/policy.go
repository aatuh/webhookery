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
			"events:read",
			"deliveries:read", "deliveries:retry",
			"replay:read", "replay:write",
		})
	case RoleOperator:
		return hasScope(scope, []string{
			"sources:read", "endpoints:read", "subscriptions:read", "routes:read", "schemas:read",
			"events:read", "deliveries:read", "deliveries:retry", "replay:read", "replay:write",
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
