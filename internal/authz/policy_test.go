package authz

import "testing"

func TestPolicyRejectsCrossTenantAccess(t *testing.T) {
	actor := Actor{TenantID: "ten_a", Role: RoleAdmin, Scopes: []string{"sources:read"}}
	if !Can(actor, "sources:read", "ten_a") {
		t.Fatal("expected same-tenant access")
	}
	if Can(actor, "sources:read", "ten_b") {
		t.Fatal("expected cross-tenant access to be rejected")
	}
}

func TestPolicyRequiresScope(t *testing.T) {
	actor := Actor{TenantID: "ten_a", Role: RoleDeveloper, Scopes: []string{"events:read"}}
	if Can(actor, "sources:write", "ten_a") {
		t.Fatal("missing scope must be rejected")
	}
}

func TestPolicyLimitsOwnerAPIKeysByScope(t *testing.T) {
	actor := Actor{TenantID: "ten_a", Role: RoleOwner, Scopes: []string{"events:read"}}
	if !Can(actor, "events:read", "ten_a") {
		t.Fatal("expected owner key to use granted scope")
	}
	if Can(actor, "events:raw", "ten_a") {
		t.Fatal("owner API key without raw scope must not read raw payloads")
	}
}

func TestPolicyAllowsOperatorOpsReadWithScope(t *testing.T) {
	actor := Actor{TenantID: "ten_a", Role: RoleOperator, Scopes: []string{"ops:read"}}
	if !Can(actor, "ops:read", "ten_a") {
		t.Fatal("operator with ops scope should read operational status")
	}
}

func TestPolicyAllowsOperatorOpsWriteWithScope(t *testing.T) {
	actor := Actor{TenantID: "ten_a", Role: RoleOperator, Scopes: []string{"ops:write"}}
	if !Can(actor, "ops:write", "ten_a") {
		t.Fatal("operator with ops:write scope should manage alert rules and firings")
	}
}

func TestPolicyRoleStillRestrictsScopedKeys(t *testing.T) {
	actor := Actor{TenantID: "ten_a", Role: RoleAuditor, Scopes: []string{"*"}}
	if !Can(actor, "audit:read", "ten_a") {
		t.Fatal("auditor should read audit events")
	}
	if Can(actor, "sources:write", "ten_a") {
		t.Fatal("wildcard scope must not bypass role restrictions")
	}
}
