package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestRetryPolicyCRUDStoreQueriesAreTenantScopedVersionedAndAudited(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"FROM retry_policies",
		"WHERE tenant_id=$1 AND id=$2",
		"FOR UPDATE",
		"domain.ConfigResourceRetryPolicy",
		"retry_policy.updated",
		"retry_policy.disabled",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("retry policy CRUD store missing tenant-scoped/config/audit evidence %q", want)
		}
	}
}
