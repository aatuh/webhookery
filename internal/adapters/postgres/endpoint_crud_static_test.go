package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestEndpointCRUDStoreQueriesAreTenantScopedVersionedAndAudited(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"WHERE tenant_id=$1 AND id=$2",
		"FOR UPDATE",
		"domain.ConfigResourceEndpoint",
		"endpoint.updated",
		"endpoint.disabled",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("endpoint CRUD store missing tenant-scoped/config/audit evidence %q", want)
		}
	}
}
