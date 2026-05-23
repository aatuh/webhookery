package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestRouteCRUDStoreQueriesAreTenantScopedVersionedAndAudited(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"FROM routes WHERE tenant_id=$1 AND id=$2",
		"FOR UPDATE",
		"domain.ConfigResourceRoute",
		"route.updated",
		"route.inactivated",
		"SELECT state FROM sources WHERE tenant_id=$1 AND id=$2",
		"SELECT state FROM endpoints WHERE tenant_id=$1 AND id=$2",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("route CRUD store missing tenant-scoped/config/audit evidence %q", want)
		}
	}
}
