package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestSourceCRUDStoreQueriesAreTenantScopedAndAudited(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"WHERE tenant_id=$1 AND id=$2",
		"FOR UPDATE",
		"domain.ConfigResourceSource",
		"source.updated",
		"source.disabled",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("source CRUD store missing tenant-scoped/audit evidence %q", want)
		}
	}
}
