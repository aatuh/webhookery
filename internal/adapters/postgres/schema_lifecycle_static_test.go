package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestSchemaLifecycleStoreQueriesAreTenantScopedVersionedAndAudited(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"FROM event_types WHERE tenant_id=$1 AND name=$2",
		"FROM event_schemas WHERE tenant_id=$1 AND event_type=$2 AND version=$3",
		"FOR UPDATE",
		"domain.ConfigResourceSchema",
		"event_type.updated",
		"event_type.disabled",
		"event_schema.updated",
		"event_schema.retired",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("schema lifecycle store missing tenant-scoped/config/audit evidence %q", want)
		}
	}
}
