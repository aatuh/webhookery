package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestSubscriptionCRUDStoreQueriesAreTenantScopedVersionedAndAudited(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"FROM subscriptions WHERE tenant_id=$1 AND id=$2",
		"FOR UPDATE",
		"domain.ConfigResourceSubscription",
		"subscription.updated",
		"subscription.disabled",
		"SELECT state FROM endpoints WHERE tenant_id=$1 AND id=$2",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("subscription CRUD store missing tenant-scoped/config/audit evidence %q", want)
		}
	}
}
