package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestTenantIsolationEvidenceAuthorityPredicates(t *testing.T) {
	storeBody, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	incidentBody, err := os.ReadFile("incidents.go")
	if err != nil {
		t.Fatal(err)
	}
	storeText := string(storeBody)
	incidentText := string(incidentBody)

	storeRequirements := map[string]string{
		"events export":       "query := `SELECT id FROM events WHERE tenant_id=$1`",
		"deliveries":          "WHERE d.tenant_id=$1",
		"replay jobs":         "replayJobSelectSQL+` WHERE tenant_id=$1",
		"raw payload export":  "WHERE tenant_id=$1 AND event_id=$2",
		"audit chain":         "WHERE c.tenant_id=$1 AND c.sequence BETWEEN $2 AND $3",
		"evidence export":     "FROM evidence_exports\n\t\tWHERE tenant_id=$1 AND id=$2",
		"provider connection": "FROM provider_connections\n\t\tWHERE tenant_id=$1",
	}
	for name, want := range storeRequirements {
		if !strings.Contains(storeText, want) {
			t.Fatalf("%s missing tenant predicate evidence %q", name, want)
		}
	}

	incidentRequirements := map[string]string{
		"incident exists": "SELECT EXISTS (SELECT 1 FROM incidents WHERE tenant_id=$1 AND id=$2)",
		"event exists":    "SELECT EXISTS (SELECT 1 FROM events WHERE tenant_id=$1 AND id=$2)",
	}
	for name, want := range incidentRequirements {
		if !strings.Contains(incidentText, want) {
			t.Fatalf("%s missing same-tenant incident evidence predicate %q", name, want)
		}
	}
}
