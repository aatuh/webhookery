package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestMetricsRollupMigrationAndStoreAreTenantScoped(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/018_metrics_rollups.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(up) + "\n" + string(store)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS metrics_rollups",
		"tenant_id text NOT NULL REFERENCES tenants(id)",
		"UNIQUE (tenant_id, metric_name, bucket_start, dimensions_hash)",
		"func (s *Store) RefreshMetricsRollups",
		"WHERE tenant_id=$1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics rollup persistence missing %q", want)
		}
	}
}
