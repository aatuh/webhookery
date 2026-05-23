package postgres

import "testing"

func TestMigrationChecksumStable(t *testing.T) {
	sum1 := checksum([]byte("select 1;"))
	sum2 := checksum([]byte("select 1;"))
	if sum1 == "" || sum1 != sum2 {
		t.Fatalf("unstable checksum: %q %q", sum1, sum2)
	}
}
