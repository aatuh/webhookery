package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMigrationChecksumStable(t *testing.T) {
	sum1 := checksum([]byte("select 1;"))
	sum2 := checksum([]byte("select 1;"))
	if sum1 == "" || sum1 != sum2 {
		t.Fatalf("unstable checksum: %q %q", sum1, sum2)
	}
}

func TestMigrationUndefinedTableClassifier(t *testing.T) {
	if !isUndefinedTable(&pgconn.PgError{Code: "42P01"}) {
		t.Fatal("expected undefined-table pg error to be recognized")
	}
	if !isUndefinedTable(fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "42P01"})) {
		t.Fatal("expected wrapped undefined-table pg error to be recognized")
	}
	for _, err := range []error{
		&pgconn.PgError{Code: "23505"},
		errors.New("not a postgres error"),
		nil,
	} {
		if isUndefinedTable(err) {
			t.Fatalf("unexpected undefined-table match for %v", err)
		}
	}
}
