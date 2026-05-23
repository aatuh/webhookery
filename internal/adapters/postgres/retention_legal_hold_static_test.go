package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestRetentionLegalHoldEvidence(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/014_retention_legal_hold.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"legal_hold", "hold_reason"} {
		if !strings.Contains(string(migration), want) {
			t.Fatalf("migration must include %s", want)
		}
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	storeText := string(store)
	if !strings.Contains(storeText, "WHERE state='active' AND legal_hold=false") {
		t.Fatal("retention worker must skip policies on legal hold")
	}
}
