package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestGenericJWTAdapterMigrationRegistersBuiltinVersion(t *testing.T) {
	body, err := os.ReadFile("../../../migrations/017_generic_jwt_adapter.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"pad_generic_jwt", "generic-jwt", "adv_generic_jwt_v1", "builtin:generic-jwt:v1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("migration missing generic JWT adapter evidence %q", want)
		}
	}
}
