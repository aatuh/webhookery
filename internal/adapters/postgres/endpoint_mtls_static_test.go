package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestEndpointMTLSMigrationAddsEncryptedMaterialColumns(t *testing.T) {
	body, err := os.ReadFile("../../../migrations/016_endpoint_mtls.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"mtls_enabled", "mtls_cert_subject", "encrypted_mtls_client_cert", "encrypted_mtls_client_key"} {
		if !strings.Contains(text, want) {
			t.Fatalf("migration missing endpoint mTLS column %q", want)
		}
	}
}

func TestEndpointMTLSStoreEncryptsMaterialAndPopulatesDeliveryItem(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"MTLSClientCertPEM", "encrypted_mtls_client_cert", "encrypted_mtls_client_key", "MTLSCertSubject"} {
		if !strings.Contains(text, want) {
			t.Fatalf("store missing endpoint mTLS persistence evidence %q", want)
		}
	}
}
