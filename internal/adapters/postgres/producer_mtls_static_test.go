package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestProducerMTLSMigrationAndStoreKeepCertificateMetadataOnly(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/025_producer_mtls.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(up) + "\n" + string(store)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS producer_mtls_identities",
		"tenant_id text NOT NULL REFERENCES tenants(id)",
		"certificate_fingerprint_sha256 text NOT NULL",
		"cert_subject text NOT NULL",
		"func (s *Store) CreateProducerMTLSIdentity",
		"func (s *Store) AuthenticateProducerMTLSIdentity",
		"WHERE tenant_id=$1",
		"producer_mtls_identity.created",
		"producer_mtls_identity.disabled",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("producer mTLS persistence missing %q", want)
		}
	}
	for _, forbidden := range []string{"private_key", "encrypted_key", "certificate_pem text"} {
		if strings.Contains(string(up), forbidden) {
			t.Fatalf("producer mTLS migration stores unsafe material marker %q", forbidden)
		}
	}
}
