package ssrf

import (
	"context"
	"net/netip"
	"testing"
)

func TestValidateURLRejectsPrivateResolvedAddress(t *testing.T) {
	validator := Validator{Resolver: StaticResolver{
		"internal.example.com": {netip.MustParseAddr("10.0.0.10")},
	}}

	result := validator.Validate(context.Background(), "https://internal.example.com/webhook", DefaultPolicy())
	if result.Allowed {
		t.Fatal("private resolved address must be blocked")
	}
	if result.BlockedReasons[0] != "blocked_ip_range" {
		t.Fatalf("unexpected blocked reason: %v", result.BlockedReasons)
	}
}

func TestValidateURLRejectsCredentialsAndHTTP(t *testing.T) {
	validator := Validator{Resolver: StaticResolver{}}
	for _, rawURL := range []string{
		"http://example.com/webhook",
		"https://user:pass@example.com/webhook",
		"file:///etc/passwd",
	} {
		t.Run(rawURL, func(t *testing.T) {
			result := validator.Validate(context.Background(), rawURL, DefaultPolicy())
			if result.Allowed {
				t.Fatalf("expected %q to be blocked", rawURL)
			}
		})
	}
}

func TestValidateURLAllowsPublicHTTPS(t *testing.T) {
	validator := Validator{Resolver: StaticResolver{
		"customer.example.com": {netip.MustParseAddr("93.184.216.34")},
	}}
	result := validator.Validate(context.Background(), "https://customer.example.com/webhooks", DefaultPolicy())
	if !result.Allowed {
		t.Fatalf("expected public https URL to be allowed: %v", result.BlockedReasons)
	}
}
