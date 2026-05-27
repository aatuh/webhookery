package ssrf

import (
	"context"
	"errors"
	"net/netip"
	"strings"
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

func TestValidateURLRejectsAddressAndParserEdgeCases(t *testing.T) {
	validator := Validator{Resolver: StaticResolver{
		"localhost":            {netip.MustParseAddr("127.0.0.1")},
		"loopback.example.com": {netip.MustParseAddr("::1")},
	}}
	tests := []string{
		"https://localhost/hook",
		"https://loopback.example.com/hook",
		"https://10.0.0.1/hook",
		"https://[fd00::1]/hook",
		"https://[fe80::1]/hook",
		"https://169.254.169.254/latest/meta-data",
		"https://[::ffff:169.254.169.254]/latest/meta-data",
		"https://0177.0.0.1/hook",
		"gopher://customer.example.com/hook",
		"ftp://customer.example.com/hook",
	}
	for _, rawURL := range tests {
		t.Run(rawURL, func(t *testing.T) {
			result := validator.Validate(context.Background(), rawURL, DefaultPolicy())
			if result.Allowed {
				t.Fatalf("expected %q to be blocked", rawURL)
			}
			if len(result.BlockedReasons) == 0 {
				t.Fatalf("expected blocked reason for %q", rawURL)
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

func TestPinnedDialerBlocksDNSRebindingAfterInitialValidation(t *testing.T) {
	initial := Validator{Resolver: StaticResolver{
		"customer.example.com": {netip.MustParseAddr("93.184.216.34")},
	}}
	if result := initial.Validate(context.Background(), "https://customer.example.com/webhooks", DefaultPolicy()); !result.Allowed {
		t.Fatalf("expected initial endpoint validation to allow public address: %+v", result)
	}

	dialer := PinnedDialer{Resolver: StaticResolver{
		"customer.example.com": {netip.MustParseAddr("10.0.0.10")},
	}, Policy: DefaultPolicy()}
	_, err := dialer.DialContext(context.Background(), "tcp", "customer.example.com:443")
	var policyErr PolicyError
	if err == nil || !strings.Contains(err.Error(), "blocked_ip_range") {
		t.Fatalf("expected delivery-time rebinding block, got %v", err)
	}
	if !errors.As(err, &policyErr) {
		t.Fatalf("expected typed policy error, got %T", err)
	}
}
