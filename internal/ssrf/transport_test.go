package ssrf

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
)

func TestPinnedDialerBlocksDNSRebindingAtDialTime(t *testing.T) {
	preflight := Validator{Resolver: StaticResolver{
		"customer.example.com": {netip.MustParseAddr("93.184.216.34")},
	}}
	result := preflight.Validate(context.Background(), "https://customer.example.com/webhook", DefaultPolicy())
	if !result.Allowed {
		t.Fatalf("expected preflight validation to allow public DNS answer: %v", result.BlockedReasons)
	}

	dialer := PinnedDialer{
		Resolver: StaticResolver{
			"customer.example.com": {netip.MustParseAddr("10.0.0.10")},
		},
		Policy: DefaultPolicy(),
		Dialer: &capturingDialer{},
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "customer.example.com:443"); err == nil {
		t.Fatal("dial-time private DNS answer must be blocked")
	}
}

func TestPinnedDialerBlocksMetadataAndIPv4MappedIPv6(t *testing.T) {
	tests := []struct {
		name string
		addr netip.Addr
	}{
		{name: "metadata", addr: netip.MustParseAddr("169.254.169.254")},
		{name: "ipv4 mapped metadata", addr: netip.MustParseAddr("::ffff:169.254.169.254")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := &capturingDialer{}
			dialer := PinnedDialer{
				Resolver: StaticResolver{"customer.example.com": {tt.addr}},
				Policy:   DefaultPolicy(),
				Dialer:   capture,
			}
			if _, err := dialer.DialContext(context.Background(), "tcp", "customer.example.com:443"); err == nil {
				t.Fatal("metadata address must be blocked")
			}
			if capture.called {
				t.Fatal("blocked address must not reach the network dialer")
			}
		})
	}
}

func TestPinnedDialerNormalizesIDNAHostBeforeResolving(t *testing.T) {
	capture := &capturingDialer{err: errStopAfterDial}
	dialer := PinnedDialer{
		Resolver: StaticResolver{"xn--bcher-kva.example": {netip.MustParseAddr("93.184.216.34")}},
		Policy:   DefaultPolicy(),
		Dialer:   capture,
	}
	_, err := dialer.DialContext(context.Background(), "tcp", "bücher.example:443")
	if !errors.Is(err, errStopAfterDial) {
		t.Fatalf("expected fake dialer error after allowed pinned dial, got %v", err)
	}
	if capture.address != "93.184.216.34:443" {
		t.Fatalf("expected dial to pinned public IP, got %q", capture.address)
	}
}

func TestPinnedDialerRejectsMixedPublicAndPrivateAnswers(t *testing.T) {
	capture := &capturingDialer{}
	dialer := PinnedDialer{
		Resolver: StaticResolver{
			"customer.example.com": {
				netip.MustParseAddr("93.184.216.34"),
				netip.MustParseAddr("10.0.0.10"),
			},
		},
		Policy: DefaultPolicy(),
		Dialer: capture,
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "customer.example.com:443"); err == nil {
		t.Fatal("mixed public/private DNS answers must be blocked")
	}
	if capture.called {
		t.Fatal("mixed blocked answers must not reach the network dialer")
	}
}

func TestPolicyErrorFormatsGenericAndSpecificReasons(t *testing.T) {
	if got := (PolicyError{}).Error(); got != "ssrf policy blocked" {
		t.Fatalf("unexpected generic policy error %q", got)
	}
	err := PolicyError{Reasons: []string{"blocked_port", "blocked_ip_range"}}
	if got := err.Error(); got != "ssrf policy blocked: blocked_port,blocked_ip_range" {
		t.Fatalf("unexpected specific policy error %q", got)
	}
}

func TestNewPinnedTransportDisablesProxyAndClearsServerName(t *testing.T) {
	base := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{ServerName: "customer.example.com", MinVersion: tls.VersionTLS13},
	}

	transport := NewPinnedTransport(base, StaticResolver{}, DefaultPolicy())
	if transport == base {
		t.Fatal("expected transport clone")
	}
	if transport.Proxy != nil {
		t.Fatal("pinned egress transport must disable proxy use")
	}
	if transport.DialContext == nil || transport.DialTLSContext != nil {
		t.Fatalf("expected pinned plain dialer and no custom TLS dialer, got %+v", transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.ServerName != "" || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected TLS config clone with cleared server name, got %+v", transport.TLSClientConfig)
	}
	if base.TLSClientConfig.ServerName != "customer.example.com" {
		t.Fatal("base transport TLS config should not be mutated")
	}
}

func TestPinnedDialerRejectsInvalidDialInputsBeforeNetwork(t *testing.T) {
	tests := []struct {
		name    string
		address string
		policy  Policy
		reason  string
	}{
		{name: "missing port", address: "customer.example.com", policy: DefaultPolicy(), reason: "invalid_dial_address"},
		{name: "blocked port", address: "customer.example.com:8080", policy: DefaultPolicy(), reason: "blocked_port"},
		{name: "invalid host", address: "\x00:443", policy: DefaultPolicy(), reason: "invalid_host"},
		{name: "unresolved host", address: "missing.example.com:443", policy: DefaultPolicy(), reason: "dns_resolution_failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := &capturingDialer{}
			dialer := PinnedDialer{Resolver: StaticResolver{}, Policy: tt.policy, Dialer: capture}
			_, err := dialer.DialContext(context.Background(), "tcp", tt.address)
			if err == nil || !errors.As(err, new(PolicyError)) || !containsReason(err, tt.reason) {
				t.Fatalf("expected policy reason %q, got %v", tt.reason, err)
			}
			if capture.called {
				t.Fatal("invalid dial input must not reach network dialer")
			}
		})
	}
}

func TestPinnedDialerHandlesIPLiteralPolicy(t *testing.T) {
	capture := &capturingDialer{err: errStopAfterDial}
	dialer := PinnedDialer{
		Policy: Policy{
			AllowIPLiteral: true,
			AllowedPorts:   map[string]bool{"443": true},
		},
		Dialer: capture,
	}
	_, err := dialer.DialContext(context.Background(), "tcp", "93.184.216.34:443")
	if !errors.Is(err, errStopAfterDial) {
		t.Fatalf("expected fake dialer error after allowed IP literal, got %v", err)
	}
	if capture.address != "93.184.216.34:443" {
		t.Fatalf("expected IP literal dial address, got %q", capture.address)
	}

	blocked := PinnedDialer{Policy: DefaultPolicy(), Dialer: &capturingDialer{}}
	if _, err := blocked.DialContext(context.Background(), "tcp", "93.184.216.34:443"); err == nil || !containsReason(err, "ip_literal_blocked") {
		t.Fatalf("expected default policy to block IP literal, got %v", err)
	}
}

func TestBlockedAddrHonorsExplicitPrivateCIDRPolicy(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.10")
	if !blockedAddr(addr, DefaultPolicy()) {
		t.Fatal("private address should be blocked by default")
	}
	if blockedAddr(addr, Policy{AllowPrivateNet: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}) {
		t.Fatal("explicitly allowed private CIDR should not be blocked")
	}
}

var errStopAfterDial = errors.New("stop after dial")

type capturingDialer struct {
	called  bool
	network string
	address string
	err     error
}

func (d *capturingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.called = true
	d.network = network
	d.address = address
	if d.err != nil {
		return nil, d.err
	}
	return nil, errStopAfterDial
}

func containsReason(err error, reason string) bool {
	var policyErr PolicyError
	if !errors.As(err, &policyErr) {
		return false
	}
	for _, got := range policyErr.Reasons {
		if got == reason {
			return true
		}
	}
	return false
}
