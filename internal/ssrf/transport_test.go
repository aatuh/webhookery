package ssrf

import (
	"context"
	"errors"
	"net"
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
