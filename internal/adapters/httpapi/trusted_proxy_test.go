package httpapi

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestSessionRemoteAddrIgnoresForwardedForWithoutTrustedProxy(t *testing.T) {
	server := NewServer(ServerConfig{})
	req := httptest.NewRequest("GET", "/v1/auth/oidc/callback", nil)
	req.RemoteAddr = "203.0.113.10:4231"
	req.Header.Set("X-Forwarded-For", "198.51.100.25")

	if got := server.remoteAddr(req); got != req.RemoteAddr {
		t.Fatalf("remote addr=%q want untrusted peer address %q", got, req.RemoteAddr)
	}
}

func TestSessionRemoteAddrUsesForwardedForFromTrustedProxy(t *testing.T) {
	trusted := netip.MustParsePrefix("10.0.0.0/8")
	server := NewServer(ServerConfig{TrustedProxyCIDRs: []netip.Prefix{trusted}})
	req := httptest.NewRequest("GET", "/v1/auth/oidc/callback", nil)
	req.RemoteAddr = "10.0.0.5:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.25, 10.0.0.5")

	if got := server.remoteAddr(req); got != "198.51.100.25" {
		t.Fatalf("remote addr=%q want trusted forwarded client IP", got)
	}
}

func TestSessionRemoteAddrFallsBackOnInvalidForwardedFor(t *testing.T) {
	trusted := netip.MustParsePrefix("10.0.0.0/8")
	server := NewServer(ServerConfig{TrustedProxyCIDRs: []netip.Prefix{trusted}})
	req := httptest.NewRequest("GET", "/v1/auth/oidc/callback", nil)
	req.RemoteAddr = "10.0.0.5:443"
	req.Header.Set("X-Forwarded-For", "not-an-ip")

	if got := server.remoteAddr(req); got != req.RemoteAddr {
		t.Fatalf("remote addr=%q want fallback peer address %q", got, req.RemoteAddr)
	}
}
