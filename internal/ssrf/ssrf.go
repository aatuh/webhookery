package ssrf

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

type Policy struct {
	AllowHTTP       bool
	AllowIPLiteral  bool
	AllowedPorts    map[string]bool
	AllowedCIDRs    []netip.Prefix
	AllowPrivateNet bool
}

func DefaultPolicy() Policy {
	return Policy{AllowedPorts: map[string]bool{"": true, "443": true}}
}

type Result struct {
	Allowed        bool     `json:"allowed"`
	NormalizedURL  string   `json:"normalized_url,omitempty"`
	ResolvedIPs    []string `json:"resolved_ips,omitempty"`
	BlockedReasons []string `json:"blocked_reasons"`
}

type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]netip.Addr, error)
}

type NetResolver struct{}

func (NetResolver) LookupIPAddr(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip.IP); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out, nil
}

type StaticResolver map[string][]netip.Addr

func (s StaticResolver) LookupIPAddr(_ context.Context, host string) ([]netip.Addr, error) {
	return s[strings.ToLower(host)], nil
}

type Validator struct {
	Resolver Resolver
}

func (v Validator) Validate(ctx context.Context, rawURL string, policy Policy) Result {
	var blocked []string
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return Result{BlockedReasons: []string{"invalid_url"}}
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && (scheme != "http" || !policy.AllowHTTP) {
		blocked = append(blocked, "blocked_scheme")
	}
	if parsed.User != nil {
		blocked = append(blocked, "embedded_credentials")
	}
	host := parsed.Hostname()
	if host == "" {
		blocked = append(blocked, "empty_host")
	}
	if !policy.AllowedPorts[parsed.Port()] {
		blocked = append(blocked, "blocked_port")
	}

	asciiHost := strings.TrimSuffix(strings.ToLower(host), ".")
	if asciiHost != "" {
		ascii, err := idna.Lookup.ToASCII(asciiHost)
		if err != nil {
			blocked = append(blocked, "invalid_host")
		} else {
			asciiHost = ascii
		}
	}

	var addrs []netip.Addr
	if addr, err := netip.ParseAddr(asciiHost); err == nil {
		if !policy.AllowIPLiteral {
			blocked = append(blocked, "ip_literal_blocked")
		}
		addrs = append(addrs, addr.Unmap())
	} else if asciiHost != "" {
		resolver := v.Resolver
		if resolver == nil {
			resolver = NetResolver{}
		}
		resolved, err := resolver.LookupIPAddr(ctx, asciiHost)
		if err != nil || len(resolved) == 0 {
			blocked = append(blocked, "dns_resolution_failed")
		}
		for _, addr := range resolved {
			addrs = append(addrs, addr.Unmap())
		}
	}
	for _, addr := range addrs {
		if blockedAddr(addr, policy) {
			blocked = append(blocked, "blocked_ip_range")
			break
		}
	}

	resolved := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		resolved = append(resolved, addr.String())
	}
	if len(blocked) > 0 {
		return Result{ResolvedIPs: resolved, BlockedReasons: dedupe(blocked)}
	}
	parsed.Scheme = scheme
	parsed.Host = asciiHost
	if port := parsed.Port(); port != "" {
		parsed.Host = net.JoinHostPort(asciiHost, port)
	}
	return Result{Allowed: true, NormalizedURL: parsed.String(), ResolvedIPs: resolved}
}

func blockedAddr(addr netip.Addr, policy Policy) bool {
	if policy.AllowPrivateNet {
		for _, p := range policy.AllowedCIDRs {
			if p.Contains(addr) {
				return false
			}
		}
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if addr == netip.MustParseAddr("169.254.169.254") {
		return true
	}
	if addr.Is6() && strings.HasPrefix(addr.String(), "fd00:ec2::254") {
		return true
	}
	return addr.IsGlobalUnicast() && isReserved(addr)
}

func isReserved(addr netip.Addr) bool {
	for _, cidr := range reservedCIDRs {
		if cidr.Contains(addr) {
			return true
		}
	}
	return false
}

var reservedCIDRs = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
