package ssrf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type PinnedDialer struct {
	Resolver Resolver
	Policy   Policy
	Dialer   ContextDialer
}

type PolicyError struct {
	Reasons []string
}

func (e PolicyError) Error() string {
	if len(e.Reasons) == 0 {
		return "ssrf policy blocked"
	}
	return "ssrf policy blocked: " + strings.Join(e.Reasons, ",")
}

func NewPinnedTransport(base *http.Transport, resolver Resolver, policy Policy) *http.Transport {
	var transport *http.Transport
	if base != nil {
		transport = base.Clone()
	} else {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	transport.Proxy = nil
	transport.DialContext = PinnedDialer{Resolver: resolver, Policy: policy}.DialContext
	transport.DialTLSContext = nil
	if transport.TLSClientConfig != nil {
		tlsConfig := transport.TLSClientConfig.Clone()
		tlsConfig.ServerName = ""
		transport.TLSClientConfig = tlsConfig
	}
	return transport
}

func (d PinnedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return nil, PolicyError{Reasons: []string{"invalid_dial_address"}}
	}
	policy := d.Policy
	if policy.AllowedPorts == nil {
		policy.AllowedPorts = DefaultPolicy().AllowedPorts
	}
	if !policy.AllowedPorts[port] {
		return nil, PolicyError{Reasons: []string{"blocked_port"}}
	}
	asciiHost, err := normalizedDialHost(host)
	if err != nil {
		return nil, PolicyError{Reasons: []string{"invalid_host"}}
	}
	addrs, err := d.resolve(ctx, asciiHost, policy)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, PolicyError{Reasons: []string{"dns_resolution_failed"}}
	}
	var blocked []string
	for _, addr := range addrs {
		if blockedAddr(addr, policy) {
			blocked = append(blocked, "blocked_ip_range")
		}
	}
	if len(blocked) > 0 {
		return nil, PolicyError{Reasons: dedupe(blocked)}
	}
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0].String(), port))
}

func (d PinnedDialer) resolve(ctx context.Context, host string, policy Policy) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		reasons := []string{}
		if !policy.AllowIPLiteral {
			reasons = append(reasons, "ip_literal_blocked")
		}
		addr = addr.Unmap()
		if blockedAddr(addr, policy) {
			reasons = append(reasons, "blocked_ip_range")
		}
		if len(reasons) > 0 {
			return nil, PolicyError{Reasons: dedupe(reasons)}
		}
		return []netip.Addr{addr}, nil
	}
	resolver := d.Resolver
	if resolver == nil {
		resolver = NetResolver{}
	}
	resolved, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, PolicyError{Reasons: []string{"dns_resolution_failed"}}
	}
	addrs := make([]netip.Addr, 0, len(resolved))
	for _, addr := range resolved {
		if !addr.IsValid() {
			continue
		}
		addrs = append(addrs, addr.Unmap())
	}
	return addrs, nil
}

func normalizedDialHost(host string) (string, error) {
	trimmed := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if trimmed == "" {
		return "", errors.New("empty host")
	}
	if _, err := netip.ParseAddr(trimmed); err == nil {
		return trimmed, nil
	}
	return idna.Lookup.ToASCII(trimmed)
}
