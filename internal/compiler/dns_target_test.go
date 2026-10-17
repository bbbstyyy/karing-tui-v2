package compiler

import (
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCompileRuntimeDNSClosesOutboundDirectAndProxyRoles(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{
				ID:        "bootstrap",
				Role:      domain.DNSRoleBootstrap,
				Transport: domain.DNSTransportUDP,
				Server:    "192.0.2.53",
				Port:      53,
			},
			{
				ID:                 "outbound",
				Role:               domain.DNSRoleOutbound,
				Transport:          domain.DNSTransportTCP,
				Server:             "outbound.example.com",
				Port:               53,
				BootstrapProfileID: "bootstrap",
			},
			{
				ID:        "direct",
				Role:      domain.DNSRoleDirect,
				Transport: domain.DNSTransportUDP,
				Server:    "198.51.100.53",
				Port:      53,
			},
			{
				ID:                 "proxy",
				Role:               domain.DNSRoleProxy,
				Transport:          domain.DNSTransportTCP,
				Server:             "proxy-dns.example.com",
				Port:               53,
				BootstrapProfileID: "bootstrap",
			},
			{
				ID:           "unused-group",
				Role:         domain.DNSRoleGroup,
				Transport:    domain.DNSTransportUDP,
				Server:       "203.0.113.53",
				Port:         53,
				DetourTarget: domain.TargetRef{Kind: domain.TargetDirect},
			},
		},
		OutboundProfileID: "outbound",
		DirectProfileID:   "direct",
		ProxyProfileID:    "proxy",
	}

	compiled, err := CompileRuntimeDNS(plan, targets)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := compiled.ProfileBindings, []DNSProfileBinding{
		{ProfileID: "bootstrap", RuntimeTag: stableDNSTag("bootstrap")},
		{ProfileID: "outbound", RuntimeTag: stableDNSTag("outbound")},
		{ProfileID: "direct", RuntimeTag: stableDNSTag("direct")},
		{ProfileID: "proxy", RuntimeTag: stableDNSTag("proxy")},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("profile bindings = %#v, want %#v", got, want)
	}
	if compiled.OutboundResolverTag != stableDNSTag("outbound") ||
		compiled.DirectResolverTag != stableDNSTag("direct") ||
		compiled.ProxyResolverTag != stableDNSTag("proxy") {
		t.Fatalf("resolver tags = outbound:%q direct:%q proxy:%q", compiled.OutboundResolverTag, compiled.DirectResolverTag, compiled.ProxyResolverTag)
	}
	if len(compiled.Servers) != 4 {
		t.Fatalf("servers = %d, want bootstrap + outbound + direct + proxy", len(compiled.Servers))
	}
	if compiled.Servers[0].Detour != "" ||
		compiled.Servers[1].Detour != "" ||
		compiled.Servers[2].Detour != "" {
		t.Fatalf("bootstrap/outbound/direct DNS unexpectedly use detours: %+v", compiled.Servers[:3])
	}
	if compiled.Servers[3].Detour != targets.CurrentSelectedTag {
		t.Fatalf("proxy DNS detour = %q, want %q", compiled.Servers[3].Detour, targets.CurrentSelectedTag)
	}
	if compiled.Servers[3].DomainResolver != stableDNSTag("bootstrap") {
		t.Fatalf("proxy DNS bootstrap resolver = %q", compiled.Servers[3].DomainResolver)
	}
	for _, binding := range compiled.ProfileBindings {
		if binding.ProfileID == "unused-group" {
			t.Fatal("unused Group DNS leaked into runtime closure")
		}
	}
}

func TestCompileRuntimeDNSDeduplicatesSharedBootstrap(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{
				ID:        "bootstrap",
				Role:      domain.DNSRoleBootstrap,
				Transport: domain.DNSTransportUDP,
				Server:    "192.0.2.53",
				Port:      53,
			},
			{
				ID:                 "outbound",
				Role:               domain.DNSRoleOutbound,
				Transport:          domain.DNSTransportTCP,
				Server:             "outbound.example.com",
				Port:               53,
				BootstrapProfileID: "bootstrap",
			},
			{
				ID:                 "direct",
				Role:               domain.DNSRoleDirect,
				Transport:          domain.DNSTransportTCP,
				Server:             "direct.example.com",
				Port:               53,
				BootstrapProfileID: "bootstrap",
			},
			{
				ID:                 "proxy",
				Role:               domain.DNSRoleProxy,
				Transport:          domain.DNSTransportTCP,
				Server:             "proxy.example.com",
				Port:               53,
				BootstrapProfileID: "bootstrap",
			},
		},
		OutboundProfileID: "outbound",
		DirectProfileID:   "direct",
		ProxyProfileID:    "proxy",
	}
	compiled, err := CompileRuntimeDNS(plan, targets)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, server := range compiled.Servers {
		if server.Tag == stableDNSTag("bootstrap") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("shared bootstrap emitted %d times, want 1", count)
	}
}

func TestCompileRuntimeDNSClosesFallbackRole(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{
				ID:        "outbound",
				Role:      domain.DNSRoleOutbound,
				Transport: domain.DNSTransportUDP,
				Server:    "192.0.2.53",
				Port:      53,
			},
			{
				ID:        "bootstrap",
				Role:      domain.DNSRoleBootstrap,
				Transport: domain.DNSTransportUDP,
				Server:    "198.51.100.53",
				Port:      53,
			},
			{
				ID:                 "fallback",
				Role:               domain.DNSRoleFallback,
				Transport:          domain.DNSTransportTCP,
				Server:             "fallback.example.com",
				Port:               53,
				BootstrapProfileID: "bootstrap",
			},
		},
		OutboundProfileID: "outbound",
		FallbackProfileID: "fallback",
	}
	compiled, err := CompileRuntimeDNS(plan, targets)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.FallbackResolverTag != stableDNSTag("fallback") {
		t.Fatalf("fallback resolver tag = %q, want %q", compiled.FallbackResolverTag, stableDNSTag("fallback"))
	}
	if len(compiled.Servers) != 3 {
		t.Fatalf("servers = %d, want outbound + bootstrap + fallback", len(compiled.Servers))
	}
	fallback := compiled.Servers[2]
	if fallback.Tag != compiled.FallbackResolverTag ||
		fallback.Detour != "" ||
		fallback.DomainResolver != stableDNSTag("bootstrap") {
		t.Fatalf("unexpected fallback DNS server: %+v", fallback)
	}
}

func TestCompileOutboundDNSRemainsNarrowCompatibilitySlice(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{
				ID:        "outbound",
				Role:      domain.DNSRoleOutbound,
				Transport: domain.DNSTransportUDP,
				Server:    "192.0.2.53",
				Port:      53,
			},
			{
				ID:        "direct",
				Role:      domain.DNSRoleDirect,
				Transport: domain.DNSTransportUDP,
				Server:    "198.51.100.53",
				Port:      53,
			},
			{
				ID:        "proxy",
				Role:      domain.DNSRoleProxy,
				Transport: domain.DNSTransportUDP,
				Server:    "203.0.113.53",
				Port:      53,
			},
		},
		OutboundProfileID: "outbound",
		DirectProfileID:   "direct",
		ProxyProfileID:    "proxy",
	}
	compiled, err := CompileOutboundDNS(plan, targets)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.DirectResolverTag != "" || compiled.ProxyResolverTag != "" || len(compiled.Servers) != 1 {
		t.Fatalf("legacy outbound-only compiler widened closure: %+v", compiled)
	}
}
