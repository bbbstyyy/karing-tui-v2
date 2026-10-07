package compiler

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCompileNativeConfigBindsDirectAndProxyTargetDNS(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	plan := domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{ID: "outbound", Role: domain.DNSRoleOutbound, Transport: domain.DNSTransportUDP, Server: "192.0.2.53", Port: 53},
			{ID: "direct", Role: domain.DNSRoleDirect, Transport: domain.DNSTransportUDP, Server: "198.51.100.53", Port: 53},
			{ID: "proxy", Role: domain.DNSRoleProxy, Transport: domain.DNSTransportUDP, Server: "203.0.113.53", Port: 53},
		},
		OutboundProfileID: "outbound",
		DirectProfileID:   "direct",
		ProxyProfileID:    "proxy",
	}
	dns, err := CompileRuntimeDNS(plan, input.Targets)
	if err != nil {
		t.Fatal(err)
	}
	routing, err := BindProxyTargetDNSRouting(input.Routing, dns)
	if err != nil {
		t.Fatal(err)
	}
	input.DNS = dns
	input.Routing = routing

	artifact, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Final   string           `json:"final"`
		} `json:"dns"`
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules []RouteRule `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(artifact.JSON, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := decoded.Outbounds[0]["domain_resolver"]; got != dns.DirectResolverTag {
		t.Fatalf("DIRECT domain_resolver = %#v, want %q", got, dns.DirectResolverTag)
	}
	proxyServerFound := false
	for _, server := range decoded.DNS.Servers {
		if server["tag"] == dns.ProxyResolverTag {
			proxyServerFound = true
			if server["detour"] != input.Targets.CurrentSelectedTag {
				t.Fatalf("Proxy DNS detour = %#v, want %q", server["detour"], input.Targets.CurrentSelectedTag)
			}
		}
	}
	if !proxyServerFound {
		t.Fatal("Proxy DNS server missing from native DNS closure")
	}
	if len(decoded.Route.Rules) < 3 ||
		decoded.Route.Rules[1].Action != "resolve" ||
		decoded.Route.Rules[1].Server != dns.ProxyResolverTag ||
		decoded.Route.Rules[2].Action != "route" ||
		decoded.Route.Rules[2].Outbound != input.Targets.CurrentSelectedTag {
		t.Fatalf("Selected resolve/route pair missing: %+v", decoded.Route.Rules)
	}
	if got, want := artifact.Manifest.DNSServerTags[:3], []string{
		dns.OutboundResolverTag,
		dns.DirectResolverTag,
		dns.ProxyResolverTag,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DNS manifest role order = %#v, want %#v", got, want)
	}
}

func TestCompileNativeConfigRejectsProxyDNSWithoutRouteBinding(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	dns, err := CompileRuntimeDNS(domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{ID: "outbound", Role: domain.DNSRoleOutbound, Transport: domain.DNSTransportUDP, Server: "192.0.2.53", Port: 53},
			{ID: "proxy", Role: domain.DNSRoleProxy, Transport: domain.DNSTransportUDP, Server: "203.0.113.53", Port: 53},
		},
		OutboundProfileID: "outbound",
		ProxyProfileID:    "proxy",
	}, input.Targets)
	if err != nil {
		t.Fatal(err)
	}
	input.DNS = dns
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrNativeConfigClosure) {
		t.Fatalf("unbound Proxy DNS error = %v", err)
	}
}

func TestCompileNativeConfigRejectsUnexpectedDNSDetour(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	input.DNS = CompiledDNS{
		Servers: []DNSServerConfig{
			{Type: "udp", Tag: "dns-outbound", Server: "192.0.2.53", ServerPort: 53},
			{Type: "udp", Tag: "dns-proxy", Server: "203.0.113.53", ServerPort: 53, Detour: "out-unknown"},
		},
		OutboundResolverTag: "dns-outbound",
		ProxyResolverTag:    "dns-proxy",
	}
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrNativeConfigClosure) {
		t.Fatalf("unexpected DNS detour error = %v", err)
	}
}


func TestCompileNativeConfigUsesExplicitFallbackAsDNSFinal(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	dns, err := CompileRuntimeDNS(domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{
				ID:        "outbound",
				Role:      domain.DNSRoleOutbound,
				Transport: domain.DNSTransportUDP,
				Server:    "192.0.2.53",
				Port:      53,
			},
			{
				ID:        "fallback",
				Role:      domain.DNSRoleFallback,
				Transport: domain.DNSTransportTCP,
				Server:    "198.51.100.53",
				Port:      53,
			},
		},
		OutboundProfileID: "outbound",
		FallbackProfileID: "fallback",
	}, input.Targets)
	if err != nil {
		t.Fatal(err)
	}
	input.DNS = dns

	artifact, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Final   string           `json:"final"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(artifact.JSON, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.DNS.Final != dns.FallbackResolverTag {
		t.Fatalf("DNS final = %q, want fallback %q", decoded.DNS.Final, dns.FallbackResolverTag)
	}
	if len(decoded.DNS.Servers) != 2 {
		t.Fatalf("DNS servers = %d, want outbound + fallback", len(decoded.DNS.Servers))
	}
	for _, server := range decoded.DNS.Servers {
		if server["tag"] == nativeDNSFailClosedTag {
			t.Fatalf("fail-closed DNS server leaked into explicit fallback closure: %+v", server)
		}
	}
	if got, want := artifact.Manifest.DNSServerTags, []string{
		dns.OutboundResolverTag,
		dns.FallbackResolverTag,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DNS manifest tags = %#v, want %#v", got, want)
	}
}

func TestCompileNativeConfigRejectsMissingFallbackResolver(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	input.DNS = CompiledDNS{
		Servers: []DNSServerConfig{{
			Type:       "udp",
			Tag:        "dns-outbound",
			Server:     "192.0.2.53",
			ServerPort: 53,
		}},
		ProfileBindings: []DNSProfileBinding{{
			ProfileID:  "outbound",
			RuntimeTag: "dns-outbound",
		}},
		OutboundResolverTag: "dns-outbound",
		FallbackResolverTag: "dns-missing",
	}
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrNativeConfigClosure) {
		t.Fatalf("missing fallback resolver error = %v", err)
	}
}
