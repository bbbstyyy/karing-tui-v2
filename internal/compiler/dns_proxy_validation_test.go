package compiler

import (
	"errors"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCompileNativeConfigRejectsForgedProxyDNSRoutePairs(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "proxy.example"})
	compiled, err := CompileRouting(domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID: "proxy-group", Layer: domain.LayerCustom, Order: 1, Match: &match,
			Binding: domain.RouteBinding{Enabled: true, Target: domain.TargetRef{Kind: domain.TargetCurrentSelected}},
		}},
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}, input.Targets)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := CompileRuntimeDNS(domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{ID: "out", Role: domain.DNSRoleOutbound, Transport: domain.DNSTransportUDP, Server: "192.0.2.53", Port: 53},
			{ID: "proxy", Role: domain.DNSRoleProxy, Transport: domain.DNSTransportTCP, Server: "198.51.100.53", Port: 53},
		},
		OutboundProfileID: "out",
		ProxyProfileID:    "proxy",
	}, input.Targets)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindProxyTargetDNSRouting(BoundRouting{CompiledRouting: compiled}, dns)
	if err != nil {
		t.Fatal(err)
	}
	input.DNS = dns
	input.Routing = bound
	if _, err := CompileNativeConfig(input); err != nil {
		t.Fatalf("untampered Proxy DNS route rejected: %v", err)
	}
	if len(bound.Rules) < 14 || len(bound.SourceMap) != 3 {
		t.Fatalf("unexpected route fixture: rules=%d source-map=%d", len(bound.Rules), len(bound.SourceMap))
	}

	cases := []struct {
		name   string
		mutate func(*BoundRouting)
	}{
		{"selected resolver spoofed", func(b *BoundRouting) { b.Rules[1].Server = "dns-out" }},
		{"selected route silently direct", func(b *BoundRouting) { b.Rules[2].Outbound = input.Targets.DirectTag }},
		{"selected resolve predicates differ", func(b *BoundRouting) { b.Rules[1].ClashMode = "Global" }},
		{"global resolve omitted", func(b *BoundRouting) { b.Rules[4].Action = "route" }},
		{"global mode target altered", func(b *BoundRouting) { b.Rules[5].Outbound = input.Targets.DirectTag }},
		{"global no private target altered", func(b *BoundRouting) { b.Rules[7].Outbound = input.Targets.DirectTag }},
		{"user resolver wrong", func(b *BoundRouting) { b.Rules[9].Server = "dns-out" }},
		{"user route changed", func(b *BoundRouting) { b.Rules[10].Outbound = input.Targets.DirectTag }},
		{"user predicates changed", func(b *BoundRouting) { b.Rules[9].Domain = []string{"other.example"} }},
		{"missing user resolve evidence", func(b *BoundRouting) { b.SourceMap = b.SourceMap[1:] }},
		{"wrong user resolve index", func(b *BoundRouting) { b.SourceMap[0].RuleIndex = 8 }},
		{"wrong user route metadata", func(b *BoundRouting) { b.SourceMap[1].Outbound = "out-unrelated" }},
		{"wrong user source target", func(b *BoundRouting) { b.SourceMap[0].Target = domain.TargetRef{Kind: domain.TargetDirect} }},
		{"source map rule index out of range", func(b *BoundRouting) { b.SourceMap[0].RuleIndex = len(b.Rules) }},
		{"orphan extra proxy resolve", func(b *BoundRouting) {
			b.SourceMap = append(b.SourceMap, RouteSourceMapEntry{
				RuleIndex: 8, GroupID: "orphan", Action: "resolve",
				Server: dns.ProxyResolverTag, Target: domain.TargetRef{Kind: domain.TargetCurrentSelected},
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invalid := input
			invalid.Routing = cloneBoundRouting(bound)
			tc.mutate(&invalid.Routing)
			if _, err := CompileNativeConfig(invalid); !errors.Is(err, ErrNativeConfigClosure) {
				t.Fatalf("invalid Proxy DNS route pair accepted: %v", err)
			}
		})
	}
}
