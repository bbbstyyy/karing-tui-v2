package compiler

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestBindProxyTargetDNSRoutingExpandsSelectedUserRuleAndFinal(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "example.com"})
	compiled, err := CompileRouting(domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID:    "proxy-domain",
			Layer: domain.LayerCustom,
			Order: 1,
			Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target:  domain.TargetRef{Kind: domain.TargetCurrentSelected},
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetCurrentSelected},
	}, targets)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewRuleSetCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindRuleSetArtifacts(compiled, catalog)
	if err != nil {
		t.Fatal(err)
	}
	proxyTag := stableDNSTag("proxy")
	dns := CompiledDNS{
		Servers: []DNSServerConfig{{
			Type:       "udp",
			Tag:        proxyTag,
			Server:     "192.0.2.53",
			ServerPort: 53,
			Detour:     targets.CurrentSelectedTag,
		}},
		ProxyResolverTag: proxyTag,
	}

	rebound, err := BindProxyTargetDNSRouting(bound, dns)
	if err != nil {
		t.Fatal(err)
	}
	if len(rebound.Rules) != 7 {
		t.Fatalf("rules = %d, want direct + selected resolve/route + group resolve/route + final resolve/route", len(rebound.Rules))
	}
	if rebound.Rules[1].Action != "resolve" || rebound.Rules[1].Server != proxyTag ||
		!reflect.DeepEqual(rebound.Rules[1].Inbound, []string{domain.InboundTagSelected}) {
		t.Fatalf("unexpected Selected resolve: %+v", rebound.Rules[1])
	}
	if rebound.Rules[2].Action != "route" || rebound.Rules[2].Outbound != targets.CurrentSelectedTag {
		t.Fatalf("unexpected Selected route: %+v", rebound.Rules[2])
	}
	if rebound.Rules[3].Action != "resolve" || rebound.Rules[3].Server != proxyTag ||
		rebound.Rules[4].Action != "route" || rebound.Rules[4].Outbound != targets.CurrentSelectedTag {
		t.Fatalf("unexpected user resolve/route pair: %+v / %+v", rebound.Rules[3], rebound.Rules[4])
	}
	if rebound.Rules[5].Action != "resolve" || rebound.Rules[5].Server != proxyTag ||
		rebound.Rules[6].Action != "route" || rebound.Rules[6].Outbound != targets.CurrentSelectedTag {
		t.Fatalf("unexpected FINAL resolve/route pair: %+v / %+v", rebound.Rules[5], rebound.Rules[6])
	}
	if len(rebound.SourceMap) != 4 {
		t.Fatalf("source map entries = %d, want resolve+route for group and FINAL", len(rebound.SourceMap))
	}
	if got := []int{
		rebound.SourceMap[0].RuleIndex,
		rebound.SourceMap[1].RuleIndex,
		rebound.SourceMap[2].RuleIndex,
		rebound.SourceMap[3].RuleIndex,
	}; !reflect.DeepEqual(got, []int{3, 4, 5, 6}) {
		t.Fatalf("source map indexes = %#v", got)
	}
	if rebound.SourceMap[0].Action != "resolve" || rebound.SourceMap[0].Server != proxyTag ||
		rebound.SourceMap[1].Action != "route" || rebound.SourceMap[1].Server != "" ||
		rebound.SourceMap[2].Action != "resolve" || !rebound.SourceMap[2].Final ||
		rebound.SourceMap[3].Action != "route" || !rebound.SourceMap[3].Final {
		t.Fatalf("unexpected source map: %+v", rebound.SourceMap)
	}
	if len(bound.Rules) != 4 || len(bound.SourceMap) != 2 || bound.Rules[1].Action != "route" {
		t.Fatal("proxy DNS binding mutated original routing")
	}
}

func TestBindProxyTargetDNSRoutingLeavesDirectAndBlockRulesUnresolved(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomain, Value: "direct.example"})
	compiled, err := CompileRouting(domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID:    "direct",
			Layer: domain.LayerCustom,
			Order: 1,
			Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target:  domain.TargetRef{Kind: domain.TargetDirect},
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetBlock},
	}, targets)
	if err != nil {
		t.Fatal(err)
	}
	bound := BoundRouting{CompiledRouting: compiled}
	proxyTag := stableDNSTag("proxy")
	rebound, err := BindProxyTargetDNSRouting(bound, CompiledDNS{
		Servers:          []DNSServerConfig{{Type: "udp", Tag: proxyTag, Server: "192.0.2.53", ServerPort: 53, Detour: targets.CurrentSelectedTag}},
		ProxyResolverTag: proxyTag,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rebound.Rules) != len(bound.Rules)+1 {
		t.Fatalf("only Selected synthetic rule should gain resolve: %d -> %d", len(bound.Rules), len(rebound.Rules))
	}
	for _, entry := range rebound.SourceMap {
		if entry.Action == "resolve" {
			t.Fatalf("Direct/BLOCK user rule unexpectedly gained resolve source map: %+v", entry)
		}
	}
}

func TestBindProxyTargetDNSRoutingRejectsIPDependentProxyMatchers(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []domain.MatchExpr{
		domain.Atom(domain.Predicate{Kind: domain.PredicateIPCIDR, CIDR: "203.0.113.0/24"}),
		domain.Atom(domain.Predicate{Kind: domain.PredicateRuleSet, Value: "geoip:cn"}),
	}
	for i, match := range cases {
		compiled, err := CompileRouting(domain.RoutingPlan{
			GeoIP: []domain.RouteGroup{{
				ID:    "ambiguous",
				Layer: domain.LayerGeoIP,
				Order: 1,
				Match: &match,
				Binding: domain.RouteBinding{
					Enabled: true,
					Target:  domain.TargetRef{Kind: domain.TargetCurrentSelected},
				},
			}},
			Final: domain.TargetRef{Kind: domain.TargetDirect},
		}, targets)
		if err != nil {
			t.Fatal(err)
		}
		proxyTag := stableDNSTag("proxy")
		if _, err := BindProxyTargetDNSRouting(BoundRouting{CompiledRouting: compiled}, CompiledDNS{
			Servers:          []DNSServerConfig{{Type: "udp", Tag: proxyTag, Server: "192.0.2.53", ServerPort: 53, Detour: targets.CurrentSelectedTag}},
			ProxyResolverTag: proxyTag,
		}); !errors.Is(err, ErrDNSRouteResolutionAmbiguous) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

func TestBindProxyTargetDNSRoutingRequiresCompiledProxyTag(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileRouting(domain.RoutingPlan{Final: domain.TargetRef{Kind: domain.TargetDirect}}, targets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindProxyTargetDNSRouting(BoundRouting{CompiledRouting: compiled}, CompiledDNS{
		ProxyResolverTag: stableDNSTag("missing"),
	}); !errors.Is(err, ErrDNSClosure) {
		t.Fatalf("missing proxy DNS tag error = %v", err)
	}
}
