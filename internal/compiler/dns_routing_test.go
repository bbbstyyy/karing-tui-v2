package compiler

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestBindProxyTargetDNSRoutingExpandsSelectedGlobalUserRuleAndFinal(t *testing.T) {
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
	if len(rebound.Rules) != 10 {
		t.Fatalf("rules = %d, want direct + selected/global resolve pairs + direct mode + group/final resolve pairs", len(rebound.Rules))
	}
	if rebound.Rules[1].Action != "resolve" || rebound.Rules[1].Server != proxyTag ||
		!reflect.DeepEqual(rebound.Rules[1].Inbound, []string{domain.InboundTagSelected}) {
		t.Fatalf("unexpected Selected resolve: %+v", rebound.Rules[1])
	}
	if rebound.Rules[2].Action != "route" || rebound.Rules[2].Outbound != targets.CurrentSelectedTag {
		t.Fatalf("unexpected Selected route: %+v", rebound.Rules[2])
	}
	if rebound.Rules[3].Action != "resolve" || rebound.Rules[3].Server != proxyTag ||
		rebound.Rules[3].ClashMode != "Global" ||
		rebound.Rules[4].Action != "route" || rebound.Rules[4].Outbound != targets.CurrentSelectedTag ||
		rebound.Rules[4].ClashMode != "Global" {
		t.Fatalf("unexpected Global resolve/route pair: %+v / %+v", rebound.Rules[3], rebound.Rules[4])
	}
	if rebound.Rules[5].ClashMode != "Direct" || rebound.Rules[5].Outbound != targets.DirectTag {
		t.Fatalf("unexpected Direct mode rule: %+v", rebound.Rules[5])
	}
	if rebound.Rules[6].Action != "resolve" || rebound.Rules[6].Server != proxyTag ||
		rebound.Rules[7].Action != "route" || rebound.Rules[7].Outbound != targets.CurrentSelectedTag {
		t.Fatalf("unexpected user resolve/route pair: %+v / %+v", rebound.Rules[6], rebound.Rules[7])
	}
	if rebound.Rules[8].Action != "resolve" || rebound.Rules[8].Server != proxyTag ||
		rebound.Rules[9].Action != "route" || rebound.Rules[9].Outbound != targets.CurrentSelectedTag {
		t.Fatalf("unexpected FINAL resolve/route pair: %+v / %+v", rebound.Rules[8], rebound.Rules[9])
	}
	if len(rebound.SourceMap) != 4 {
		t.Fatalf("source map entries = %d, want resolve+route for group and FINAL", len(rebound.SourceMap))
	}
	if got := []int{
		rebound.SourceMap[0].RuleIndex,
		rebound.SourceMap[1].RuleIndex,
		rebound.SourceMap[2].RuleIndex,
		rebound.SourceMap[3].RuleIndex,
	}; !reflect.DeepEqual(got, []int{6, 7, 8, 9}) {
		t.Fatalf("source map indexes = %#v", got)
	}
	if rebound.SourceMap[0].Action != "resolve" || rebound.SourceMap[0].Server != proxyTag ||
		rebound.SourceMap[1].Action != "route" || rebound.SourceMap[1].Server != "" ||
		rebound.SourceMap[2].Action != "resolve" || !rebound.SourceMap[2].Final ||
		rebound.SourceMap[3].Action != "route" || !rebound.SourceMap[3].Final {
		t.Fatalf("unexpected source map: %+v", rebound.SourceMap)
	}
	if len(bound.Rules) != 6 || len(bound.SourceMap) != 2 || bound.Rules[1].Action != "route" {
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
	if len(rebound.Rules) != len(bound.Rules)+2 {
		t.Fatalf("Selected and Global synthetic proxy rules should gain resolve: %d -> %d", len(bound.Rules), len(rebound.Rules))
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
