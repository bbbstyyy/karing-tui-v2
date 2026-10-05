package compiler

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestBindGroupDNSRoutingExpandsResolveRoutePair(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "group.example"})
	compiled, err := CompileRouting(domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID: "group", Layer: domain.LayerCustom, Order: 1, Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true, Target: domain.TargetRef{Kind: domain.TargetCurrentSelected}, DNSProfileID: "group-dns",
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}, targets)
	if err != nil {
		t.Fatal(err)
	}
	tag := stableDNSTag("group-dns")
	dns := CompiledDNS{
		Servers: []DNSServerConfig{{Type: "udp", Tag: tag, Server: "192.0.2.53", ServerPort: 53, Detour: targets.CurrentSelectedTag}},
		GroupBindings: []DNSGroupBinding{{
			GroupID: "group", ProfileID: "group-dns", RuntimeTag: tag, DetourOutbound: targets.CurrentSelectedTag,
		}},
	}
	bound := BoundRouting{CompiledRouting: compiled}
	got, err := BindGroupDNSRouting(bound, dns)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != len(bound.Rules)+1 {
		t.Fatalf("rules = %d, want %d", len(got.Rules), len(bound.Rules)+1)
	}
	if got.Rules[2].Action != "resolve" || got.Rules[2].Server != tag || got.Rules[2].Outbound != "" {
		t.Fatalf("resolve rule = %+v", got.Rules[2])
	}
	if got.Rules[3].Action != "route" || got.Rules[3].Outbound != targets.CurrentSelectedTag {
		t.Fatalf("route rule = %+v", got.Rules[3])
	}
	if len(got.SourceMap) != 3 {
		t.Fatalf("source map = %+v", got.SourceMap)
	}
	if idx := []int{got.SourceMap[0].RuleIndex, got.SourceMap[1].RuleIndex, got.SourceMap[2].RuleIndex}; !reflect.DeepEqual(idx, []int{2, 3, 4}) {
		t.Fatalf("source-map indexes = %#v", idx)
	}
	if got.SourceMap[0].Action != "resolve" || got.SourceMap[0].Server != tag ||
		got.SourceMap[0].DNSProfileID != "group-dns" ||
		got.SourceMap[1].Action != "route" || got.SourceMap[1].DNSProfileID != "group-dns" {
		t.Fatalf("source map = %+v", got.SourceMap)
	}
	if bound.Rules[2].Action != "route" || len(bound.SourceMap) != 2 {
		t.Fatal("binding mutated original routing")
	}
}

func TestBindGroupDNSRoutingRejectsPreResolutionAmbiguity(t *testing.T) {
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
				ID: "ambiguous", Layer: domain.LayerGeoIP, Order: 1, Match: &match,
				Binding: domain.RouteBinding{
					Enabled: true, Target: domain.TargetRef{Kind: domain.TargetDirect}, DNSProfileID: "group-dns",
				},
			}},
			Final: domain.TargetRef{Kind: domain.TargetDirect},
		}, targets)
		if err != nil {
			t.Fatal(err)
		}
		tag := stableDNSTag("group-dns")
		dns := CompiledDNS{
			Servers:       []DNSServerConfig{{Type: "udp", Tag: tag, Server: "192.0.2.53", ServerPort: 53}},
			GroupBindings: []DNSGroupBinding{{GroupID: "ambiguous", ProfileID: "group-dns", RuntimeTag: tag}},
		}
		if _, err := BindGroupDNSRouting(BoundRouting{CompiledRouting: compiled}, dns); !errors.Is(err, ErrDNSRouteResolutionAmbiguous) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

func TestGroupDNSAndProxyDNSDoNotDoubleResolve(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	groupMatch := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "group.example"})
	proxyMatch := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "proxy.example"})
	compiled, err := CompileRouting(domain.RoutingPlan{
		Custom: []domain.RouteGroup{
			{ID: "group", Layer: domain.LayerCustom, Order: 1, Match: &groupMatch, Binding: domain.RouteBinding{
				Enabled: true, Target: domain.TargetRef{Kind: domain.TargetCurrentSelected}, DNSProfileID: "group-dns",
			}},
			{ID: "proxy", Layer: domain.LayerCustom, Order: 2, Match: &proxyMatch, Binding: domain.RouteBinding{
				Enabled: true, Target: domain.TargetRef{Kind: domain.TargetCurrentSelected},
			}},
		},
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}, targets)
	if err != nil {
		t.Fatal(err)
	}
	groupTag := stableDNSTag("group-dns")
	proxyTag := stableDNSTag("proxy-dns")
	dns := CompiledDNS{
		Servers: []DNSServerConfig{
			{Type: "udp", Tag: proxyTag, Server: "192.0.2.53", ServerPort: 53, Detour: targets.CurrentSelectedTag},
			{Type: "udp", Tag: groupTag, Server: "198.51.100.53", ServerPort: 53, Detour: targets.CurrentSelectedTag},
		},
		ProxyResolverTag: proxyTag,
		GroupBindings: []DNSGroupBinding{{
			GroupID: "group", ProfileID: "group-dns", RuntimeTag: groupTag, DetourOutbound: targets.CurrentSelectedTag,
		}},
	}
	bound, err := BindGroupDNSRouting(BoundRouting{CompiledRouting: compiled}, dns)
	if err != nil {
		t.Fatal(err)
	}
	bound, err = BindProxyTargetDNSRouting(bound, dns)
	if err != nil {
		t.Fatal(err)
	}
	groupResolve, proxyResolve := 0, 0
	for _, entry := range bound.SourceMap {
		if entry.Action != "resolve" {
			continue
		}
		switch entry.Server {
		case groupTag:
			groupResolve++
		case proxyTag:
			proxyResolve++
		}
		if entry.GroupID == "group" && entry.Server == proxyTag {
			t.Fatalf("group route received extra Proxy DNS resolve: %+v", entry)
		}
	}
	if groupResolve != 1 || proxyResolve != 1 {
		t.Fatalf("resolve counts = group:%d proxy:%d; map=%+v", groupResolve, proxyResolve, bound.SourceMap)
	}
}
