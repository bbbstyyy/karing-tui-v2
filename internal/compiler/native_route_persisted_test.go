package compiler

import (
	"errors"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestValidatePersistedRouteProvenanceSupportsCompiledGroupAndProxyDNS(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	groupMatch := domain.Atom(domain.Predicate{Kind: domain.PredicateDomain, Value: "group.invalid"})
	proxyMatch := domain.Atom(domain.Predicate{Kind: domain.PredicateDomain, Value: "proxy.invalid"})
	routing, err := CompileRouting(domain.RoutingPlan{
		Custom: []domain.RouteGroup{
			{
				ID: "group", Layer: domain.LayerCustom, Order: 1, Match: &groupMatch,
				Binding: domain.RouteBinding{
					Enabled: true, Target: domain.TargetRef{Kind: domain.TargetDirect},
					DNSProfileID: "group-dns",
				},
			},
			{
				ID: "proxy", Layer: domain.LayerCustom, Order: 2, Match: &proxyMatch,
				Binding: domain.RouteBinding{
					Enabled: true, Target: domain.TargetRef{Kind: domain.TargetCurrentSelected},
				},
			},
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
			{
				Type: "tcp", Tag: proxyTag, Server: "127.0.0.1",
				ServerPort: 5354, Detour: targets.CurrentSelectedTag,
			},
			{
				Type: "tcp", Tag: groupTag, Server: "127.0.0.1",
				ServerPort: 5355, Detour: targets.CurrentSelectedTag,
			},
		},
		ProxyResolverTag: proxyTag,
		GroupBindings: []DNSGroupBinding{{
			GroupID: "group", ProfileID: "group-dns", RuntimeTag: groupTag,
			DetourOutbound: targets.CurrentSelectedTag,
		}},
	}
	bound, err := BindGroupDNSRouting(BoundRouting{CompiledRouting: routing}, dns)
	if err != nil {
		t.Fatal(err)
	}
	bound, err = BindProxyTargetDNSRouting(bound, dns)
	if err != nil {
		t.Fatal(err)
	}
	tags := []string{groupTag, proxyTag}
	if err := ValidatePersistedRouteProvenance(bound.Rules, bound.SourceMap, tags); err != nil {
		t.Fatalf("real compiler Group + Proxy DNS source-map rejected: %v", err)
	}
	t.Run("missing Group DNS manifest tag", func(t *testing.T) {
		if err := ValidatePersistedRouteProvenance(bound.Rules, bound.SourceMap, []string{proxyTag}); !errors.Is(err, ErrNativeConfigClosure) {
			t.Fatalf("unadvertised Group DNS accepted: %v", err)
		}
	})
	t.Run("missing Proxy DNS manifest tag", func(t *testing.T) {
		if err := ValidatePersistedRouteProvenance(bound.Rules, bound.SourceMap, []string{groupTag}); !errors.Is(err, ErrNativeConfigClosure) {
			t.Fatalf("unadvertised Proxy DNS accepted: %v", err)
		}
	})
	t.Run("DNS source-map profile spoofed", func(t *testing.T) {
		mutated := cloneBoundRouting(bound)
		for i := range mutated.SourceMap {
			if mutated.SourceMap[i].Action == "resolve" && mutated.SourceMap[i].DNSProfileID != "" {
				mutated.SourceMap[i].DNSProfileID = "forged"
				break
			}
		}
		if err := ValidatePersistedRouteProvenance(mutated.Rules, mutated.SourceMap, tags); !errors.Is(err, ErrNativeConfigClosure) {
			t.Fatalf("spoofed Group DNS profile accepted: %v", err)
		}
	})
	t.Run("DNS source-map resolve dropped", func(t *testing.T) {
		mutated := cloneBoundRouting(bound)
		for i := range mutated.SourceMap {
			if mutated.SourceMap[i].Action == "resolve" && mutated.SourceMap[i].DNSProfileID != "" {
				mutated.SourceMap = append(mutated.SourceMap[:i], mutated.SourceMap[i+1:]...)
				break
			}
		}
		if err := ValidatePersistedRouteProvenance(mutated.Rules, mutated.SourceMap, tags); !errors.Is(err, ErrNativeConfigClosure) {
			t.Fatalf("missing Group DNS resolve evidence accepted: %v", err)
		}
	})
}
