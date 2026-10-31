package compiler

import (
	"errors"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCompileNativeConfigPreservesAllFiveLayerSourceMapActions(t *testing.T) {
	input := fiveLayerProvenanceInput(t)
	artifact, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.SourceMap) != 5 {
		t.Fatalf("source-map has %d entries, want all four layers plus FINAL", len(artifact.SourceMap))
	}
	for i, layer := range []domain.RoutingLayer{
		domain.LayerCustom, domain.LayerGeoSite, domain.LayerGeoIP, domain.LayerACL, domain.LayerFinal,
	} {
		if artifact.SourceMap[i].Layer != layer {
			t.Fatalf("layer %d is %s, want %s", i, artifact.SourceMap[i].Layer, layer)
		}
	}
	if artifact.SourceMap[0].Action != "reject" ||
		artifact.SourceMap[1].Action != "route" ||
		artifact.SourceMap[2].Action != "route" ||
		artifact.SourceMap[3].Action != "route" ||
		artifact.SourceMap[4].Action != "reject" || !artifact.SourceMap[4].Final {
		t.Fatalf("unexpected route actions: %+v", artifact.SourceMap)
	}
}

func TestCompileNativeConfigRejectsForgedFiveLayerProvenance(t *testing.T) {
	base := fiveLayerProvenanceInput(t)
	if _, err := CompileNativeConfig(base); err != nil {
		t.Fatalf("untampered native route rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*BoundRouting)
	}{
		{"missing source-map", func(b *BoundRouting) { b.SourceMap = nil }},
		{"missing custom group", func(b *BoundRouting) { b.SourceMap = b.SourceMap[1:] }},
		{"missing final", func(b *BoundRouting) { b.SourceMap = b.SourceMap[:4] }},
		{"duplicate rule index", func(b *BoundRouting) { b.SourceMap[1].RuleIndex = b.SourceMap[0].RuleIndex }},
		{"reordered source rows", func(b *BoundRouting) { b.SourceMap[0], b.SourceMap[1] = b.SourceMap[1], b.SourceMap[0] }},
		{"source index too large", func(b *BoundRouting) { b.SourceMap[0].RuleIndex = len(b.Rules) }},
		{"source index negative", func(b *BoundRouting) { b.SourceMap[0].RuleIndex = -1 }},
		{"subscription layer", func(b *BoundRouting) { b.SourceMap[1].Layer = "subscription" }},
		{"layer order inversion", func(b *BoundRouting) { b.SourceMap[1].Layer = domain.LayerACL }},
		{"incorrect final flag", func(b *BoundRouting) { b.SourceMap[4].Final = false }},
		{"incorrect final layer", func(b *BoundRouting) { b.SourceMap[4].Layer = domain.LayerACL }},
		{"final group identity", func(b *BoundRouting) { b.SourceMap[4].GroupID = "forged-final" }},
		{"final DNS profile", func(b *BoundRouting) { b.SourceMap[4].DNSProfileID = "dns-forged" }},
		{"duplicate group provenance", func(b *BoundRouting) { b.SourceMap[1].GroupID = b.SourceMap[0].GroupID }},
		{"missing group identity", func(b *BoundRouting) { b.SourceMap[0].GroupID = "" }},
		{"BLOCK impersonates DIRECT", func(b *BoundRouting) { b.SourceMap[0].Target = domain.TargetRef{Kind: domain.TargetDirect} }},
		{"BLOCK gets a DNS binding", func(b *BoundRouting) { b.SourceMap[0].DNSProfileID = "dns-forged" }},
		{"BLOCK native action changed", func(b *BoundRouting) { b.Rules[b.SourceMap[0].RuleIndex].Action = "route" }},
		{"target references wrong outbound", func(b *BoundRouting) { b.SourceMap[1].Target = domain.TargetRef{Kind: domain.TargetCurrentSelected} }},
		{"target points to wrong node", func(b *BoundRouting) {
			b.SourceMap[2].Target = domain.TargetRef{
				Kind: domain.TargetSpecificNode, ProfileID: "other", NodeID: "node",
			}
		}},
		{"source-map outbound spoof", func(b *BoundRouting) { b.SourceMap[3].Outbound = DirectOutboundTag }},
		{"native outbound drift", func(b *BoundRouting) { b.Rules[b.SourceMap[3].RuleIndex].Outbound = DirectOutboundTag }},
		{"native matcher loses Rule scope", func(b *BoundRouting) {
			b.Rules[b.SourceMap[1].RuleIndex].Rules[0] = RouteRule{Inbound: []string{domain.InboundTagSelected}}
		}},
		{"final native match narrowed", func(b *BoundRouting) {
			b.Rules[b.SourceMap[4].RuleIndex].DomainSuffix = []string{"partial.invalid"}
		}},
		{"final native inbound changed", func(b *BoundRouting) {
			b.Rules[b.SourceMap[4].RuleIndex].Inbound = []string{domain.InboundTagSelected}
		}},
		{"orphan resolve without DNS", func(b *BoundRouting) {
			b.SourceMap[1].Action = "resolve"
			b.SourceMap[1].Outbound = ""
			b.SourceMap[1].Server = "dns-forged"
			b.Rules[b.SourceMap[1].RuleIndex].Action = "resolve"
			b.Rules[b.SourceMap[1].RuleIndex].Outbound = ""
			b.Rules[b.SourceMap[1].RuleIndex].Server = "dns-forged"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			altered := base
			altered.Routing = cloneBoundRouting(base.Routing)
			tc.mutate(&altered.Routing)
			if _, err := CompileNativeConfig(altered); !errors.Is(err, ErrNativeConfigClosure) {
				t.Fatalf("invalid native provenance accepted: %v", err)
			}
		})
	}
}

func fiveLayerProvenanceInput(t *testing.T) NativeConfigInput {
	t.Helper()
	input := nativeTestInput(t, "127.0.0.1")
	custom := domain.Atom(domain.Predicate{Kind: domain.PredicateDomain, Value: "custom.invalid"})
	geosite := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "site.invalid"})
	geoip := domain.Atom(domain.Predicate{Kind: domain.PredicateIPCIDR, CIDR: "203.0.113.0/24"})
	acl := domain.Atom(domain.Predicate{Kind: domain.PredicateNetwork, Network: domain.NetworkTCP})
	plan := domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID: "custom-block", Layer: domain.LayerCustom, Order: 1, Match: &custom,
			Binding: domain.RouteBinding{Enabled: true, Target: domain.TargetRef{Kind: domain.TargetBlock}},
		}},
		GeoSite: []domain.RouteGroup{{
			ID: "site-direct", Layer: domain.LayerGeoSite, Order: 1, Match: &geosite,
			Binding: domain.RouteBinding{Enabled: true, Target: domain.TargetRef{Kind: domain.TargetDirect}},
		}},
		GeoIP: []domain.RouteGroup{{
			ID: "ip-node", Layer: domain.LayerGeoIP, Order: 1, Match: &geoip,
			Binding: domain.RouteBinding{Enabled: true, Target: domain.TargetRef{
				Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a",
			}},
		}},
		ACL: []domain.RouteGroup{{
			ID: "acl-selected", Layer: domain.LayerACL, Order: 1, Match: &acl,
			Binding: domain.RouteBinding{Enabled: true, Target: domain.TargetRef{Kind: domain.TargetCurrentSelected}},
		}},
		Final: domain.TargetRef{Kind: domain.TargetBlock},
	}
	compiled, err := CompileRouting(plan, input.Targets)
	if err != nil {
		t.Fatal(err)
	}
	input.Routing = BoundRouting{CompiledRouting: compiled}
	return input
}
