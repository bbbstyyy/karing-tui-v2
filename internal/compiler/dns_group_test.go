package compiler

import (
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCompileRuntimeDNSForRoutingClosesActiveGroups(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "a.example"})
	b := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "b.example"})
	routing := domain.RoutingPlan{
		Custom: []domain.RouteGroup{
			{ID: "a", Layer: domain.LayerCustom, Order: 1, Match: &a, Binding: domain.RouteBinding{
				Enabled: true, Target: domain.TargetRef{Kind: domain.TargetDirect}, DNSProfileID: "dns-a",
			}},
			{ID: "b", Layer: domain.LayerCustom, Order: 2, Match: &b, Binding: domain.RouteBinding{
				Enabled: true, Target: domain.TargetRef{Kind: domain.TargetCurrentSelected}, DNSProfileID: "dns-b",
			}},
		},
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}
	plan := domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{ID: "out", Role: domain.DNSRoleOutbound, Transport: domain.DNSTransportUDP, Server: "192.0.2.53", Port: 53},
			{ID: "dns-a", Role: domain.DNSRoleGroup, Transport: domain.DNSTransportUDP, Server: "198.51.100.53", Port: 53, DetourTarget: domain.TargetRef{Kind: domain.TargetDirect}},
			{ID: "dns-b", Role: domain.DNSRoleGroup, Transport: domain.DNSTransportTCP, Server: "203.0.113.53", Port: 53, DetourTarget: domain.TargetRef{Kind: domain.TargetCurrentSelected}},
			{ID: "unused", Role: domain.DNSRoleGroup, Transport: domain.DNSTransportUDP, Server: "192.0.2.54", Port: 53, DetourTarget: domain.TargetRef{Kind: domain.TargetDirect}},
		},
		OutboundProfileID: "out",
	}

	got, err := CompileRuntimeDNSForRouting(plan, routing, targets)
	if err != nil {
		t.Fatal(err)
	}
	if want := []DNSGroupBinding{
		{GroupID: "a", ProfileID: "dns-a", RuntimeTag: stableDNSTag("dns-a")},
		{GroupID: "b", ProfileID: "dns-b", RuntimeTag: stableDNSTag("dns-b"), DetourOutbound: targets.CurrentSelectedTag},
	}; !reflect.DeepEqual(got.GroupBindings, want) {
		t.Fatalf("group bindings = %#v, want %#v", got.GroupBindings, want)
	}
	if want := []string{targets.CurrentSelectedTag}; !reflect.DeepEqual(got.DetourOutboundTags, want) {
		t.Fatalf("detour tags = %#v, want %#v", got.DetourOutboundTags, want)
	}
	if len(got.Servers) != 3 || got.Servers[1].Detour != "" || got.Servers[2].Detour != targets.CurrentSelectedTag {
		t.Fatalf("unexpected DNS closure: %+v", got.Servers)
	}
	for _, binding := range got.ProfileBindings {
		if binding.ProfileID == "unused" {
			t.Fatal("unused Group DNS leaked into closure")
		}
	}
}

func TestRuntimeOutboundRequirementsIncludesDNSDetours(t *testing.T) {
	node := NodeTargetKey{ProfileID: "p", NodeID: "n"}
	targets, err := NewTargetCatalog([]string{"auto"}, []NodeTargetKey{node})
	if err != nil {
		t.Fatal(err)
	}
	routing := CompiledRouting{OutboundTags: []string{targets.DirectTag, targets.CurrentSelectedTag}}
	dns := CompiledDNS{DetourOutboundTags: []string{
		targets.CustomURLTestTags["auto"], targets.NodeTags[node], targets.CurrentSelectedTag,
	}}
	got := RuntimeOutboundRequirements(routing, dns)
	want := []string{
		targets.DirectTag, targets.CurrentSelectedTag,
		targets.CustomURLTestTags["auto"], targets.NodeTags[node],
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("requirements = %#v, want %#v", got, want)
	}
}
