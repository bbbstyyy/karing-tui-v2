package compiler

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCompileNativeConfigEmitsGroupDNSResolveAndDetour(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "group.example"})
	plan := domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID: "group", Layer: domain.LayerCustom, Order: 1, Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true, Target: domain.TargetRef{Kind: domain.TargetCurrentSelected}, DNSProfileID: "group-dns",
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}
	routing, err := CompileRouting(plan, input.Targets)
	if err != nil {
		t.Fatal(err)
	}
	ruleSets, err := NewRuleSetCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindRuleSetArtifacts(routing, ruleSets)
	if err != nil {
		t.Fatal(err)
	}

	dns, err := CompileRuntimeDNSForRouting(domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{ID: "out", Role: domain.DNSRoleOutbound, Transport: domain.DNSTransportUDP, Server: "192.0.2.53", Port: 53},
			{
				ID: "group-dns", Role: domain.DNSRoleGroup, Transport: domain.DNSTransportUDP,
				Server: "198.51.100.53", Port: 53,
				DetourTarget: domain.TargetRef{Kind: domain.TargetCurrentSelected},
			},
		},
		OutboundProfileID: "out",
	}, plan, input.Targets)
	if err != nil {
		t.Fatal(err)
	}
	bound, err = BindGroupDNSRouting(bound, dns)
	if err != nil {
		t.Fatal(err)
	}

	input.DNS = dns
	input.Routing = bound
	artifact, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}

	var decoded struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
		} `json:"dns"`
		Route struct {
			Rules []RouteRule `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(artifact.JSON, &decoded); err != nil {
		t.Fatal(err)
	}
	groupTag := stableDNSTag("group-dns")
	foundServer := false
	for _, server := range decoded.DNS.Servers {
		if server["tag"] == groupTag {
			foundServer = true
			if server["detour"] != input.Targets.CurrentSelectedTag {
				t.Fatalf("Group DNS detour = %#v, want %q", server["detour"], input.Targets.CurrentSelectedTag)
			}
		}
	}
	if !foundServer {
		t.Fatal("Group DNS server missing")
	}
	if len(decoded.Route.Rules) < 10 ||
		decoded.Route.Rules[6].Action != "resolve" ||
		decoded.Route.Rules[6].Server != groupTag ||
		decoded.Route.Rules[7].Action != "route" {
		t.Fatalf("Group DNS resolve/route pair missing: %+v", decoded.Route.Rules)
	}
}

func TestCompileNativeConfigRejectsUnboundGroupDNS(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	tag := stableDNSTag("group-dns")
	input.DNS = CompiledDNS{
		Servers: []DNSServerConfig{
			{Type: "udp", Tag: "dns-out", Server: "192.0.2.53", ServerPort: 53},
			{Type: "udp", Tag: tag, Server: "198.51.100.53", ServerPort: 53, Detour: input.Targets.CurrentSelectedTag},
		},
		OutboundResolverTag: "dns-out",
		GroupBindings: []DNSGroupBinding{{
			GroupID: "missing", ProfileID: "group-dns", RuntimeTag: tag, DetourOutbound: input.Targets.CurrentSelectedTag,
		}},
	}
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrNativeConfigClosure) {
		t.Fatalf("unbound Group DNS error = %v", err)
	}
}
