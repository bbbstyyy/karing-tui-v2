package compiler

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCompileOutboundDNSBuildsDependencyFirstClosure(t *testing.T) {
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
				Server:             "resolver.example.com",
				Port:               53,
				BootstrapProfileID: "bootstrap",
			},
			{
				ID:        "unused-direct",
				Role:      domain.DNSRoleDirect,
				Transport: domain.DNSTransportUDP,
				Server:    "198.51.100.53",
				Port:      53,
			},
		},
		OutboundProfileID: "outbound",
	}
	compiled, err := CompileOutboundDNS(plan, targets)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Servers) != 2 {
		t.Fatalf("servers = %d, want bootstrap + outbound", len(compiled.Servers))
	}
	if got, want := compiled.ProfileBindings, []DNSProfileBinding{
		{ProfileID: "bootstrap", RuntimeTag: stableDNSTag("bootstrap")},
		{ProfileID: "outbound", RuntimeTag: stableDNSTag("outbound")},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bindings = %#v, want %#v", got, want)
	}
	if compiled.OutboundResolverTag != stableDNSTag("outbound") {
		t.Fatalf("outbound resolver tag = %q", compiled.OutboundResolverTag)
	}

	first, err := json.Marshal(compiled.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	wantFirst := `{"type":"udp","tag":"` + stableDNSTag("bootstrap") + `","server":"192.0.2.53","server_port":53,"detour":"out-direct"}`
	if string(first) != wantFirst {
		t.Fatalf("bootstrap JSON = %s, want %s", first, wantFirst)
	}
	second, err := json.Marshal(compiled.Servers[1])
	if err != nil {
		t.Fatal(err)
	}
	wantSecond := `{"type":"tcp","tag":"` + stableDNSTag("outbound") + `","server":"resolver.example.com","server_port":53,"detour":"out-direct","domain_resolver":"` + stableDNSTag("bootstrap") + `"}`
	if string(second) != wantSecond {
		t.Fatalf("outbound DNS JSON = %s, want %s", second, wantSecond)
	}
}

func TestCompileOutboundDNSRejectsMissingOutboundRole(t *testing.T) {
	targets, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := domain.DNSPlan{
		Profiles: []domain.DNSProfile{{
			ID:        "direct",
			Role:      domain.DNSRoleDirect,
			Transport: domain.DNSTransportUDP,
			Server:    "192.0.2.53",
			Port:      53,
		}},
	}
	if _, err := CompileOutboundDNS(plan, targets); !errors.Is(err, ErrDNSClosure) {
		t.Fatalf("missing outbound DNS error = %v", err)
	}
}

func TestBindNodeDomainResolverBindsOnlyDomainServers(t *testing.T) {
	domainNode := domain.Node{
		ProfileID: "profile-a",
		NodeID:    "domain-node",
		Kind:      domain.NodeHTTP,
		Server:    "proxy.example.com",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}
	ipNode := domain.Node{
		ProfileID: "profile-b",
		NodeID:    "ip-node",
		Kind:      domain.NodeHTTP,
		Server:    "192.0.2.10",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}
	keyDomain := NodeTargetKey{ProfileID: domainNode.ProfileID, NodeID: domainNode.NodeID}
	keyIP := NodeTargetKey{ProfileID: ipNode.ProfileID, NodeID: ipNode.NodeID}
	targets, err := NewTargetCatalog(nil, []NodeTargetKey{keyDomain, keyIP})
	if err != nil {
		t.Fatal(err)
	}
	required := []domain.TargetRef{
		{Kind: domain.TargetSpecificNode, ProfileID: domainNode.ProfileID, NodeID: domainNode.NodeID},
		{Kind: domain.TargetSpecificNode, ProfileID: ipNode.ProfileID, NodeID: ipNode.NodeID},
	}
	nodes, err := CompileBasicNodeOutbounds([]domain.Node{domainNode, ipNode}, targets, required)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := CompileOutboundDNS(domain.DNSPlan{
		Profiles: []domain.DNSProfile{{
			ID:        "outbound",
			Role:      domain.DNSRoleOutbound,
			Transport: domain.DNSTransportUDP,
			Server:    "192.0.2.53",
			Port:      53,
		}},
		OutboundProfileID: "outbound",
	}, targets)
	if err != nil {
		t.Fatal(err)
	}

	bound, err := BindNodeDomainResolver(nodes, dns)
	if err != nil {
		t.Fatal(err)
	}
	if bound.Outbounds[0].DomainResolver != dns.OutboundResolverTag {
		t.Fatalf("domain node resolver = %q, want %q", bound.Outbounds[0].DomainResolver, dns.OutboundResolverTag)
	}
	if bound.Outbounds[1].DomainResolver != "" {
		t.Fatalf("IP node unexpectedly has resolver %q", bound.Outbounds[1].DomainResolver)
	}
	if nodes.Outbounds[0].DomainResolver != "" {
		t.Fatal("resolver binding mutated original node compiler output")
	}

	encoded, err := json.Marshal(bound.Outbounds[0])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bound.Tags, nodes.Tags) || !reflect.DeepEqual(bound.Targets, nodes.Targets) {
		t.Fatal("resolver binding changed node closure metadata")
	}
	want := `{"type":"http","tag":"` + nodes.Tags[0] + `","server":"proxy.example.com","server_port":8080,"domain_resolver":"` + dns.OutboundResolverTag + `"}`
	if string(encoded) != want {
		t.Fatalf("bound node JSON = %s, want %s", encoded, want)
	}
}

func TestBindNodeDomainResolverFailsClosedWithoutResolver(t *testing.T) {
	nodes := CompiledNodes{
		Outbounds: []NodeOutboundConfig{{
			Type:       "http",
			Tag:        "out-node-test",
			Server:     "proxy.example.com",
			ServerPort: 8080,
		}},
		Targets: []domain.TargetRef{{Kind: domain.TargetSpecificNode, ProfileID: "profile", NodeID: "node"}},
		Tags:    []string{"out-node-test"},
	}
	if _, err := BindNodeDomainResolver(nodes, CompiledDNS{}); !errors.Is(err, ErrDNSClosure) {
		t.Fatalf("missing resolver error = %v", err)
	}
}

func TestBindNodeDomainResolverAllowsIPOnlyClosureWithoutDNS(t *testing.T) {
	nodes := CompiledNodes{
		Outbounds: []NodeOutboundConfig{{
			Type:       "http",
			Tag:        "out-node-test",
			Server:     "192.0.2.10",
			ServerPort: 8080,
		}},
		Targets: []domain.TargetRef{{Kind: domain.TargetSpecificNode, ProfileID: "profile", NodeID: "node"}},
		Tags:    []string{"out-node-test"},
	}
	bound, err := BindNodeDomainResolver(nodes, CompiledDNS{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bound, nodes) {
		t.Fatalf("IP-only closure changed after empty DNS bind: %+v / %+v", bound, nodes)
	}
}
