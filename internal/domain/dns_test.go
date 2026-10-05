package domain

import (
	"errors"
	"testing"
)

func TestDNSPlanValidatesExplicitRoleAndBootstrapGraph(t *testing.T) {
	plan := DNSPlan{
		Profiles: []DNSProfile{
			{ID: "bootstrap", Role: DNSRoleBootstrap, Transport: DNSTransportUDP, Server: "192.0.2.53", Port: 53},
			{ID: "outbound", Role: DNSRoleOutbound, Transport: DNSTransportTCP, Server: "resolver.example.com", Port: 53, BootstrapProfileID: "bootstrap"},
			{ID: "direct", Role: DNSRoleDirect, Transport: DNSTransportUDP, Server: "198.51.100.53", Port: 53},
			{ID: "proxy", Role: DNSRoleProxy, Transport: DNSTransportTCP, Server: "203.0.113.53", Port: 53},
			{ID: "fallback", Role: DNSRoleFallback, Transport: DNSTransportUDP, Server: "192.0.2.54", Port: 53},
			{ID: "group-a", Role: DNSRoleGroup, Transport: DNSTransportUDP, Server: "192.0.2.55", Port: 53, DetourTarget: TargetRef{Kind: TargetDirect}},
		},
		OutboundProfileID: "outbound",
		DirectProfileID:   "direct",
		ProxyProfileID:    "proxy",
		FallbackProfileID: "fallback",
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	if profile, ok := plan.Profile("group-a"); !ok || profile.Role != DNSRoleGroup {
		t.Fatalf("group profile lookup = %+v, %v", profile, ok)
	}
}

func TestDNSPlanRejectsDomainServerWithoutBootstrap(t *testing.T) {
	plan := DNSPlan{Profiles: []DNSProfile{{
		ID:        "outbound",
		Role:      DNSRoleOutbound,
		Transport: DNSTransportUDP,
		Server:    "resolver.example.com",
		Port:      53,
	}}}
	if err := plan.Validate(); !errors.Is(err, ErrInvalidDNSPlan) {
		t.Fatalf("missing bootstrap error = %v", err)
	}
}

func TestDNSPlanRejectsMissingOrWrongBootstrapRole(t *testing.T) {
	base := DNSProfile{
		ID:                 "outbound",
		Role:               DNSRoleOutbound,
		Transport:          DNSTransportUDP,
		Server:             "resolver.example.com",
		Port:               53,
		BootstrapProfileID: "bootstrap",
	}
	if err := (DNSPlan{Profiles: []DNSProfile{base}}).Validate(); !errors.Is(err, ErrInvalidDNSPlan) {
		t.Fatalf("missing bootstrap error = %v", err)
	}

	wrong := DNSPlan{Profiles: []DNSProfile{
		base,
		{ID: "bootstrap", Role: DNSRoleDirect, Transport: DNSTransportUDP, Server: "192.0.2.53", Port: 53},
	}}
	if err := wrong.Validate(); !errors.Is(err, ErrInvalidDNSPlan) {
		t.Fatalf("wrong bootstrap role error = %v", err)
	}
}

func TestDNSPlanRejectsBootstrapCyclesDeterministically(t *testing.T) {
	plan := DNSPlan{Profiles: []DNSProfile{
		{ID: "bootstrap-a", Role: DNSRoleBootstrap, Transport: DNSTransportUDP, Server: "a.example.com", Port: 53, BootstrapProfileID: "bootstrap-b"},
		{ID: "bootstrap-b", Role: DNSRoleBootstrap, Transport: DNSTransportUDP, Server: "b.example.com", Port: 53, BootstrapProfileID: "bootstrap-a"},
	}}
	err1 := plan.Validate()
	err2 := plan.Validate()
	if !errors.Is(err1, ErrDNSDependencyCycle) || !errors.Is(err2, ErrDNSDependencyCycle) {
		t.Fatalf("cycle errors = %v / %v", err1, err2)
	}
	if err1.Error() != err2.Error() {
		t.Fatalf("cycle diagnostic is not deterministic: %q / %q", err1, err2)
	}
}

func TestDNSPlanRejectsDuplicateProfilesAndRoleSlotMismatch(t *testing.T) {
	duplicate := DNSPlan{Profiles: []DNSProfile{
		{ID: "same", Role: DNSRoleDirect, Transport: DNSTransportUDP, Server: "192.0.2.53", Port: 53},
		{ID: "same", Role: DNSRoleDirect, Transport: DNSTransportUDP, Server: "192.0.2.54", Port: 53},
	}}
	if err := duplicate.Validate(); !errors.Is(err, ErrDuplicateDNSProfile) {
		t.Fatalf("duplicate profile error = %v", err)
	}

	mismatch := DNSPlan{
		Profiles: []DNSProfile{
			{ID: "direct", Role: DNSRoleDirect, Transport: DNSTransportUDP, Server: "192.0.2.53", Port: 53},
		},
		OutboundProfileID: "direct",
	}
	if err := mismatch.Validate(); !errors.Is(err, ErrInvalidDNSPlan) {
		t.Fatalf("role slot mismatch error = %v", err)
	}
}

func TestDNSProfileRequiresExplicitSupportedTransportAndPort(t *testing.T) {
	cases := []DNSProfile{
		{ID: "dns", Role: DNSRoleDirect, Transport: DNSTransport("https"), Server: "192.0.2.53", Port: 443},
		{ID: "dns", Role: DNSRole("unknown"), Transport: DNSTransportUDP, Server: "192.0.2.53", Port: 53},
		{ID: "dns", Role: DNSRoleDirect, Transport: DNSTransportUDP, Server: "192.0.2.53", Port: 0},
		{ID: "dns", Role: DNSRoleDirect, Transport: DNSTransportUDP, Server: "0.0.0.0", Port: 53},
		{ID: "dns", Role: DNSRoleDirect, Transport: DNSTransportUDP, Server: "192.0.2.53", Port: 53, BootstrapProfileID: "unused"},
		{ID: "group", Role: DNSRoleGroup, Transport: DNSTransportUDP, Server: "192.0.2.54", Port: 53},
		{ID: "group", Role: DNSRoleGroup, Transport: DNSTransportUDP, Server: "192.0.2.54", Port: 53, DetourTarget: TargetRef{Kind: TargetBlock}},
		{ID: "direct", Role: DNSRoleDirect, Transport: DNSTransportUDP, Server: "192.0.2.55", Port: 53, DetourTarget: TargetRef{Kind: TargetCurrentSelected}},
	}
	for i, profile := range cases {
		if err := profile.Validate(); !errors.Is(err, ErrInvalidDNSPlan) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

func TestDNSPlanValidatesEnabledRouteGroupDNSBindings(t *testing.T) {
	match := Atom(Predicate{Kind: PredicateDomain, Value: "example.com"})
	routing := RoutingPlan{
		Custom: []RouteGroup{
			{
				ID:    "enabled",
				Layer: LayerCustom,
				Order: 1,
				Match: &match,
				Binding: RouteBinding{
					Enabled:      true,
					Target:       TargetRef{Kind: TargetDirect},
					DNSProfileID: "group-dns",
				},
			},
			{
				ID:    "disabled",
				Layer: LayerCustom,
				Order: 2,
				Binding: RouteBinding{
					Enabled:      false,
					Target:       TargetRef{Kind: TargetDirect},
					DNSProfileID: "missing-but-disabled",
				},
			},
		},
		Final: TargetRef{Kind: TargetDirect},
	}
	plan := DNSPlan{Profiles: []DNSProfile{
		{ID: "group-dns", Role: DNSRoleGroup, Transport: DNSTransportUDP, Server: "192.0.2.53", Port: 53, DetourTarget: TargetRef{Kind: TargetDirect}},
	}}
	if err := plan.ValidateActiveRouteBindings(routing); err != nil {
		t.Fatal(err)
	}

	plan.Profiles[0].Role = DNSRoleDirect
	plan.Profiles[0].DetourTarget = TargetRef{}
	if err := plan.ValidateActiveRouteBindings(routing); !errors.Is(err, ErrInvalidDNSRouteBind) {
		t.Fatalf("wrong group DNS role error = %v", err)
	}

	plan.Profiles = nil
	if err := plan.ValidateActiveRouteBindings(routing); !errors.Is(err, ErrInvalidDNSRouteBind) {
		t.Fatalf("missing group DNS error = %v", err)
	}
}
