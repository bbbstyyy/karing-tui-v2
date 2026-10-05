package domain

import (
	"net/netip"
	"testing"
)

func TestDefaultInboundSetMatchesPlan(t *testing.T) {
	set := DefaultInboundSet()
	if err := set.Validate(); err != nil {
		t.Fatal(err)
	}
	ordered, err := set.Ordered()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"rule=127.0.0.1:2080",
		"direct=127.0.0.1:2081",
		"selected=127.0.0.1:2082",
	}
	for i, inbound := range ordered {
		got := string(inbound.Role) + "=" + inbound.Address.String()
		if got != want[i] {
			t.Fatalf("inbound[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestInboundSetRejectsPortCollisionAndLANBind(t *testing.T) {
	cases := []InboundSet{
		{Listen: netip.MustParseAddr("127.0.0.1"), RulePort: 2080, DirectPort: 2080, SelectedPort: 2082},
		{Listen: netip.MustParseAddr("0.0.0.0"), RulePort: 2080, DirectPort: 2081, SelectedPort: 2082},
		{Listen: netip.MustParseAddr("192.168.1.2"), RulePort: 2080, DirectPort: 2081, SelectedPort: 2082},
		{Listen: netip.MustParseAddr("127.0.0.1"), RulePort: 0, DirectPort: 2081, SelectedPort: 2082},
	}
	for _, set := range cases {
		if err := set.Validate(); err == nil {
			t.Fatalf("expected invalid inbound set to fail: %+v", set)
		}
	}
}

func TestInboundSetAllowsExplicitIPv6Loopback(t *testing.T) {
	set := InboundSet{
		Listen:       netip.IPv6Loopback(),
		RulePort:     2080,
		DirectPort:   2081,
		SelectedPort: 2082,
	}
	if err := set.Validate(); err != nil {
		t.Fatal(err)
	}
	address, err := set.Address(InboundSelected)
	if err != nil {
		t.Fatal(err)
	}
	if got := address.String(); got != "[::1]:2082" {
		t.Fatalf("selected address = %q", got)
	}
}

func TestInboundRuntimeTagsAreStable(t *testing.T) {
	cases := []struct {
		role InboundRole
		want string
	}{
		{role: InboundRule, want: InboundTagRule},
		{role: InboundDirect, want: InboundTagDirect},
		{role: InboundSelected, want: InboundTagSelected},
	}
	for _, tc := range cases {
		got, err := tc.role.RuntimeTag()
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("%s runtime tag = %q, want %q", tc.role, got, tc.want)
		}
	}
	if _, err := InboundRole("unknown").RuntimeTag(); err == nil {
		t.Fatal("unknown inbound role unexpectedly produced a runtime tag")
	}
}
