package declaration

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func firstRunHTTPNode() domain.Node {
	return domain.Node{
		ProfileID: "profile-first", NodeID: "node-first",
		Kind: domain.NodeHTTP, Server: "127.0.0.1", Port: 9080,
		HTTP: &domain.HTTPNodeOptions{Username: "private", Password: "SUPER_PRIVATE_PASSWORD"},
	}
}

func TestBuildInitialProxyOnlyV1ExplicitSelectedAndResolver(t *testing.T) {
	node := firstRunHTTPNode()
	resolver := netip.MustParseAddrPort("127.0.0.1:5300")
	document, err := BuildInitialProxyOnlyV1([]domain.Node{node}, node.NodeID, resolver)
	if err != nil {
		t.Fatalf("build initial declaration: %v", err)
	}
	if !bytes.Contains(document, []byte("SUPER_PRIVATE_PASSWORD")) {
		t.Fatal("canonical initial document omitted the actual imported credential")
	}
	model, err := ParseV1(document)
	if err != nil {
		t.Fatalf("parse initial declaration: %v", err)
	}
	if len(model.Nodes) != 1 ||
		model.Selection.Current.Default.Kind != domain.TargetSpecificNode ||
		model.Selection.Current.Default.NodeID != node.NodeID ||
		len(model.Selection.Current.Members) != 1 ||
		model.Routing.Final.Kind != domain.TargetCurrentSelected ||
		model.CNPreset != nil || model.RegionAppend != nil ||
		len(model.Routing.Custom) != 0 || len(model.Routing.GeoSite) != 0 ||
		len(model.Routing.GeoIP) != 0 || len(model.Routing.ACL) != 0 ||
		len(model.DNS.Profiles) != 2 ||
		model.DNS.OutboundProfileID != "first-run-outbound" ||
		model.DNS.FallbackProfileID != "first-run-fallback" {
		t.Fatal("initial document implicitly enabled CN or direct routing, or failed to bind selection/DNS")
	}
	for _, dns := range model.DNS.Profiles {
		if dns.Server != "127.0.0.1" || dns.Port != 5300 {
			t.Fatal("initial declaration silently substituted a different resolver")
		}
	}
	repeated, err := BuildInitialProxyOnlyV1([]domain.Node{node}, node.NodeID, resolver)
	if err != nil || !bytes.Equal(repeated, document) {
		t.Fatalf("initial document digest is not deterministic: err=%v", err)
	}
}

func TestBuildInitialProxyOnlyV1FailsClosed(t *testing.T) {
	node := firstRunHTTPNode()
	resolver := netip.MustParseAddrPort("127.0.0.1:5300")
	bad := node
	bad.Port = 0
	other := node
	other.ProfileID = "other-profile"
	for _, tc := range []struct {
		name     string
		nodes    []domain.Node
		selected string
		resolver netip.AddrPort
	}{
		{"no selected node", []domain.Node{node}, "", resolver},
		{"unavailable selected", []domain.Node{node}, "not-a-member", resolver},
		{"empty source", nil, node.NodeID, resolver},
		{"invalid node", []domain.Node{bad}, bad.NodeID, resolver},
		{"duplicate node", []domain.Node{node, node}, node.NodeID, resolver},
		{"mixed profiles", []domain.Node{node, other}, node.NodeID, resolver},
		{"missing DNS", []domain.Node{node}, node.NodeID, netip.AddrPort{}},
		{"DNS wildcard", []domain.Node{node}, node.NodeID, netip.MustParseAddrPort("0.0.0.0:53")},
		{"DNS multicast", []domain.Node{node}, node.NodeID, netip.MustParseAddrPort("224.0.0.1:53")},
		{"DNS zero port", []domain.Node{node}, node.NodeID, netip.MustParseAddrPort("127.0.0.1:0")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildInitialProxyOnlyV1(tc.nodes, tc.selected, tc.resolver); err == nil {
				t.Fatal("unsafe first-run initialization accepted")
			}
		})
	}
}
