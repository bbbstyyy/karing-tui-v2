package compiler

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCompileBasicNodeOutboundsPreservesRequiredOrder(t *testing.T) {
	nodeA := domain.Node{
		ProfileID: "profile-a",
		NodeID:    "socks-a",
		Kind:      domain.NodeSOCKS,
		Server:    "proxy-a.example.com",
		Port:      1080,
		SOCKS: &domain.SOCKSNodeOptions{
			Version:  domain.SOCKS5,
			Username: "alice",
			Password: "secret",
			Network:  domain.ProxyNetworkBoth,
		},
	}
	nodeB := domain.Node{
		ProfileID: "profile-b",
		NodeID:    "http-b",
		Kind:      domain.NodeHTTP,
		Server:    "192.0.2.20",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}
	keyA := NodeTargetKey{ProfileID: nodeA.ProfileID, NodeID: nodeA.NodeID}
	keyB := NodeTargetKey{ProfileID: nodeB.ProfileID, NodeID: nodeB.NodeID}
	catalog, err := NewTargetCatalog(nil, []NodeTargetKey{keyA, keyB})
	if err != nil {
		t.Fatal(err)
	}
	refA := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: nodeA.ProfileID, NodeID: nodeA.NodeID}
	refB := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: nodeB.ProfileID, NodeID: nodeB.NodeID}

	compiled, err := CompileBasicNodeOutbounds([]domain.Node{nodeA, nodeB}, catalog, []domain.TargetRef{refB, refA, refB})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := compiled.Targets, []domain.TargetRef{refB, refA}; !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %#v, want %#v", got, want)
	}
	if got, want := compiled.Tags, []string{catalog.NodeTags[keyB], catalog.NodeTags[keyA]}; !reflect.DeepEqual(got, want) {
		t.Fatalf("tags = %#v, want %#v", got, want)
	}
	if len(compiled.Outbounds) != 2 {
		t.Fatalf("outbounds = %d, want 2", len(compiled.Outbounds))
	}
}

func TestCompileBasicNodeOutboundsEmitsSupportedProtocolFields(t *testing.T) {
	socks := domain.Node{
		ProfileID: "profile-a",
		NodeID:    "socks-a",
		Kind:      domain.NodeSOCKS,
		Server:    "proxy.example.com",
		Port:      1080,
		SOCKS: &domain.SOCKSNodeOptions{
			Version:  domain.SOCKS5,
			Username: "user",
			Password: "pass",
			Network:  domain.ProxyNetworkUDP,
		},
	}
	httpNode := domain.Node{
		ProfileID: "profile-b",
		NodeID:    "http-b",
		Kind:      domain.NodeHTTP,
		Server:    "192.0.2.30",
		Port:      8080,
		HTTP: &domain.HTTPNodeOptions{
			Username: "bob",
			Password: "secret",
		},
	}
	ssNode := domain.Node{
		ProfileID: "profile-c",
		NodeID:    "ss-c",
		Kind:      domain.NodeShadowsocks,
		Server:    "ss.example.com",
		Port:      8388,
		Shadowsocks: &domain.ShadowsocksNodeOptions{
			Method:        "aes-256-gcm",
			Password:      "ss-secret",
			Plugin:        "obfs-local",
			PluginOptions: "obfs=http",
			Network:       domain.ProxyNetworkTCP,
		},
	}
	keyS := NodeTargetKey{ProfileID: socks.ProfileID, NodeID: socks.NodeID}
	keyH := NodeTargetKey{ProfileID: httpNode.ProfileID, NodeID: httpNode.NodeID}
	keySS := NodeTargetKey{ProfileID: ssNode.ProfileID, NodeID: ssNode.NodeID}
	catalog, err := NewTargetCatalog(nil, []NodeTargetKey{keyS, keyH, keySS})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileBasicNodeOutbounds(
		[]domain.Node{socks, httpNode, ssNode},
		catalog,
		[]domain.TargetRef{
			{Kind: domain.TargetSpecificNode, ProfileID: socks.ProfileID, NodeID: socks.NodeID},
			{Kind: domain.TargetSpecificNode, ProfileID: httpNode.ProfileID, NodeID: httpNode.NodeID},
			{Kind: domain.TargetSpecificNode, ProfileID: ssNode.ProfileID, NodeID: ssNode.NodeID},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	first, err := json.Marshal(compiled.Outbounds[0])
	if err != nil {
		t.Fatal(err)
	}
	wantFirst := `{"type":"socks","tag":"` + catalog.NodeTags[keyS] + `","server":"proxy.example.com","server_port":1080,"version":"5","username":"user","password":"pass","network":"udp"}`
	if string(first) != wantFirst {
		t.Fatalf("SOCKS JSON = %s, want %s", first, wantFirst)
	}

	second, err := json.Marshal(compiled.Outbounds[1])
	if err != nil {
		t.Fatal(err)
	}
	wantSecond := `{"type":"http","tag":"` + catalog.NodeTags[keyH] + `","server":"192.0.2.30","server_port":8080,"username":"bob","password":"secret"}`
	if string(second) != wantSecond {
		t.Fatalf("HTTP JSON = %s, want %s", second, wantSecond)
	}

	third, err := json.Marshal(compiled.Outbounds[2])
	if err != nil {
		t.Fatal(err)
	}
	wantThird := `{"type":"shadowsocks","tag":"` + catalog.NodeTags[keySS] + `","server":"ss.example.com","server_port":8388,"password":"ss-secret","method":"aes-256-gcm","plugin":"obfs-local","plugin_opts":"obfs=http","network":"tcp"}`
	if string(third) != wantThird {
		t.Fatalf("Shadowsocks JSON = %s, want %s", third, wantThird)
	}
}

func TestCompileBasicNodeOutboundsRejectsMissingAndDuplicateNodes(t *testing.T) {
	node := domain.Node{
		ProfileID: "profile-a",
		NodeID:    "node-a",
		Kind:      domain.NodeHTTP,
		Server:    "proxy.example.com",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}
	key := NodeTargetKey{ProfileID: node.ProfileID, NodeID: node.NodeID}
	catalog, err := NewTargetCatalog(nil, []NodeTargetKey{key})
	if err != nil {
		t.Fatal(err)
	}
	required := []domain.TargetRef{{Kind: domain.TargetSpecificNode, ProfileID: node.ProfileID, NodeID: node.NodeID}}

	if _, err := CompileBasicNodeOutbounds(nil, catalog, required); !errors.Is(err, ErrNodeClosure) {
		t.Fatalf("missing node error = %v", err)
	}
	if _, err := CompileBasicNodeOutbounds([]domain.Node{node, node}, catalog, required); !errors.Is(err, ErrDuplicateNodeSpec) {
		t.Fatalf("duplicate node error = %v", err)
	}
}

func TestCompileBasicNodeOutboundsRejectsCatalogDrift(t *testing.T) {
	node := domain.Node{
		ProfileID: "profile-a",
		NodeID:    "node-a",
		Kind:      domain.NodeHTTP,
		Server:    "proxy.example.com",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}
	catalog, err := NewTargetCatalog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileBasicNodeOutbounds([]domain.Node{node}, catalog, nil); !errors.Is(err, ErrNodeClosure) {
		t.Fatalf("catalog drift error = %v", err)
	}
}

func TestCompileBasicNodeOutboundsRejectsNonNodeRequirement(t *testing.T) {
	node := domain.Node{
		ProfileID: "profile-a",
		NodeID:    "node-a",
		Kind:      domain.NodeHTTP,
		Server:    "proxy.example.com",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}
	key := NodeTargetKey{ProfileID: node.ProfileID, NodeID: node.NodeID}
	catalog, err := NewTargetCatalog(nil, []NodeTargetKey{key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileBasicNodeOutbounds([]domain.Node{node}, catalog, []domain.TargetRef{{Kind: domain.TargetDirect}}); !errors.Is(err, ErrNodeClosure) {
		t.Fatalf("non-node requirement error = %v", err)
	}
}

func TestBasicNodeCompilerConsumesSelectionNodeClosure(t *testing.T) {
	node := domain.Node{
		ProfileID: "profile-a",
		NodeID:    "node-a",
		Kind:      domain.NodeSOCKS,
		Server:    "proxy.example.com",
		Port:      1080,
		SOCKS: &domain.SOCKSNodeOptions{
			Version: domain.SOCKS5,
			Network: domain.ProxyNetworkBoth,
		},
	}
	key := NodeTargetKey{ProfileID: node.ProfileID, NodeID: node.NodeID}
	catalog, err := NewTargetCatalog(nil, []NodeTargetKey{key})
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: node.ProfileID, NodeID: node.NodeID}
	selection, err := CompileSelectionGroups(domain.SelectionPlan{
		Current: domain.CurrentSelection{
			Members: []domain.TargetRef{ref},
			Default: ref,
		},
	}, catalog, []string{catalog.CurrentSelectedTag})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileBasicNodeOutbounds([]domain.Node{node}, catalog, selection.NodeTargets)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := compiled.Tags, selection.NodeTags; !reflect.DeepEqual(got, want) {
		t.Fatalf("node compiler tags = %#v, selection closure tags = %#v", got, want)
	}
}
