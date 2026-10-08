package declaration

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestReplaceProfileNodesV1PreservesStableReferenceAndUpdatesPayload(t *testing.T) {
	replacement, err := ReplaceProfileNodesV1(minimalDeclaration(), "p1", []domain.Node{{
		ProfileID: "p1",
		NodeID:    "n1",
		Kind:      domain.NodeHTTP,
		Server:    "127.0.0.1",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{Username: "u", Password: "p"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := replacement.Impact.RetainedNodeIDs, []string{"n1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retained nodes = %#v, want %#v", got, want)
	}
	if len(replacement.Impact.AddedNodeIDs) != 0 || len(replacement.Impact.RemovedNodeIDs) != 0 {
		t.Fatalf("unexpected replacement impact: %+v", replacement.Impact)
	}
	model, err := ParseV1(replacement.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 1 || model.Nodes[0].Port != 8080 ||
		model.Nodes[0].HTTP == nil ||
		model.Nodes[0].HTTP.Username != "u" ||
		model.Selection.Current.Default.NodeID != "n1" {
		t.Fatalf("replacement model = %+v", model)
	}
}

func TestReplaceProfileNodesV1ReportsRemovedReferenceAndFailsClosed(t *testing.T) {
	replacement, err := ReplaceProfileNodesV1(minimalDeclaration(), "p1", []domain.Node{{
		ProfileID: "p1",
		NodeID:    "n2",
		Kind:      domain.NodeHTTP,
		Server:    "127.0.0.1",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}})
	if !errors.Is(err, ErrProfileNodeReplacementInvalid) {
		t.Fatalf("removed referenced node error = %v", err)
	}
	if len(replacement.Document) == 0 {
		t.Fatal("failed replacement did not return inspectable candidate document")
	}
	if got, want := replacement.Impact.AddedNodeIDs, []string{"n2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("added nodes = %#v, want %#v", got, want)
	}
	if got, want := replacement.Impact.RemovedNodeIDs, []string{"n1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("removed nodes = %#v, want %#v", got, want)
	}
	if len(replacement.Impact.RetainedNodeIDs) != 0 {
		t.Fatalf("retained nodes = %#v", replacement.Impact.RetainedNodeIDs)
	}
}

func TestReplaceProfileNodesV1AppendsNewProfileWithoutChangingExistingOrder(t *testing.T) {
	replacement, err := ReplaceProfileNodesV1(minimalDeclaration(), "p2", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "n2",
		Kind:      domain.NodeSOCKS,
		Server:    "127.0.0.1",
		Port:      1080,
		SOCKS: &domain.SOCKSNodeOptions{
			Version: domain.SOCKS5,
			Network: domain.ProxyNetworkBoth,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := ParseV1(replacement.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 2 ||
		model.Nodes[0].ProfileID != "p1" ||
		model.Nodes[0].NodeID != "n1" ||
		model.Nodes[1].ProfileID != "p2" ||
		model.Nodes[1].NodeID != "n2" {
		t.Fatalf("node order = %+v", model.Nodes)
	}
	if got, want := replacement.Impact.AddedNodeIDs, []string{"n2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("impact = %+v", replacement.Impact)
	}
}

func TestReplaceProfileNodesV1RoundTripsShadowsocksFields(t *testing.T) {
	replacement, err := ReplaceProfileNodesV1(minimalDeclaration(), "p2", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "ss-1",
		Kind:      domain.NodeShadowsocks,
		Server:    "ss.example.com",
		Port:      8388,
		Shadowsocks: &domain.ShadowsocksNodeOptions{
			Method:        "aes-256-gcm",
			Password:      "secret",
			Plugin:        "obfs-local",
			PluginOptions: "obfs=http",
			Network:       domain.ProxyNetworkUDP,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := ParseV1(replacement.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 2 {
		t.Fatalf("nodes = %+v", model.Nodes)
	}
	node := model.Nodes[1]
	if node.Kind != domain.NodeShadowsocks ||
		node.Shadowsocks == nil ||
		node.Shadowsocks.Method != "aes-256-gcm" ||
		node.Shadowsocks.Password != "secret" ||
		node.Shadowsocks.Plugin != "obfs-local" ||
		node.Shadowsocks.PluginOptions != "obfs=http" ||
		node.Shadowsocks.Network != domain.ProxyNetworkUDP {
		t.Fatalf("Shadowsocks declaration node = %+v", node)
	}
}

func TestReplaceProfileNodesV1RoundTripsVMessFields(t *testing.T) {
	replacement, err := ReplaceProfileNodesV1(minimalDeclaration(), "p2", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "vmess-1",
		Kind:      domain.NodeVMess,
		Server:    "vmess.example.com",
		Port:      10086,
		VMess: &domain.VMessNodeOptions{
			UUID:                "11111111-2222-3333-4444-555555555555",
			Security:            "aes-128-gcm",
			AlterID:             1,
			GlobalPadding:       true,
			AuthenticatedLength: true,
			Network:             domain.ProxyNetworkUDP,
			PacketEncoding:      "xudp",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := ParseV1(replacement.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 2 {
		t.Fatalf("nodes = %+v", model.Nodes)
	}
	node := model.Nodes[1]
	if node.Kind != domain.NodeVMess ||
		node.VMess == nil ||
		node.VMess.UUID != "11111111-2222-3333-4444-555555555555" ||
		node.VMess.Security != "aes-128-gcm" ||
		node.VMess.AlterID != 1 ||
		!node.VMess.GlobalPadding ||
		!node.VMess.AuthenticatedLength ||
		node.VMess.Network != domain.ProxyNetworkUDP ||
		node.VMess.PacketEncoding != "xudp" {
		t.Fatalf("VMess declaration node = %+v", node)
	}
}

func TestReplaceProfileNodesV1RoundTripsVLESSPacketEncodingPresence(t *testing.T) {
	explicitNone := ""
	replacement, err := ReplaceProfileNodesV1(minimalDeclaration(), "p2", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "vless-1",
		Kind:      domain.NodeVLESS,
		Server:    "vless.example.com",
		Port:      443,
		VLESS: &domain.VLESSNodeOptions{
			UUID:           "11111111-2222-3333-4444-555555555555",
			Encryption:     "none",
			Network:        domain.ProxyNetworkUDP,
			PacketEncoding: &explicitNone,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := ParseV1(replacement.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 2 {
		t.Fatalf("nodes = %+v", model.Nodes)
	}
	node := model.Nodes[1]
	if node.Kind != domain.NodeVLESS ||
		node.VLESS == nil ||
		node.VLESS.UUID != "11111111-2222-3333-4444-555555555555" ||
		node.VLESS.Encryption != "none" ||
		node.VLESS.Network != domain.ProxyNetworkUDP ||
		node.VLESS.PacketEncoding == nil ||
		*node.VLESS.PacketEncoding != "" {
		t.Fatalf("VLESS declaration node = %+v", node)
	}

	defaultEncoding, err := ReplaceProfileNodesV1(replacement.Document, "p2", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "vless-1",
		Kind:      domain.NodeVLESS,
		Server:    "vless.example.com",
		Port:      443,
		VLESS: &domain.VLESSNodeOptions{
			UUID:    "11111111-2222-3333-4444-555555555555",
			Network: domain.ProxyNetworkBoth,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err = ParseV1(defaultEncoding.Document)
	if err != nil {
		t.Fatal(err)
	}
	if model.Nodes[1].VLESS == nil || model.Nodes[1].VLESS.PacketEncoding != nil {
		t.Fatalf("VLESS omitted packet encoding was not preserved: %+v", model.Nodes[1])
	}
}

func TestReplaceProfileNodesV1RoundTripsTrojanFields(t *testing.T) {
	replacement, err := ReplaceProfileNodesV1(minimalDeclaration(), "p2", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "trojan-1",
		Kind:      domain.NodeTrojan,
		Server:    "trojan.example.com",
		Port:      443,
		Trojan: &domain.TrojanNodeOptions{
			Password: "secret",
			Network:  domain.ProxyNetworkUDP,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := ParseV1(replacement.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 2 {
		t.Fatalf("nodes = %+v", model.Nodes)
	}
	node := model.Nodes[1]
	if node.Kind != domain.NodeTrojan ||
		node.Trojan == nil ||
		node.Trojan.Password != "secret" ||
		node.Trojan.Network != domain.ProxyNetworkUDP {
		t.Fatalf("Trojan declaration node = %+v", node)
	}
}

func TestReplaceProfileNodesV1RejectsCrossProfileReplacement(t *testing.T) {
	_, err := ReplaceProfileNodesV1(minimalDeclaration(), "p1", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "n2",
		Kind:      domain.NodeHTTP,
		Server:    "127.0.0.1",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}})
	if err == nil {
		t.Fatal("cross-profile replacement was accepted")
	}
}

func TestReplaceProfileNodesV1CanRemoveUnreferencedProfile(t *testing.T) {
	withP2, err := ReplaceProfileNodesV1(minimalDeclaration(), "p2", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "n2",
		Kind:      domain.NodeHTTP,
		Server:    "127.0.0.1",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := ReplaceProfileNodesV1(withP2.Document, "p2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := removed.Impact.RemovedNodeIDs, []string{"n2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("removed impact = %+v", removed.Impact)
	}
	model, err := ParseV1(removed.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 1 || model.Nodes[0].ProfileID != "p1" {
		t.Fatalf("unreferenced profile removal changed other nodes: %+v", model.Nodes)
	}
}
