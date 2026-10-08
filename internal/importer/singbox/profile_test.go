package singbox

import (
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

func TestAnalyzeBasicProfileExtractsSupportedNodesAndReportsIgnoredPolicy(t *testing.T) {
	data := []byte(`{
  "inbounds":[{"type":"mixed","tag":"local","listen":"127.0.0.1","listen_port":2080,"set_system_proxy":false}],
  "outbounds":[
    {"type":"direct","tag":"direct"},
    {"type":"http","tag":"http-a","server":"127.0.0.1","server_port":8080,"username":"u","password":"p"},
    {"type":"socks","tag":"socks-b","server":"127.0.0.1","server_port":1080}
  ],
  "route":{"rules":[{"domain_suffix":["example.com"],"outbound":"direct"}]},
  "dns":{"servers":[{"tag":"dns","address":"local"}]}
}`)
	analysis, err := AnalyzeBasicProfile(data, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.CanCommit() {
		t.Fatalf("supported profile unexpectedly blocked: %+v", analysis.Diagnostics)
	}
	if len(analysis.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2: %+v", len(analysis.Nodes), analysis.Nodes)
	}
	if analysis.Nodes[0].Source.SourceKey != "http-a" || analysis.Nodes[0].Kind != domain.NodeHTTP {
		t.Fatalf("HTTP node = %+v", analysis.Nodes[0])
	}
	if analysis.Nodes[1].Source.SourceKey != "socks-b" || analysis.Nodes[1].Kind != domain.NodeSOCKS {
		t.Fatalf("SOCKS node = %+v", analysis.Nodes[1])
	}
	if analysis.Nodes[1].SOCKS.Version != domain.SOCKS5 || analysis.Nodes[1].SOCKS.Network != domain.ProxyNetworkBoth {
		t.Fatalf("SOCKS defaults = %+v", analysis.Nodes[1].SOCKS)
	}
	if analysis.SourceSHA256 == "" || len(analysis.SourceSHA256) != 64 {
		t.Fatalf("source hash = %q", analysis.SourceSHA256)
	}
	if !hasDiagnostic(analysis.Diagnostics, DiagnosticInfo, "route", "ignored_by_product_policy") {
		t.Fatalf("route policy was not reported as ignored: %+v", analysis.Diagnostics)
	}
	if !hasDiagnostic(analysis.Diagnostics, DiagnosticInfo, "dns", "ignored_by_product_policy") {
		t.Fatalf("DNS policy was not reported as ignored: %+v", analysis.Diagnostics)
	}
	if !hasDiagnostic(analysis.Diagnostics, DiagnosticInfo, "outbounds[0]", "non_node_outbound_ignored") {
		t.Fatalf("direct outbound ignore was not reported: %+v", analysis.Diagnostics)
	}

	nodes, hash, ok := analysis.SnapshotNodes()
	if !ok || hash != analysis.SourceSHA256 || len(nodes) != 2 {
		t.Fatalf("snapshot nodes = %+v hash=%q ok=%v", nodes, hash, ok)
	}
}

func TestAnalyzeBasicProfileShadowsocksPreservesSupportedFields(t *testing.T) {
	data := []byte(`{
  "outbounds":[{
    "type":"shadowsocks",
    "tag":"ss-a",
    "server":"ss.example.com",
    "server_port":8388,
    "method":"aes-256-gcm",
    "password":"secret",
    "plugin":"obfs-local",
    "plugin_opts":"obfs=http;obfs-host=example.com",
    "network":["tcp","udp"]
  }]
}`)
	analysis, err := AnalyzeBasicProfile(data, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.CanCommit() || len(analysis.Nodes) != 1 {
		t.Fatalf("Shadowsocks analysis = %+v", analysis)
	}
	imported := analysis.Nodes[0]
	if imported.Kind != domain.NodeShadowsocks ||
		imported.Shadowsocks == nil ||
		imported.Shadowsocks.Method != "aes-256-gcm" ||
		imported.Shadowsocks.Password != "secret" ||
		imported.Shadowsocks.Plugin != "obfs-local" ||
		imported.Shadowsocks.PluginOptions != "obfs=http;obfs-host=example.com" ||
		imported.Shadowsocks.Network != domain.ProxyNetworkBoth {
		t.Fatalf("Shadowsocks node = %+v", imported)
	}

	identity := profile.NodeIdentity{
		ProfileID:  "profile-a",
		NodeID:     "stable-ss",
		SourceKey:  "ss-a",
		SourceName: "ss-a",
	}
	node, err := DecodeBasicNode(imported.Source.PayloadJSON, identity)
	if err != nil {
		t.Fatal(err)
	}
	if node.NodeID != "stable-ss" ||
		node.Kind != domain.NodeShadowsocks ||
		node.Shadowsocks == nil ||
		node.Shadowsocks.PluginOptions != imported.Shadowsocks.PluginOptions {
		t.Fatalf("decoded Shadowsocks node = %+v", node)
	}
}

func TestAnalyzeBasicProfileBlocksUnsupportedShadowsocksExtensions(t *testing.T) {
	data := []byte(`{
  "outbounds":[{
    "type":"shadowsocks",
    "tag":"ss-a",
    "server":"ss.example.com",
    "server_port":8388,
    "method":"aes-256-gcm",
    "password":"secret",
    "udp_over_tcp":{"enabled":true}
  }]
}`)
	analysis, err := AnalyzeBasicProfile(data, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if analysis.CanCommit() || len(analysis.Nodes) != 0 {
		t.Fatalf("Shadowsocks extension was silently accepted: %+v", analysis)
	}
	if !hasDiagnostic(
		analysis.Diagnostics,
		DiagnosticError,
		"outbounds[0]",
		"unsupported_or_invalid_node",
	) {
		t.Fatalf("Shadowsocks extension diagnostic = %+v", analysis.Diagnostics)
	}
	if !strings.Contains(
		analysis.Diagnostics[len(analysis.Diagnostics)-1].Message,
		"udp_over_tcp",
	) {
		t.Fatalf("unsupported Shadowsocks field not reported: %+v", analysis.Diagnostics)
	}
}

func TestAnalyzeBasicProfileVMessPreservesApprovedBasicFields(t *testing.T) {
	data := []byte(`{
  "outbounds":[{
    "type":"vmess",
    "tag":"vmess-a",
    "server":"vmess.example.com",
    "server_port":10086,
    "uuid":"11111111-2222-3333-4444-555555555555",
    "security":"aes-128-gcm",
    "alter_id":1,
    "global_padding":true,
    "authenticated_length":true,
    "network":["tcp","udp"],
    "packet_encoding":"xudp"
  }]
}`)
	analysis, err := AnalyzeBasicProfile(data, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.CanCommit() || len(analysis.Nodes) != 1 {
		t.Fatalf("VMess analysis = %+v", analysis)
	}
	imported := analysis.Nodes[0]
	if imported.Kind != domain.NodeVMess ||
		imported.VMess == nil ||
		imported.VMess.UUID != "11111111-2222-3333-4444-555555555555" ||
		imported.VMess.Security != "aes-128-gcm" ||
		imported.VMess.AlterID != 1 ||
		!imported.VMess.GlobalPadding ||
		!imported.VMess.AuthenticatedLength ||
		imported.VMess.Network != domain.ProxyNetworkBoth ||
		imported.VMess.PacketEncoding != "xudp" {
		t.Fatalf("VMess node = %+v", imported)
	}

	node, err := DecodeBasicNode(imported.Source.PayloadJSON, profile.NodeIdentity{
		ProfileID:  "profile-a",
		NodeID:     "stable-vmess",
		SourceKey:  "vmess-a",
		SourceName: "vmess-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.NodeID != "stable-vmess" ||
		node.Kind != domain.NodeVMess ||
		node.VMess == nil ||
		node.VMess.PacketEncoding != "xudp" {
		t.Fatalf("decoded VMess node = %+v", node)
	}
}

func TestAnalyzeBasicProfileBlocksUnsupportedVMessExtensions(t *testing.T) {
	for _, field := range []string{
		`"tls":{"enabled":true}`,
		`"transport":{"type":"ws","path":"/ws"}`,
		`"multiplex":{"enabled":true}`,
		`"detour":"bootstrap"`,
	} {
		data := []byte(`{
  "outbounds":[{
    "type":"vmess",
    "tag":"vmess-a",
    "server":"vmess.example.com",
    "server_port":10086,
    "uuid":"11111111-2222-3333-4444-555555555555",
    "security":"auto",
    ` + field + `
  }]
}`)
		analysis, err := AnalyzeBasicProfile(data, "profile-a")
		if err != nil {
			t.Fatal(err)
		}
		if analysis.CanCommit() || len(analysis.Nodes) != 0 {
			t.Fatalf("VMess extension %s was silently accepted: %+v", field, analysis)
		}
		if !hasDiagnostic(
			analysis.Diagnostics,
			DiagnosticError,
			"outbounds[0]",
			"unsupported_or_invalid_node",
		) {
			t.Fatalf("VMess extension diagnostic for %s = %+v", field, analysis.Diagnostics)
		}
	}
}

func TestAnalyzeBasicProfileTrojanPreservesSupportedFields(t *testing.T) {
	data := []byte(`{
  "outbounds":[{
    "type":"trojan",
    "tag":"trojan-a",
    "server":"trojan.example.com",
    "server_port":443,
    "password":"secret",
    "network":["tcp","udp"]
  }]
}`)
	analysis, err := AnalyzeBasicProfile(data, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.CanCommit() || len(analysis.Nodes) != 1 {
		t.Fatalf("Trojan analysis = %+v", analysis)
	}
	imported := analysis.Nodes[0]
	if imported.Kind != domain.NodeTrojan ||
		imported.Trojan == nil ||
		imported.Trojan.Password != "secret" ||
		imported.Trojan.Network != domain.ProxyNetworkBoth {
		t.Fatalf("Trojan node = %+v", imported)
	}

	node, err := DecodeBasicNode(imported.Source.PayloadJSON, profile.NodeIdentity{
		ProfileID:  "profile-a",
		NodeID:     "stable-trojan",
		SourceKey:  "trojan-a",
		SourceName: "trojan-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.NodeID != "stable-trojan" ||
		node.Kind != domain.NodeTrojan ||
		node.Trojan == nil ||
		node.Trojan.Password != "secret" {
		t.Fatalf("decoded Trojan node = %+v", node)
	}
}

func TestAnalyzeBasicProfileBlocksUnsupportedTrojanExtensions(t *testing.T) {
	for _, field := range []string{
		`"tls":{"enabled":true}`,
		`"transport":{"type":"ws","path":"/ws"}`,
		`"multiplex":{"enabled":true}`,
		`"detour":"bootstrap"`,
	} {
		data := []byte(`{
  "outbounds":[{
    "type":"trojan",
    "tag":"trojan-a",
    "server":"trojan.example.com",
    "server_port":443,
    "password":"secret",
    ` + field + `
  }]
}`)
		analysis, err := AnalyzeBasicProfile(data, "profile-a")
		if err != nil {
			t.Fatal(err)
		}
		if analysis.CanCommit() || len(analysis.Nodes) != 0 {
			t.Fatalf("Trojan extension %s was silently accepted: %+v", field, analysis)
		}
		if !hasDiagnostic(
			analysis.Diagnostics,
			DiagnosticError,
			"outbounds[0]",
			"unsupported_or_invalid_node",
		) {
			t.Fatalf("Trojan extension diagnostic for %s = %+v", field, analysis.Diagnostics)
		}
	}
}

func TestAnalyzeBasicProfileVLESSPreservesPacketEncodingPresence(t *testing.T) {
	data := []byte(`{
  "outbounds":[
    {
      "type":"vless",
      "tag":"vless-default",
      "server":"vless.example.com",
      "server_port":443,
      "uuid":"11111111-2222-3333-4444-555555555555",
      "network":["tcp","udp"]
    },
    {
      "type":"vless",
      "tag":"vless-none",
      "server":"192.0.2.44",
      "server_port":8443,
      "uuid":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
      "encryption":"none",
      "network":"udp",
      "packet_encoding":""
    }
  ]
}`)
	analysis, err := AnalyzeBasicProfile(data, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.CanCommit() || len(analysis.Nodes) != 2 {
		t.Fatalf("VLESS analysis = %+v", analysis)
	}
	first := analysis.Nodes[0]
	if first.Kind != domain.NodeVLESS ||
		first.VLESS == nil ||
		first.VLESS.PacketEncoding != nil ||
		first.VLESS.Network != domain.ProxyNetworkBoth {
		t.Fatalf("default VLESS node = %+v", first)
	}
	second := analysis.Nodes[1]
	if second.Kind != domain.NodeVLESS ||
		second.VLESS == nil ||
		second.VLESS.Encryption != "none" ||
		second.VLESS.Network != domain.ProxyNetworkUDP ||
		second.VLESS.PacketEncoding == nil ||
		*second.VLESS.PacketEncoding != "" {
		t.Fatalf("explicit VLESS node = %+v", second)
	}

	node, err := DecodeBasicNode(second.Source.PayloadJSON, profile.NodeIdentity{
		ProfileID:  "profile-a",
		NodeID:     "stable-vless",
		SourceKey:  "vless-none",
		SourceName: "vless-none",
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.NodeID != "stable-vless" ||
		node.Kind != domain.NodeVLESS ||
		node.VLESS == nil ||
		node.VLESS.PacketEncoding == nil ||
		*node.VLESS.PacketEncoding != "" {
		t.Fatalf("decoded VLESS node = %+v", node)
	}
}

func TestAnalyzeBasicProfileBlocksUnsupportedVLESSExtensions(t *testing.T) {
	for _, field := range []string{
		`"tls":{"enabled":true}`,
		`"transport":{"type":"ws","path":"/ws"}`,
		`"multiplex":{"enabled":true}`,
		`"detour":"bootstrap"`,
		`"flow":"xtls-rprx-vision"`,
		`"encryption":"mlkem768x25519plus.native.1rtt.invalid"`,
	} {
		data := []byte(`{
  "outbounds":[{
    "type":"vless",
    "tag":"vless-a",
    "server":"vless.example.com",
    "server_port":443,
    "uuid":"11111111-2222-3333-4444-555555555555",
    ` + field + `
  }]
}`)
		analysis, err := AnalyzeBasicProfile(data, "profile-a")
		if err != nil {
			t.Fatal(err)
		}
		if analysis.CanCommit() || len(analysis.Nodes) != 0 {
			t.Fatalf("VLESS extension %s was silently accepted: %+v", field, analysis)
		}
		if !hasDiagnostic(
			analysis.Diagnostics,
			DiagnosticError,
			"outbounds[0]",
			"unsupported_or_invalid_node",
		) {
			t.Fatalf("VLESS extension diagnostic for %s = %+v", field, analysis.Diagnostics)
		}
	}
}

func TestAnalyzeBasicProfileAcceptsCoreNetworkListArray(t *testing.T) {
	data := []byte(`{
  "outbounds":[{
    "type":"socks",
    "tag":"socks-a",
    "server":"127.0.0.1",
    "server_port":1080,
    "network":["udp","tcp"]
  }]
}`)
	analysis, err := AnalyzeBasicProfile(data, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.CanCommit() ||
		len(analysis.Nodes) != 1 ||
		analysis.Nodes[0].SOCKS == nil ||
		analysis.Nodes[0].SOCKS.Network != domain.ProxyNetworkBoth {
		t.Fatalf("network-list analysis = %+v", analysis)
	}
}

func TestAnalyzeBasicProfileRejectsUnsupportedNodeFieldsWithoutPartialApply(t *testing.T) {
	data := []byte(`{
  "outbounds":[
    {"type":"http","tag":"secure-http","server":"proxy.example","server_port":443,"tls":{"enabled":true}}
  ]
}`)
	analysis, err := AnalyzeBasicProfile(data, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if analysis.CanCommit() {
		t.Fatalf("TLS-bearing node was silently accepted: %+v", analysis)
	}
	if len(analysis.Nodes) != 0 {
		t.Fatalf("unsupported node leaked into materialized nodes: %+v", analysis.Nodes)
	}
	if !hasDiagnostic(analysis.Diagnostics, DiagnosticError, "outbounds[0]", "unsupported_or_invalid_node") {
		t.Fatalf("unsupported TLS field diagnostic = %+v", analysis.Diagnostics)
	}
	if !strings.Contains(analysis.Diagnostics[len(analysis.Diagnostics)-1].Message, "tls") {
		t.Fatalf("unsupported field path not visible: %+v", analysis.Diagnostics)
	}
	if nodes, _, ok := analysis.SnapshotNodes(); ok || nodes != nil {
		t.Fatalf("blocked analysis produced snapshot nodes: %+v ok=%v", nodes, ok)
	}
}

func TestAnalyzeBasicProfileBlocksUnknownProxyProtocolEvenWithSupportedNodes(t *testing.T) {
	data := []byte(`{
  "outbounds":[
    {"type":"http","tag":"http-a","server":"127.0.0.1","server_port":8080},
    {"type":"hysteria2","tag":"hysteria-b","server":"example.com","server_port":443,"password":"secret"}
  ]
}`)
	analysis, err := AnalyzeBasicProfile(data, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Nodes) != 1 {
		t.Fatalf("supported node analysis changed: %+v", analysis.Nodes)
	}
	if analysis.CanCommit() {
		t.Fatalf("partial protocol support was treated as complete: %+v", analysis.Diagnostics)
	}
	if !hasDiagnostic(analysis.Diagnostics, DiagnosticError, "outbounds[1].type", "unsupported_proxy_protocol") {
		t.Fatalf("unsupported protocol diagnostic = %+v", analysis.Diagnostics)
	}
}

func TestAnalyzeBasicProfileRejectsDuplicateSupportedTags(t *testing.T) {
	data := []byte(`{
  "outbounds":[
    {"type":"http","tag":"dup","server":"127.0.0.1","server_port":8080},
    {"type":"socks","tag":"dup","server":"127.0.0.1","server_port":1080}
  ]
}`)
	analysis, err := AnalyzeBasicProfile(data, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if analysis.CanCommit() {
		t.Fatalf("duplicate tags were accepted: %+v", analysis.Diagnostics)
	}
	if !hasDiagnostic(analysis.Diagnostics, DiagnosticError, "outbounds[1].tag", "duplicate_tag") {
		t.Fatalf("duplicate tag diagnostic = %+v", analysis.Diagnostics)
	}
}

func TestAnalyzeBasicProfileRejectsPrivilegedInboundBeforeNodeImport(t *testing.T) {
	data := []byte(`{
  "inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],
  "outbounds":[{"type":"http","tag":"http-a","server":"127.0.0.1","server_port":8080}]
}`)
	_, err := AnalyzeBasicProfile(data, "profile-a")
	if !errors.Is(err, ErrPrivilegedNetworkFeature) {
		t.Fatalf("privileged profile error = %v", err)
	}
}

func TestBasicNodeMaterializeUsesReconciledIdentity(t *testing.T) {
	analysis, err := AnalyzeBasicProfile([]byte(`{
  "outbounds":[{"type":"http","tag":"http-a","server":"127.0.0.1","server_port":8080}]
}`), "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.CanCommit() || len(analysis.Nodes) != 1 {
		t.Fatalf("analysis = %+v", analysis)
	}
	node, err := analysis.Nodes[0].Materialize(profile.NodeIdentity{
		ProfileID:  "profile-a",
		NodeID:     "preserved-legacy-id",
		SourceKey:  "http-a",
		SourceName: "http-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.ProfileID != "profile-a" || node.NodeID != "preserved-legacy-id" || node.Kind != domain.NodeHTTP {
		t.Fatalf("materialized node = %+v", node)
	}
	if _, err := analysis.Nodes[0].Materialize(profile.NodeIdentity{
		ProfileID: "profile-a", NodeID: "x", SourceKey: "wrong",
	}); err == nil {
		t.Fatal("mismatched source identity was accepted")
	}
}

func hasDiagnostic(items []Diagnostic, level DiagnosticLevel, path, code string) bool {
	for _, item := range items {
		if item.Level == level && item.Path == path && item.Code == code {
			return true
		}
	}
	return false
}
