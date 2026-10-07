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
    {"type":"vmess","tag":"vmess-b","server":"example.com","server_port":443,"uuid":"00000000-0000-0000-0000-000000000000"}
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
