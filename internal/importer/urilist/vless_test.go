package urilist

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	singboximport "github.com/bbbstyyy/karing-tui-v2/internal/importer/singbox"
)

const testVLESSUUID = "01234567-89ab-cdef-0123-456789abcdef"

func TestVLESSURIStrictTCPVerifiedTLSAndCanonicalIdentity(t *testing.T) {
	original := "vless://" + testVLESSUUID +
		"@edge.example.com:443?encryption=none&security=tls&type=tcp&sni=cdn.example.com#Primary"
	equivalent := "vless://0123456789ABCDEF0123456789ABCDEF@edge.example.com:443" +
		"?sni=cdn.example.com&allowInsecure=false&type=tcp&security=tls&encryption=none#Renamed"
	first, err := AnalyzeBasicProfile([]byte(original), "profile-vless")
	if err != nil || !first.CanCommit() || len(first.Nodes) != 1 {
		t.Fatalf("valid VLESS TCP/TLS rejected: diagnostics=%+v err=%v", first.Diagnostics, err)
	}
	node := first.Nodes[0]
	if node.Kind != domain.NodeVLESS || node.Server != "edge.example.com" ||
		node.Port != 443 || node.VLESS == nil ||
		node.VLESS.UUID != testVLESSUUID || node.VLESS.Encryption != "none" ||
		node.VLESS.Network != domain.ProxyNetworkTCP ||
		node.VLESS.Flow != "" || node.VLESS.PacketEncoding != nil ||
		node.TLS == nil || !node.TLS.Enabled || node.TLS.Insecure ||
		node.TLS.DisableSNI || node.TLS.ServerName != "cdn.example.com" ||
		node.Source.SourceName != "Primary" ||
		!strings.HasPrefix(node.Source.SourceKey, "uri-") {
		t.Fatal("VLESS URI lost a verified field or enabled unsupported behavior")
	}
	second, err := AnalyzeBasicProfile([]byte(equivalent), "profile-vless")
	if err != nil || !second.CanCommit() || len(second.Nodes) != 1 {
		t.Fatalf("semantically equivalent VLESS URI rejected: diagnostics=%+v err=%v", second.Diagnostics, err)
	}
	if node.Source.SourceKey != second.Nodes[0].Source.SourceKey ||
		second.Nodes[0].Source.SourceName != "Renamed" {
		t.Fatal("query order, explicit safe default, UUID case or fragment changed VLESS identity")
	}
	duplicate, err := AnalyzeBasicProfile([]byte(original+"\n"+equivalent), "profile-vless")
	if err != nil || duplicate.CanCommit() || len(duplicate.Diagnostics) != 1 ||
		duplicate.Diagnostics[0].Code != "duplicate_node" {
		t.Fatalf("VLESS semantic duplicate was accepted: diagnostics=%+v err=%v", duplicate.Diagnostics, err)
	}
}

func TestVLESSURIBase64EnvelopeAndExplicitDefaults(t *testing.T) {
	line := "vless://" + testVLESSUUID +
		"@edge.example.com:443?security=tls&encryption=none#VLESS"
	wrapped := base64.StdEncoding.EncodeToString([]byte(line))
	result, err := AnalyzeBase64Profile([]byte(wrapped), "profile-vless")
	if err != nil || !result.CanCommit() || len(result.Nodes) != 1 ||
		result.Nodes[0].Kind != domain.NodeVLESS ||
		result.Nodes[0].VLESS == nil ||
		result.Nodes[0].VLESS.UUID != testVLESSUUID ||
		result.Nodes[0].VLESS.Network != domain.ProxyNetworkTCP ||
		result.Nodes[0].TLS == nil || !result.Nodes[0].TLS.Enabled ||
		result.Nodes[0].TLS.Insecure {
		t.Fatalf("base64 VLESS TCP/TLS import rejected: diagnostics=%+v err=%v", result.Diagnostics, err)
	}
}

func TestVLESSURIRejectsUnsupportedTLSAndTransportWithoutUUIDDisclosure(t *testing.T) {
	base := "vless://" + testVLESSUUID + "@edge.example.com:443"
	for _, suffix := range []string{
		"?security=none&encryption=none",
		"?security=reality&encryption=none",
		"?security=tls&encryption=auto",
		"?security=tls",
		"?encryption=none",
		"?security=tls&encryption=none&type=ws",
		"?security=tls&encryption=none&type=grpc",
		"?security=tls&encryption=none&flow=xtls-rprx-vision",
		"?security=tls&encryption=none&fp=chrome",
		"?security=tls&encryption=none&alpn=h2",
		"?security=tls&encryption=none&allowInsecure=1",
		"?security=tls&encryption=none&allowInsecure=true",
		"?security=tls&encryption=none&sni=",
		"?security=tls&encryption=none&sni=%ZZ",
		"?security=tls&encryption=none&packetEncoding=xudp",
		"?security=tls&encryption=none&path=/socket",
		"?security=tls&encryption=none&serviceName=rpc",
		"?security=tls&encryption=none&type=tcp&type=tcp",
		"?security=tls&encryption=none&security=tls",
		"?security=tls&encryption=none&host=cdn.example.com",
		"?security=tls&encryption=none&allowInsecure=0&allowInsecure=false",
	} {
		analysis, err := AnalyzeBasicProfile([]byte(base+suffix), "profile-vless")
		if err != nil || analysis.CanCommit() || len(analysis.Nodes) != 0 ||
			len(analysis.Diagnostics) != 1 ||
			analysis.Diagnostics[0].Level != singboximport.DiagnosticError ||
			analysis.Diagnostics[0].Code != "unsupported_or_invalid_uri" {
			t.Fatalf("unsafe VLESS URI accepted: diagnostics=%+v err=%v", analysis.Diagnostics, err)
		}
		if strings.Contains(analysis.Diagnostics[0].Message, testVLESSUUID) {
			t.Fatal("VLESS diagnostic leaked source UUID")
		}
	}
	for _, uri := range []string{
		"vless://@edge.example.com:443?security=tls&encryption=none",
		"vless://TOP_SECRET@edge.example.com:443?security=tls&encryption=none",
		"vless://" + testVLESSUUID + ":TOP_SECRET@edge.example.com:443?security=tls&encryption=none",
		"vless://" + testVLESSUUID + "@edge.example.com:0?security=tls&encryption=none",
		"vless://" + testVLESSUUID + "@edge.example.com:65536?security=tls&encryption=none",
		"vless://" + testVLESSUUID + "@edge.example.com:443/secret?security=tls&encryption=none",
		"vless://" + testVLESSUUID + "@bad%ZZ?security=tls&encryption=none",
		"vless://01234567-89ab-cdef-0123-456789abcdeg@edge.example.com:443?security=tls&encryption=none",
	} {
		result, err := AnalyzeBasicProfile([]byte(uri), "profile-vless")
		if err != nil || result.CanCommit() || len(result.Nodes) != 0 ||
			len(result.Diagnostics) != 1 ||
			result.Diagnostics[0].Code != "unsupported_or_invalid_uri" {
			t.Fatalf("malformed VLESS URI accepted: diagnostics=%+v err=%v", result.Diagnostics, err)
		}
		if strings.Contains(result.Diagnostics[0].Message, "TOP_SECRET") ||
			strings.Contains(result.Diagnostics[0].Message, testVLESSUUID) {
			t.Fatal("invalid VLESS URL error leaked credential or UUID")
		}
	}
}

func TestVLESSMixedURIListRejectsPartialSnapshot(t *testing.T) {
	valid := "vless://" + testVLESSUUID +
		"@edge.example.com:443?security=tls&encryption=none#Good"
	mixed := valid + "\n" + "vless://" + testVLESSUUID +
		"@edge.example.com:443?security=reality&encryption=none#Bad"
	result, err := AnalyzeBasicProfile([]byte(mixed), "profile-vless")
	if err != nil || result.CanCommit() || len(result.Nodes) != 1 ||
		len(result.Diagnostics) != 1 ||
		result.Diagnostics[0].Code != "unsupported_or_invalid_uri" {
		t.Fatalf("VLESS mixed-source atomic failure was lost: diagnostics=%+v err=%v", result.Diagnostics, err)
	}
	if strings.Contains(result.Diagnostics[0].Message, testVLESSUUID) {
		t.Fatal("mixed-subscription diagnostics leaked UUID")
	}
}
