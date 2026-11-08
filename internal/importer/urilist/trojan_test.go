package urilist

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	singboximport "github.com/bbbstyyy/karing-tui-v2/internal/importer/singbox"
)

func TestTrojanURIStrictTLSAndSemanticStableIdentity(t *testing.T) {
	original := "trojan://s3cr3t@edge.example.com:443?type=tcp&security=tls&sni=cdn.example.com#Alpha"
	renamed := "trojan://s3cr3t@edge.example.com:443?sni=cdn.example.com&allowInsecure=0&security=tls&type=tcp#Renamed"
	first, err := AnalyzeBasicProfile([]byte(original), "profile-trojan")
	if err != nil || !first.CanCommit() || len(first.Nodes) != 1 {
		t.Fatalf("valid Trojan TCP/TLS source rejected: diagnostics=%+v err=%v", first.Diagnostics, err)
	}
	node := first.Nodes[0]
	if node.Kind != domain.NodeTrojan || node.Port != 443 ||
		node.Server != "edge.example.com" ||
		node.Trojan == nil || node.Trojan.Password != "s3cr3t" ||
		node.Trojan.Network != domain.ProxyNetworkTCP ||
		node.TLS == nil || !node.TLS.Enabled || node.TLS.Insecure ||
		node.TLS.ServerName != "cdn.example.com" ||
		node.Source.SourceName != "Alpha" ||
		!strings.HasPrefix(node.Source.SourceKey, "uri-") {
		t.Fatal("Trojan URI lost supported fields")
	}

	second, err := AnalyzeBasicProfile([]byte(renamed), "profile-trojan")
	if err != nil || !second.CanCommit() || len(second.Nodes) != 1 {
		t.Fatalf("equivalent Trojan URI rejected: %+v %v", second.Diagnostics, err)
	}
	if node.Source.SourceKey != second.Nodes[0].Source.SourceKey ||
		second.Nodes[0].Source.SourceName != "Renamed" {
		t.Fatalf("equivalent query/fragment changed canonical identity: %q != %q", node.Source.SourceKey, second.Nodes[0].Source.SourceKey)
	}

	// The source's canonical sing-box payload is valid without custom
	// runtime parsing and supports percent-decoded credentials.
	encoded, err := AnalyzeBasicProfile([]byte("trojan://p%40ss@edge.example.com:443#Encoded"), "profile-trojan")
	if err != nil || !encoded.CanCommit() || encoded.Nodes[0].Trojan.Password != "p@ss" {
		t.Fatalf("encoded credential not preserved: diagnostics=%+v err=%v", encoded.Diagnostics, err)
	}
	duplicate, err := AnalyzeBasicProfile([]byte(original+"\n"+renamed), "profile-trojan")
	if err != nil || duplicate.CanCommit() || len(duplicate.Diagnostics) != 1 ||
		duplicate.Diagnostics[0].Code != "duplicate_node" {
		t.Fatalf("semantic duplicate was accepted: %+v %v", duplicate, err)
	}
}

func TestTrojanURIBase64EnvelopeWorksWithoutSecondInterpretation(t *testing.T) {
	line := "trojan://secret@edge.example.com:443?security=tls&sni=edge.example.com#URI"
	wrapped := base64.StdEncoding.EncodeToString([]byte(line))
	result, err := AnalyzeBase64Profile([]byte(wrapped), "profile-trojan")
	if err != nil || !result.CanCommit() || len(result.Nodes) != 1 ||
		result.Nodes[0].Kind != domain.NodeTrojan ||
		result.Nodes[0].Trojan == nil || result.Nodes[0].Trojan.Password != "secret" {
		t.Fatalf("base64 URI Trojan import rejected: diagnostics=%+v err=%v", result.Diagnostics, err)
	}
}

func TestTrojanURIRejectsUnsupportedOrInvalidFieldsWithoutSecrets(t *testing.T) {
	for _, uri := range []string{
		"trojan://TOPSECRET@edge.example.com:443?type=ws#Unsupported",
		"trojan://TOPSECRET@edge.example.com:443?security=reality",
		"trojan://TOPSECRET@edge.example.com:443?allowInsecure=1",
		"trojan://TOPSECRET@edge.example.com:443?alpn=h2",
		"trojan://TOPSECRET@edge.example.com:443?sni=",
		"trojan://TOPSECRET@edge.example.com:443?sni=%ZZ",
		"trojan://TOPSECRET@edge.example.com:443?type=tcp&type=tcp",
		"trojan://TOPSECRET@edge.example.com:443/path",
		"trojan://TOPSECRET@edge.example.com:65536",
		"trojan://TOPSECRET:OTHERSECRET@edge.example.com:443",
		"trojan://@edge.example.com:443",
		"trojan://TOPSECRET@edge.example.com:443?transport=tcp",
		"trojan://TOPSECRET@bad%ZZ",
	} {
		analysis, err := AnalyzeBasicProfile([]byte(uri), "profile-trojan")
		if err != nil {
			t.Fatalf("malformed URI should return bounded blocking diagnostics, not raw error: %v", err)
		}
		if analysis.CanCommit() || len(analysis.Nodes) != 0 ||
			len(analysis.Diagnostics) != 1 ||
			analysis.Diagnostics[0].Level != singboximport.DiagnosticError ||
			analysis.Diagnostics[0].Code != "unsupported_or_invalid_uri" {
			t.Fatalf("Trojan URI unexpectedly accepted: %+v", analysis)
		}
		if strings.Contains(analysis.Diagnostics[0].Message, "TOPSECRET") ||
			strings.Contains(analysis.Diagnostics[0].Message, "OTHERSECRET") {
			t.Fatalf("Trojan parse diagnostics disclosed credentials: %s", analysis.Diagnostics[0].Message)
		}
	}
}

func TestTrojanURIInvalidMixedSubscriptionNeverPartiallyCommits(t *testing.T) {
	source := strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#SS",
		"trojan://TOPSECRET@edge.example.com:443?type=grpc",
	}, "\n")
	result, err := AnalyzeBasicProfile([]byte(source), "profile-trojan")
	if err != nil || result.CanCommit() || len(result.Nodes) != 1 ||
		len(result.Diagnostics) != 1 ||
		result.Diagnostics[0].Code != "unsupported_or_invalid_uri" {
		t.Fatalf("partial mixed subscription accepted: %+v %v", result, err)
	}
	if strings.Contains(result.Diagnostics[0].Message, "TOPSECRET") {
		t.Fatal("Trojan credential leaked in failed mixed source")
	}
}
