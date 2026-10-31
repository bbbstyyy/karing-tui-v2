package urilist

import (
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	singboximport "github.com/bbbstyyy/karing-tui-v2/internal/importer/singbox"
)

func TestAnalyzeBasicProfileImportsShadowsocksSIP002(t *testing.T) {
	data := []byte(`
# provider comment
ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#Alpha

ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwQHNzOncwcmQ@[2001:db8::1]:443?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#Beta
`)
	analysis, err := AnalyzeBasicProfile(data, "profile-uri")
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.CanCommit() || len(analysis.Nodes) != 2 {
		t.Fatalf("URI-list analysis = %+v", analysis)
	}
	first := analysis.Nodes[0]
	if first.Kind != domain.NodeShadowsocks ||
		first.Server != "ss.example.com" ||
		first.Port != 8388 ||
		first.Shadowsocks == nil ||
		first.Shadowsocks.Method != "aes-256-gcm" ||
		first.Shadowsocks.Password != "secret" ||
		first.Source.SourceName != "Alpha" ||
		!strings.HasPrefix(first.Source.SourceKey, "uri-") {
		t.Fatalf("first SIP002 node = %+v", first)
	}
	second := analysis.Nodes[1]
	if second.Kind != domain.NodeShadowsocks ||
		second.Server != "2001:db8::1" ||
		second.Port != 443 ||
		second.Shadowsocks == nil ||
		second.Shadowsocks.Method != "chacha20-ietf-poly1305" ||
		second.Shadowsocks.Password != "p@ss:w0rd" ||
		second.Shadowsocks.Plugin != "obfs-local" ||
		second.Shadowsocks.PluginOptions != "obfs=http;obfs-host=example.com" ||
		second.Source.SourceName != "Beta" {
		t.Fatalf("second SIP002 node = %+v", second)
	}
	if analysis.SourceSHA256 == "" || len(analysis.SourceSHA256) != 64 {
		t.Fatalf("source hash = %q", analysis.SourceSHA256)
	}
}

func TestAnalyzeBasicProfileKeepsNodeIdentityAcrossFragmentRename(t *testing.T) {
	first, err := AnalyzeBasicProfile([]byte(
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#Before",
	), "profile-uri")
	if err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeBasicProfile([]byte(
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#After",
	), "profile-uri")
	if err != nil {
		t.Fatal(err)
	}
	if !first.CanCommit() || !second.CanCommit() {
		t.Fatalf("rename analyses first=%+v second=%+v", first, second)
	}
	if first.Nodes[0].Source.SourceKey != second.Nodes[0].Source.SourceKey {
		t.Fatalf(
			"fragment rename changed source key: %q -> %q",
			first.Nodes[0].Source.SourceKey,
			second.Nodes[0].Source.SourceKey,
		)
	}
	if first.Nodes[0].Source.SourceName != "Before" ||
		second.Nodes[0].Source.SourceName != "After" {
		t.Fatalf("fragment names were not preserved: first=%+v second=%+v", first.Nodes[0], second.Nodes[0])
	}
}

func TestAnalyzeBasicProfileBlocksUnsupportedAndMalformedURIs(t *testing.T) {
	data := []byte(strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#Alpha",
		"vmess://unsupported",
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388?udp-over-tcp=true#UnknownQuery",
		"ss://legacy-base64-only#Legacy",
	}, "\n"))
	analysis, err := AnalyzeBasicProfile(data, "profile-uri")
	if err != nil {
		t.Fatal(err)
	}
	if analysis.CanCommit() {
		t.Fatalf("unsupported URI-list unexpectedly committable: %+v", analysis)
	}
	if len(analysis.Nodes) != 1 {
		t.Fatalf("supported node extraction changed: %+v", analysis.Nodes)
	}
	if len(analysis.Diagnostics) != 3 {
		t.Fatalf("diagnostics = %+v", analysis.Diagnostics)
	}
	for _, diagnostic := range analysis.Diagnostics {
		if diagnostic.Level != singboximport.DiagnosticError ||
			diagnostic.Code != "unsupported_or_invalid_uri" {
			t.Fatalf("unexpected diagnostic = %+v", diagnostic)
		}
	}
}

func TestAnalyzeBasicProfileBlocksDuplicateSemanticNode(t *testing.T) {
	data := []byte(strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#One",
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#Two",
	}, "\n"))
	analysis, err := AnalyzeBasicProfile(data, "profile-uri")
	if err != nil {
		t.Fatal(err)
	}
	if analysis.CanCommit() || len(analysis.Nodes) != 1 {
		t.Fatalf("duplicate semantic URI analysis = %+v", analysis)
	}
	if len(analysis.Diagnostics) != 1 ||
		analysis.Diagnostics[0].Code != "duplicate_node" {
		t.Fatalf("duplicate diagnostic = %+v", analysis.Diagnostics)
	}
}

func TestAnalyzeBasicProfileRejectsOversizedLine(t *testing.T) {
	data := []byte("ss://" + strings.Repeat("a", MaxURILineBytes+1))
	if _, err := AnalyzeBasicProfile(data, "profile-uri"); err == nil {
		t.Fatal("oversized URI line was accepted")
	}
}
