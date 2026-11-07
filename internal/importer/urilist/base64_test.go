package urilist

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	singboximport "github.com/bbbstyyy/karing-tui-v2/internal/importer/singbox"
)

func TestAnalyzeBase64ProfilePreservesCanonicalNodesAndRawSourceHash(t *testing.T) {
	decoded := "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#Alpha\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(decoded))
	wrapped := []byte(encoded[:16] + "\r\n" + encoded[16:] + "\n")
	analysis, err := AnalyzeBase64Profile(wrapped, "profile-b64")
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.CanCommit() || len(analysis.Nodes) != 1 {
		t.Fatalf("base64 analysis = %+v", analysis)
	}
	node := analysis.Nodes[0]
	if node.Kind != domain.NodeShadowsocks ||
		node.Shadowsocks == nil ||
		node.Shadowsocks.Method != "aes-256-gcm" ||
		node.Shadowsocks.Password != "secret" ||
		node.Source.SourceName != "Alpha" {
		t.Fatalf("decoded Shadowsocks node = %+v", node)
	}
	sum := sha256.Sum256(wrapped)
	if analysis.SourceSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("source SHA256 = %q, want raw envelope hash", analysis.SourceSHA256)
	}

	renamed := strings.Replace(decoded, "#Alpha", "#Renamed", 1)
	other, err := AnalyzeBase64Profile(
		[]byte(base64.RawURLEncoding.EncodeToString([]byte(renamed))),
		"profile-b64",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !other.CanCommit() || len(other.Nodes) != 1 ||
		other.Nodes[0].Source.SourceKey != node.Source.SourceKey ||
		other.Nodes[0].Source.SourceName != "Renamed" {
		t.Fatalf("base64 representation/fragment changed semantic identity: %+v", other)
	}
}

func TestAnalyzeBase64ProfileBlocksUnsupportedURIWithoutPartialCommit(t *testing.T) {
	decoded := strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#Alpha",
		"vmess://unsupported",
	}, "\n")
	analysis, err := AnalyzeBase64Profile(
		[]byte(base64.RawStdEncoding.EncodeToString([]byte(decoded))),
		"profile-b64",
	)
	if err != nil {
		t.Fatal(err)
	}
	if analysis.CanCommit() || len(analysis.Nodes) != 1 ||
		len(analysis.Diagnostics) != 1 ||
		analysis.Diagnostics[0].Level != singboximport.DiagnosticError ||
		analysis.Diagnostics[0].Code != "unsupported_or_invalid_uri" {
		t.Fatalf("unsupported URI was silently accepted: %+v", analysis)
	}
}

func TestAnalyzeBase64ProfileRejectsMalformedAndPartialDecodes(t *testing.T) {
	for _, encoded := range []string{
		"",
		"   \r\n",
		"%%%not-base64",
		"YWJj?",
		"YWJj$",
		"c3M6Ly8===",
		"ab!ab",
		base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe}),
	} {
		if _, err := AnalyzeBase64Profile([]byte(encoded), "profile-b64"); !errors.Is(
			err, ErrInvalidBase64URIList,
		) {
			t.Fatalf("invalid encoded source %q error = %v", encoded, err)
		}
	}
	huge := []byte(strings.Repeat("A", MaxBase64URIListSourceBytes+1))
	if _, err := AnalyzeBase64Profile(huge, "profile-b64"); !errors.Is(
		err, ErrInvalidBase64URIList,
	) {
		t.Fatalf("oversized source error = %v", err)
	}
}
