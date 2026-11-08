package clash

import (
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const clashMVPExample = `mixed-port: 7890
mode: rule
proxies:
  - name: Primary SS
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: TEST_SS_SECRET
    udp: false
  - name: Primary Trojan
    type: trojan
    server: edge.example.test
    port: 443
    password: TEST_TROJAN_SECRET
    sni: edge.example.test
    skip-cert-verify: false
  - name: Primary VLESS
    type: vless
    server: edge2.example.test
    port: 8443
    uuid: 01234567-89ab-cdef-0123-456789abcdef
    tls: true
    servername: edge2.example.test
    network: tcp
proxy-groups:
  - name: Untrusted imported policy
    type: select
    proxies:
      - DIRECT
rules:
  - MATCH,DIRECT
dns:
  enable: true
  nameserver: [1.1.1.1]
`

func TestClashYAMLStrictThreeBasicProxiesAndPolicyIsolation(t *testing.T) {
	result, err := AnalyzeBasicProfile([]byte(clashMVPExample), "work")
	if err != nil || !result.CanCommit() || len(result.Nodes) != 3 {
		t.Fatalf("valid Clash YAML rejected: err=%v diagnostics=%+v", err, result.Diagnostics)
	}
	for i, kind := range []domain.NodeKind{domain.NodeShadowsocks, domain.NodeTrojan, domain.NodeVLESS} {
		node := result.Nodes[i]
		if node.Kind != kind || len(node.Source.PayloadJSON) == 0 ||
			len(node.Source.SourceKey) != len("clash-")+64 {
			t.Fatalf("Clash node %d failed strict canonical conversion", i)
		}
		if strings.Contains(string(node.Source.PayloadJSON), "DIRECT") ||
			strings.Contains(string(node.Source.PayloadJSON), "MATCH") ||
			strings.Contains(string(node.Source.PayloadJSON), "1.1.1.1") {
			t.Fatal("imported subscription route or DNS leaked into runtime node")
		}
	}
	if result.Nodes[0].Shadowsocks == nil ||
		result.Nodes[0].Shadowsocks.Method != "aes-256-gcm" ||
		result.Nodes[0].Shadowsocks.Network != domain.ProxyNetworkTCP ||
		result.Nodes[1].TLS == nil || !result.Nodes[1].TLS.Enabled ||
		result.Nodes[1].TLS.Insecure ||
		result.Nodes[1].Trojan == nil || result.Nodes[1].Trojan.Password != "TEST_TROJAN_SECRET" ||
		result.Nodes[2].VLESS == nil || result.Nodes[2].VLESS.Encryption != "none" ||
		result.Nodes[2].VLESS.Network != domain.ProxyNetworkTCP ||
		result.Nodes[2].TLS == nil || !result.Nodes[2].TLS.Enabled ||
		result.Nodes[2].TLS.ServerName != "edge2.example.test" {
		t.Fatal("Clash proxy lost a validated field or changed protocol security")
	}
	ignored := map[string]bool{}
	for _, diag := range result.Diagnostics {
		if diag.Level == "error" {
			t.Fatal("valid Clash YAML contained a blocking diagnostic")
		}
		if diag.Code == "ignored_by_product_policy" {
			ignored[diag.Path] = true
		}
	}
	for _, key := range []string{"proxy-groups", "rules", "dns"} {
		if !ignored[key] {
			t.Fatalf("source policy %s was not explicitly marked as ignored", key)
		}
	}
}

func TestClashYAMLSemanticIdentitySurvivesRenameAndKeyOrder(t *testing.T) {
	a := `proxies:
  - name: Old Name
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: TEST_SECRET
`
	b := `proxies:
  - password: TEST_SECRET
    cipher: aes-256-gcm
    port: "8388"
    server: 127.0.0.1
    type: ss
    name: New Name
    udp: false
`
	one, err := AnalyzeBasicProfile([]byte(a), "work")
	if err != nil || !one.CanCommit() {
		t.Fatalf("first: %v %+v", err, one.Diagnostics)
	}
	two, err := AnalyzeBasicProfile([]byte(b), "work")
	if err != nil || !two.CanCommit() {
		t.Fatalf("second: %v %+v", err, two.Diagnostics)
	}
	if one.Nodes[0].Source.SourceKey != two.Nodes[0].Source.SourceKey ||
		one.Nodes[0].Source.SourceName == two.Nodes[0].Source.SourceName {
		t.Fatal("Clash source identity followed display name or YAML key order")
	}
}

func TestClashYAMLRejectsUnsafeAndUnknownPropertiesAtomically(t *testing.T) {
	const safe = `proxies:
  - name: Legit
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: TEST_SECRET
`
	badItems := []string{
		"  - name: Bad\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: aes-256-gcm\n    password: TEST_SECRET\n    udp: true\n",
		"  - name: Bad\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: aes-256-gcm\n    password: TEST_SECRET\n    plugin: obfs\n",
		"  - name: Bad\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: unsupported-cipher\n    password: TEST_SECRET\n",
		"  - name: Bad\n    type: trojan\n    server: 127.0.0.1\n    port: 443\n    password: TEST_SECRET\n    skip-cert-verify: true\n",
		"  - name: Bad\n    type: trojan\n    server: 127.0.0.1\n    port: 443\n    password: TEST_SECRET\n    network: ws\n",
		"  - name: Bad\n    type: vless\n    server: 127.0.0.1\n    port: 443\n    uuid: 01234567-89ab-cdef-0123-456789abcdef\n",
		"  - name: Bad\n    type: vless\n    server: 127.0.0.1\n    port: 443\n    uuid: 01234567-89ab-cdef-0123-456789abcdef\n    tls: false\n",
		"  - name: Bad\n    type: vless\n    server: 127.0.0.1\n    port: 443\n    uuid: 01234567-89ab-cdef-0123-456789abcdef\n    tls: true\n    flow: xtls-rprx-vision\n",
		"  - name: Bad\n    type: vmess\n    server: 127.0.0.1\n    port: 443\n    uuid: 01234567-89ab-cdef-0123-456789abcdef\n",
		"  - name: Bad\n    type: trojan\n    server: 127.0.0.1\n    port: 0\n    password: TEST_SECRET\n",
		"  - name: Bad\n    type: trojan\n    server: 127.0.0.1\n    port: 443\n    password: TEST_SECRET\n    sni: example.com\n    servername: example.com\n",
	}
	for i, tail := range badItems {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			result, err := AnalyzeBasicProfile([]byte(safe+tail), "work")
			if err != nil || result.CanCommit() || len(result.Nodes) != 1 ||
				!result.HasBlockingDiagnostics() {
				t.Fatalf("invalid node allowed partial source update: err=%v diagnostics=%+v", err, result.Diagnostics)
			}
			for _, d := range result.Diagnostics {
				if strings.Contains(d.Message, "TEST_SECRET") ||
					strings.Contains(d.Message, "xtls-rprx-vision") {
					t.Fatal("Clash diagnostic leaked password or external field value")
				}
			}
		})
	}
}

func TestClashYAMLRejectsStructuralAttacksWithoutSecretDisclosure(t *testing.T) {
	const base = `proxies:
  - name: Safe
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: TEST_SECRET
`
	attacks := []string{
		strings.Replace(base, "    port: 8388", "    port: 8388\n    port: 443", 1),
		strings.Replace(base, "  - name: Safe", "  - name: Safe\n    name: Duplicate", 1),
		strings.Replace(base, "  - name: Safe", "  - name: &secret Safe", 1),
		strings.Replace(base, "  - name: Safe", "  - name: !secret Safe", 1),
		strings.Replace(base, "    password: TEST_SECRET", "    password: *MISSING_SECRET", 1),
		strings.Replace(base, "    password: TEST_SECRET", "    password: [INVALID_SECRET", 1),
		base + "---\nproxies: []\n",
		base + "tun:\n  enable: true\n",
		base + "rule-providers:\n  secret:\n    url: https://secret.invalid/TOP_SECRET\n",
		base + "extra: TOP_SECRET\n",
	}
	for i, payload := range attacks {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			result, err := AnalyzeBasicProfile([]byte(payload), "work")
			if err == nil && result.CanCommit() {
				t.Fatal("Clash YAML attack was accepted")
			}
			if err != nil && (strings.Contains(err.Error(), "TEST_SECRET") ||
				strings.Contains(err.Error(), "TOP_SECRET") ||
				strings.Contains(err.Error(), "INVALID_SECRET")) {
				t.Fatal("Clash YAML parser leaked raw source scalar")
			}
			for _, d := range result.Diagnostics {
				if strings.Contains(d.Message, "TEST_SECRET") ||
					strings.Contains(d.Message, "TOP_SECRET") {
					t.Fatal("Clash YAML diagnostic leaked raw source scalar")
				}
			}
		})
	}
}

func TestClashYAMLRejectsOversizedSource(t *testing.T) {
	payload := []byte(strings.Repeat("A", MaxClashSourceBytes+1))
	_, err := AnalyzeBasicProfile(payload, "work")
	if err == nil || strings.Contains(err.Error(), strings.Repeat("A", 16)) {
		t.Fatal("oversized source should be rejected without dumping bytes")
	}
}

func TestClashYAMLRejectsDuplicatedIdentityAndName(t *testing.T) {
	base := `proxies:
  - name: One
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: TEST_SECRET
`
	for _, tail := range []string{
		"  - name: Two\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: aes-256-gcm\n    password: TEST_SECRET\n",
		"  - name: One\n    type: ss\n    server: 127.0.0.2\n    port: 8388\n    cipher: aes-256-gcm\n    password: TEST_SECRET\n",
	} {
		result, err := AnalyzeBasicProfile([]byte(base+tail), "work")
		if err != nil || result.CanCommit() || len(result.Diagnostics) == 0 {
			t.Fatalf("duplicated Clash node unexpectedly accepted: %v %+v", err, result.Diagnostics)
		}
	}
}
