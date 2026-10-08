package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestBasicSOCKSAndHTTPNodesValidate(t *testing.T) {
	nodes := []Node{
		{
			ProfileID: "profile-a",
			NodeID:    "socks-a",
			Kind:      NodeSOCKS,
			Server:    "proxy.example.com",
			Port:      1080,
			SOCKS: &SOCKSNodeOptions{
				Version:  SOCKS5,
				Username: "user",
				Password: "pass with spaces",
				Network:  ProxyNetworkBoth,
			},
		},
		{
			ProfileID: "profile-a",
			NodeID:    "http-a",
			Kind:      NodeHTTP,
			Server:    "192.0.2.10",
			Port:      8080,
			HTTP: &HTTPNodeOptions{
				Username: "user",
				Password: "pass",
			},
		},
		{
			ProfileID: "profile-b",
			NodeID:    "ipv6-socks",
			Kind:      NodeSOCKS,
			Server:    "2001:db8::1",
			Port:      1080,
			SOCKS: &SOCKSNodeOptions{
				Version: SOCKS4A,
				Network: ProxyNetworkTCP,
			},
		},
		{
			ProfileID: "profile-c",
			NodeID:    "ss-a",
			Kind:      NodeShadowsocks,
			Server:    "ss.example.com",
			Port:      8388,
			Shadowsocks: &ShadowsocksNodeOptions{
				Method:        "aes-256-gcm",
				Password:      "secret",
				Plugin:        "obfs-local",
				PluginOptions: "obfs=http;obfs-host=example.com",
				Network:       ProxyNetworkBoth,
			},
		},
	}
	for _, node := range nodes {
		if err := node.Validate(); err != nil {
			t.Fatalf("valid node %+v: %v", node, err)
		}
	}
}

func TestNodeRejectsAmbiguousOrUnsupportedOptions(t *testing.T) {
	validSOCKS := &SOCKSNodeOptions{Version: SOCKS5, Network: ProxyNetworkBoth}
	validHTTP := &HTTPNodeOptions{}
	validSS := &ShadowsocksNodeOptions{Method: "aes-256-gcm", Password: "secret", Network: ProxyNetworkBoth}
	cases := []Node{
		{},
		{ProfileID: "p", NodeID: "n", Kind: NodeSOCKS, Server: "proxy.example.com", Port: 1080},
		{ProfileID: "p", NodeID: "n", Kind: NodeHTTP, Server: "proxy.example.com", Port: 8080},
		{ProfileID: "p", NodeID: "n", Kind: NodeSOCKS, Server: "proxy.example.com", Port: 1080, SOCKS: validSOCKS, HTTP: validHTTP},
		{ProfileID: "p", NodeID: "n", Kind: NodeHTTP, Server: "proxy.example.com", Port: 8080, SOCKS: validSOCKS, HTTP: validHTTP},
		{ProfileID: "p", NodeID: "n", Kind: NodeShadowsocks, Server: "proxy.example.com", Port: 8388},
		{ProfileID: "p", NodeID: "n", Kind: NodeShadowsocks, Server: "proxy.example.com", Port: 8388, HTTP: validHTTP, Shadowsocks: validSS},
		{ProfileID: "p", NodeID: "n", Kind: NodeKind("vless"), Server: "proxy.example.com", Port: 443},
		{ProfileID: "p", NodeID: "n", Kind: NodeSOCKS, Server: "proxy.example.com", Port: 0, SOCKS: validSOCKS},
	}
	for i, node := range cases {
		if err := node.Validate(); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

func TestSOCKSOptionsAreExplicitAndVersionAware(t *testing.T) {
	cases := []SOCKSNodeOptions{
		{},
		{Version: SOCKSVersion("6"), Network: ProxyNetworkBoth},
		{Version: SOCKS5, Network: ProxyNetwork("icmp")},
		{Version: SOCKS4, Password: "not-supported", Network: ProxyNetworkTCP},
		{Version: SOCKS4A, Password: "not-supported", Network: ProxyNetworkTCP},
		{Version: SOCKS4, Network: ProxyNetworkBoth},
		{Version: SOCKS4A, Network: ProxyNetworkUDP},
		{Version: SOCKS5, Password: "needs-user", Network: ProxyNetworkBoth},
		{Version: SOCKS5, Username: "bad\nuser", Network: ProxyNetworkBoth},
	}
	for i, options := range cases {
		if err := options.Validate(); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}

	valid := []SOCKSNodeOptions{
		{Version: SOCKS4, Username: "user", Network: ProxyNetworkTCP},
		{Version: SOCKS4A, Username: "user", Network: ProxyNetworkTCP},
		{Version: SOCKS5, Username: "user", Password: "pass", Network: ProxyNetworkBoth},
		{Version: SOCKS5, Network: ProxyNetworkUDP},
	}
	for _, options := range valid {
		if err := options.Validate(); err != nil {
			t.Fatalf("valid SOCKS options %+v: %v", options, err)
		}
	}
}

func TestShadowsocksOptionsAreBoundedAndExplicit(t *testing.T) {
	valid := []ShadowsocksNodeOptions{
		{Method: "aes-256-gcm", Password: "secret", Network: ProxyNetworkBoth},
		{Method: "chacha20-ietf-poly1305", Password: "secret", Network: ProxyNetworkTCP},
		{
			Method:        "aes-128-gcm",
			Password:      "secret",
			Plugin:        "v2ray-plugin",
			PluginOptions: "mode=websocket;host=example.com",
			Network:       ProxyNetworkUDP,
		},
	}
	for _, options := range valid {
		if err := options.Validate(); err != nil {
			t.Fatalf("valid Shadowsocks options %+v: %v", options, err)
		}
	}

	invalid := []ShadowsocksNodeOptions{
		{},
		{Method: "aes-256-gcm", Network: ProxyNetworkBoth},
		{Method: " aes-256-gcm", Password: "secret", Network: ProxyNetworkBoth},
		{Method: "aes-256-gcm", Password: "secret", PluginOptions: "orphan=1", Network: ProxyNetworkBoth},
		{Method: "aes-256-gcm", Password: "bad\nsecret", Network: ProxyNetworkBoth},
		{Method: "aes-256-gcm", Password: "secret", Network: ProxyNetwork("icmp")},
	}
	for i, options := range invalid {
		if err := options.Validate(); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("invalid Shadowsocks case %d error = %v", i, err)
		}
	}
}

func TestVMessOptionsMatchApprovedCoreBasicFields(t *testing.T) {
	valid := []VMessNodeOptions{
		{
			UUID:     "11111111-2222-3333-4444-555555555555",
			Security: "auto",
			Network:  ProxyNetworkBoth,
		},
		{
			UUID:                "11111111222233334444555555555555",
			Security:            "aes-128-gcm",
			AlterID:             1,
			GlobalPadding:       true,
			AuthenticatedLength: true,
			Network:             ProxyNetworkTCP,
			PacketEncoding:      "xudp",
		},
		{
			UUID:           "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
			Security:       "none",
			Network:        ProxyNetworkUDP,
			PacketEncoding: "packetaddr",
		},
	}
	for _, options := range valid {
		if err := options.Validate(); err != nil {
			t.Fatalf("valid VMess options %+v: %v", options, err)
		}
	}

	invalid := []VMessNodeOptions{
		{},
		{UUID: "not-a-uuid", Security: "auto", Network: ProxyNetworkBoth},
		{UUID: "11111111-2222-3333-4444-555555555555", Security: "rc4-md5", Network: ProxyNetworkBoth},
		{UUID: "11111111-2222-3333-4444-555555555555", Security: "auto", Network: ProxyNetwork("icmp")},
		{UUID: "11111111-2222-3333-4444-555555555555", Security: "auto", Network: ProxyNetworkBoth, PacketEncoding: "unknown"},
	}
	for i, options := range invalid {
		if err := options.Validate(); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("invalid VMess case %d error = %v", i, err)
		}
	}
}

func TestVMessNodeRejectsMixedProtocolOptions(t *testing.T) {
	vmess := &VMessNodeOptions{
		UUID:     "11111111-2222-3333-4444-555555555555",
		Security: "auto",
		Network:  ProxyNetworkBoth,
	}
	valid := Node{
		ProfileID: "profile-v",
		NodeID:    "vmess-a",
		Kind:      NodeVMess,
		Server:    "vmess.example.com",
		Port:      10086,
		VMess:     vmess,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	mixed := valid
	mixed.HTTP = &HTTPNodeOptions{}
	if err := mixed.Validate(); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("mixed VMess options error = %v", err)
	}
}

func TestVLESSOptionsPreservePacketEncodingPresence(t *testing.T) {
	explicitNone := ""
	xudp := "xudp"
	valid := []VLESSNodeOptions{
		{
			UUID:    "11111111-2222-3333-4444-555555555555",
			Network: ProxyNetworkBoth,
		},
		{
			UUID:           "11111111222233334444555555555555",
			Encryption:     "none",
			Network:        ProxyNetworkTCP,
			PacketEncoding: &explicitNone,
		},
		{
			UUID:           "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
			Network:        ProxyNetworkUDP,
			PacketEncoding: &xudp,
		},
	}
	for _, options := range valid {
		if err := options.Validate(); err != nil {
			t.Fatalf("valid VLESS options %+v: %v", options, err)
		}
	}

	unknownPacket := "unknown"
	invalid := []VLESSNodeOptions{
		{},
		{UUID: "not-a-uuid", Network: ProxyNetworkBoth},
		{UUID: "11111111-2222-3333-4444-555555555555", Flow: "xtls-rprx-vision", Network: ProxyNetworkBoth},
		{UUID: "11111111-2222-3333-4444-555555555555", Encryption: "mlkem768x25519plus.native.1rtt.key", Network: ProxyNetworkBoth},
		{UUID: "11111111-2222-3333-4444-555555555555", Network: ProxyNetwork("icmp")},
		{UUID: "11111111-2222-3333-4444-555555555555", Network: ProxyNetworkBoth, PacketEncoding: &unknownPacket},
	}
	for i, options := range invalid {
		if err := options.Validate(); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("invalid VLESS case %d error = %v", i, err)
		}
	}
}

func TestVLESSNodeRejectsMixedProtocolOptions(t *testing.T) {
	packetEncoding := "packetaddr"
	vless := &VLESSNodeOptions{
		UUID:           "11111111-2222-3333-4444-555555555555",
		Network:        ProxyNetworkBoth,
		PacketEncoding: &packetEncoding,
	}
	valid := Node{
		ProfileID: "profile-vless",
		NodeID:    "vless-a",
		Kind:      NodeVLESS,
		Server:    "vless.example.com",
		Port:      443,
		VLESS:     vless,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	mixed := valid
	mixed.VMess = &VMessNodeOptions{
		UUID:     "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
		Security: "auto",
		Network:  ProxyNetworkBoth,
	}
	if err := mixed.Validate(); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("mixed VLESS options error = %v", err)
	}
}

func TestTrojanOptionsAreBoundedAndExplicit(t *testing.T) {
	valid := []TrojanNodeOptions{
		{Password: "secret", Network: ProxyNetworkBoth},
		{Password: "secret with spaces", Network: ProxyNetworkTCP},
		{Password: "another-secret", Network: ProxyNetworkUDP},
	}
	for _, options := range valid {
		if err := options.Validate(); err != nil {
			t.Fatalf("valid Trojan options %+v: %v", options, err)
		}
	}

	invalid := []TrojanNodeOptions{
		{},
		{Password: "bad\nsecret", Network: ProxyNetworkBoth},
		{Password: "secret", Network: ProxyNetwork("icmp")},
	}
	for i, options := range invalid {
		if err := options.Validate(); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("invalid Trojan case %d error = %v", i, err)
		}
	}
}

func TestTrojanNodeRejectsMixedProtocolOptions(t *testing.T) {
	valid := Node{
		ProfileID: "profile-trojan",
		NodeID:    "trojan-a",
		Kind:      NodeTrojan,
		Server:    "trojan.example.com",
		Port:      443,
		Trojan: &TrojanNodeOptions{
			Password: "secret",
			Network:  ProxyNetworkBoth,
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	mixed := valid
	mixed.HTTP = &HTTPNodeOptions{}
	if err := mixed.Validate(); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("mixed Trojan options error = %v", err)
	}
}

func TestNodeServerMustBeBareHost(t *testing.T) {
	base := Node{
		ProfileID: "profile-a",
		NodeID:    "node-a",
		Kind:      NodeHTTP,
		Port:      8080,
		HTTP:      &HTTPNodeOptions{},
	}
	invalid := []string{
		"",
		" proxy.example.com",
		"proxy.example.com ",
		"https://proxy.example.com",
		"user@proxy.example.com",
		"proxy.example.com/path",
		"-bad.example.com",
		"bad-.example.com",
		"bad..example.com",
		"0.0.0.0",
		"::",
	}
	for _, server := range invalid {
		node := base
		node.Server = server
		if err := node.Validate(); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("server %q error = %v", server, err)
		}
	}

	for _, server := range []string{"localhost", "proxy.example.com", "192.0.2.1", "2001:db8::1"} {
		node := base
		node.Server = server
		if err := node.Validate(); err != nil {
			t.Fatalf("server %q: %v", server, err)
		}
	}
}

func TestHTTPPasswordRequiresUsername(t *testing.T) {
	node := Node{
		ProfileID: "profile-a",
		NodeID:    "http-a",
		Kind:      NodeHTTP,
		Server:    "proxy.example.com",
		Port:      8080,
		HTTP:      &HTTPNodeOptions{Password: "secret"},
	}
	if err := node.Validate(); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("password-only HTTP auth error = %v", err)
	}
}

func TestNodeStableIDsAndCredentialsAreBounded(t *testing.T) {
	node := Node{
		ProfileID: strings.Repeat("a", 513),
		NodeID:    "node",
		Kind:      NodeHTTP,
		Server:    "proxy.example.com",
		Port:      8080,
		HTTP:      &HTTPNodeOptions{},
	}
	if err := node.Validate(); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("long profile ID error = %v", err)
	}

	node.ProfileID = "profile"
	node.HTTP.Password = strings.Repeat("x", 4097)
	if err := node.Validate(); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("long password error = %v", err)
	}
}
