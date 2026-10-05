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
	cases := []Node{
		{},
		{ProfileID: "p", NodeID: "n", Kind: NodeSOCKS, Server: "proxy.example.com", Port: 1080},
		{ProfileID: "p", NodeID: "n", Kind: NodeHTTP, Server: "proxy.example.com", Port: 8080},
		{ProfileID: "p", NodeID: "n", Kind: NodeSOCKS, Server: "proxy.example.com", Port: 1080, SOCKS: validSOCKS, HTTP: validHTTP},
		{ProfileID: "p", NodeID: "n", Kind: NodeHTTP, Server: "proxy.example.com", Port: 8080, SOCKS: validSOCKS, HTTP: validHTTP},
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
		{Version: SOCKS5, Username: "bad
user", Network: ProxyNetworkBoth},
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
