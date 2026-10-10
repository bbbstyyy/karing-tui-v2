package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

type NodeKind string

const (
	NodeSOCKS       NodeKind = "socks"
	NodeHTTP        NodeKind = "http"
	NodeShadowsocks NodeKind = "shadowsocks"
	NodeVMess       NodeKind = "vmess"
	NodeVLESS       NodeKind = "vless"
	NodeTrojan      NodeKind = "trojan"
)

type SOCKSVersion string

const (
	SOCKS4  SOCKSVersion = "4"
	SOCKS4A SOCKSVersion = "4a"
	SOCKS5  SOCKSVersion = "5"
)

type ProxyNetwork string

const (
	ProxyNetworkBoth ProxyNetwork = "both"
	ProxyNetworkTCP  ProxyNetwork = "tcp"
	ProxyNetworkUDP  ProxyNetwork = "udp"
)

var ErrInvalidNode = errors.New("invalid proxy node")

type SOCKSNodeOptions struct {
	Version  SOCKSVersion
	Username string
	Password string
	Network  ProxyNetwork
}

type HTTPNodeOptions struct {
	Username string
	Password string
}

type ShadowsocksNodeOptions struct {
	Method        string
	Password      string
	Plugin        string
	PluginOptions string
	Network       ProxyNetwork
}

type VMessNodeOptions struct {
	UUID                string
	Security            string
	AlterID             uint16
	GlobalPadding       bool
	AuthenticatedLength bool
	Network             ProxyNetwork
	PacketEncoding      string
}

type VLESSNodeOptions struct {
	UUID           string
	Flow           string
	Encryption     string
	Network        ProxyNetwork
	PacketEncoding *string
}

type TrojanNodeOptions struct {
	Password string
	Network  ProxyNetwork
}

type OutboundTLSOptions struct {
	Enabled    bool
	DisableSNI bool
	ServerName string
	Insecure   bool
}

type Node struct {
	ProfileID   string
	NodeID      string
	Kind        NodeKind
	Server      string
	Port        uint16
	SOCKS       *SOCKSNodeOptions
	HTTP        *HTTPNodeOptions
	Shadowsocks *ShadowsocksNodeOptions
	VMess       *VMessNodeOptions
	VLESS       *VLESSNodeOptions
	Trojan      *TrojanNodeOptions
	TLS         *OutboundTLSOptions
}

func (n Node) Validate() error {
	if err := validateNodeID(n.ProfileID); err != nil {
		return fmt.Errorf("%w: profile ID: %v", ErrInvalidNode, err)
	}
	if err := validateNodeID(n.NodeID); err != nil {
		return fmt.Errorf("%w: node ID: %v", ErrInvalidNode, err)
	}
	if err := validateServerHost(n.Server); err != nil {
		return fmt.Errorf("%w: server: %v", ErrInvalidNode, err)
	}
	if n.Port == 0 {
		return fmt.Errorf("%w: server port must be non-zero", ErrInvalidNode)
	}

	switch n.Kind {
	case NodeSOCKS:
		if n.SOCKS == nil || n.HTTP != nil || n.Shadowsocks != nil || n.VMess != nil || n.VLESS != nil || n.Trojan != nil {
			return fmt.Errorf("%w: SOCKS node must contain only SOCKS options", ErrInvalidNode)
		}
		if err := n.SOCKS.Validate(); err != nil {
			return err
		}
	case NodeHTTP:
		if n.HTTP == nil || n.SOCKS != nil || n.Shadowsocks != nil || n.VMess != nil || n.VLESS != nil || n.Trojan != nil {
			return fmt.Errorf("%w: HTTP node must contain only HTTP options", ErrInvalidNode)
		}
		if err := n.HTTP.Validate(); err != nil {
			return err
		}
	case NodeShadowsocks:
		if n.Shadowsocks == nil || n.SOCKS != nil || n.HTTP != nil || n.VMess != nil || n.VLESS != nil || n.Trojan != nil {
			return fmt.Errorf("%w: Shadowsocks node must contain only Shadowsocks options", ErrInvalidNode)
		}
		if err := n.Shadowsocks.Validate(); err != nil {
			return err
		}
	case NodeVMess:
		if n.VMess == nil || n.SOCKS != nil || n.HTTP != nil || n.Shadowsocks != nil || n.VLESS != nil || n.Trojan != nil {
			return fmt.Errorf("%w: VMess node must contain only VMess options", ErrInvalidNode)
		}
		if err := n.VMess.Validate(); err != nil {
			return err
		}
	case NodeVLESS:
		if n.VLESS == nil || n.SOCKS != nil || n.HTTP != nil || n.Shadowsocks != nil || n.VMess != nil || n.Trojan != nil {
			return fmt.Errorf("%w: VLESS node must contain only VLESS options", ErrInvalidNode)
		}
		if err := n.VLESS.Validate(); err != nil {
			return err
		}
	case NodeTrojan:
		if n.Trojan == nil || n.SOCKS != nil || n.HTTP != nil || n.Shadowsocks != nil || n.VMess != nil || n.VLESS != nil {
			return fmt.Errorf("%w: Trojan node must contain only Trojan options", ErrInvalidNode)
		}
		if err := n.Trojan.Validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unsupported node kind %q", ErrInvalidNode, n.Kind)
	}
	if n.TLS != nil {
		switch n.Kind {
		case NodeVMess, NodeVLESS, NodeTrojan:
		default:
			return fmt.Errorf("%w: TLS is not supported for node kind %q", ErrInvalidNode, n.Kind)
		}
		if err := n.TLS.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (o SOCKSNodeOptions) Validate() error {
	switch o.Version {
	case SOCKS4, SOCKS4A:
		if o.Password != "" {
			return fmt.Errorf("%w: SOCKS %s does not support password authentication", ErrInvalidNode, o.Version)
		}
		if o.Network != ProxyNetworkTCP {
			return fmt.Errorf("%w: SOCKS %s is restricted to TCP in the basic node model", ErrInvalidNode, o.Version)
		}
	case SOCKS5:
		switch o.Network {
		case ProxyNetworkBoth, ProxyNetworkTCP, ProxyNetworkUDP:
		default:
			return fmt.Errorf("%w: unsupported SOCKS network %q", ErrInvalidNode, o.Network)
		}
	default:
		return fmt.Errorf("%w: unsupported SOCKS version %q", ErrInvalidNode, o.Version)
	}
	if err := validateCredential(o.Username); err != nil {
		return fmt.Errorf("%w: SOCKS username: %v", ErrInvalidNode, err)
	}
	if err := validateCredential(o.Password); err != nil {
		return fmt.Errorf("%w: SOCKS password: %v", ErrInvalidNode, err)
	}
	if o.Password != "" && o.Username == "" {
		return fmt.Errorf("%w: SOCKS password requires a username", ErrInvalidNode)
	}
	return nil
}

func (o HTTPNodeOptions) Validate() error {
	if err := validateCredential(o.Username); err != nil {
		return fmt.Errorf("%w: HTTP username: %v", ErrInvalidNode, err)
	}
	if err := validateCredential(o.Password); err != nil {
		return fmt.Errorf("%w: HTTP password: %v", ErrInvalidNode, err)
	}
	if o.Password != "" && o.Username == "" {
		return fmt.Errorf("%w: HTTP password requires a username", ErrInvalidNode)
	}
	return nil
}

func (o ShadowsocksNodeOptions) Validate() error {
	if err := validateNodeToken("Shadowsocks method", o.Method, 128, true); err != nil {
		return err
	}
	if err := validateCredential(o.Password); err != nil {
		return fmt.Errorf("%w: Shadowsocks password: %v", ErrInvalidNode, err)
	}
	if o.Password == "" {
		return fmt.Errorf("%w: Shadowsocks password must not be empty", ErrInvalidNode)
	}
	if err := validateNodeToken("Shadowsocks plugin", o.Plugin, 256, false); err != nil {
		return err
	}
	if err := validateCredential(o.PluginOptions); err != nil {
		return fmt.Errorf("%w: Shadowsocks plugin options: %v", ErrInvalidNode, err)
	}
	if o.Plugin == "" && o.PluginOptions != "" {
		return fmt.Errorf("%w: Shadowsocks plugin options require a plugin", ErrInvalidNode)
	}
	switch o.Network {
	case ProxyNetworkBoth, ProxyNetworkTCP, ProxyNetworkUDP:
	default:
		return fmt.Errorf("%w: unsupported Shadowsocks network %q", ErrInvalidNode, o.Network)
	}
	return nil
}

func (o VMessNodeOptions) Validate() error {
	if err := validateVMessUUID(o.UUID); err != nil {
		return fmt.Errorf("%w: VMess UUID: %v", ErrInvalidNode, err)
	}
	switch o.Security {
	case "", "auto", "zero", "none", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb":
	default:
		return fmt.Errorf("%w: unsupported VMess security %q", ErrInvalidNode, o.Security)
	}
	switch o.Network {
	case ProxyNetworkBoth, ProxyNetworkTCP, ProxyNetworkUDP:
	default:
		return fmt.Errorf("%w: unsupported VMess network %q", ErrInvalidNode, o.Network)
	}
	switch o.PacketEncoding {
	case "", "packetaddr", "xudp":
	default:
		return fmt.Errorf("%w: unsupported VMess packet encoding %q", ErrInvalidNode, o.PacketEncoding)
	}
	return nil
}

func (o VLESSNodeOptions) Validate() error {
	if err := validateVMessUUID(o.UUID); err != nil {
		return fmt.Errorf("%w: VLESS UUID: %v", ErrInvalidNode, err)
	}
	if o.Flow != "" {
		return fmt.Errorf(
			"%w: VLESS flow %q requires TLS/encryption semantics outside the basic node model",
			ErrInvalidNode,
			o.Flow,
		)
	}
	switch o.Encryption {
	case "", "none":
	default:
		return fmt.Errorf(
			"%w: VLESS encryption %q is outside the verified basic subset",
			ErrInvalidNode,
			o.Encryption,
		)
	}
	switch o.Network {
	case ProxyNetworkBoth, ProxyNetworkTCP, ProxyNetworkUDP:
	default:
		return fmt.Errorf("%w: unsupported VLESS network %q", ErrInvalidNode, o.Network)
	}
	if o.PacketEncoding != nil {
		switch *o.PacketEncoding {
		case "", "packetaddr", "xudp":
		default:
			return fmt.Errorf(
				"%w: unsupported VLESS packet encoding %q",
				ErrInvalidNode,
				*o.PacketEncoding,
			)
		}
	}
	return nil
}

func (o OutboundTLSOptions) Validate() error {
	if !o.Enabled {
		return fmt.Errorf(
			"%w: explicit TLS options must set enabled=true in the verified subset",
			ErrInvalidNode,
		)
	}
	if o.ServerName != "" {
		if err := validateServerHost(o.ServerName); err != nil {
			return fmt.Errorf("%w: TLS server_name: %v", ErrInvalidNode, err)
		}
	}
	return nil
}

func (o TrojanNodeOptions) Validate() error {
	if err := validateCredential(o.Password); err != nil {
		return fmt.Errorf("%w: Trojan password: %v", ErrInvalidNode, err)
	}
	if o.Password == "" {
		return fmt.Errorf("%w: Trojan password must not be empty", ErrInvalidNode)
	}
	switch o.Network {
	case ProxyNetworkBoth, ProxyNetworkTCP, ProxyNetworkUDP:
	default:
		return fmt.Errorf("%w: unsupported Trojan network %q", ErrInvalidNode, o.Network)
	}
	return nil
}

func validateVMessUUID(value string) error {
	if len(value) != 32 && len(value) != 36 {
		return errors.New("UUID must contain 32 hexadecimal digits with optional canonical hyphens")
	}
	for index, r := range value {
		if len(value) == 36 {
			switch index {
			case 8, 13, 18, 23:
				if r != '-' {
					return errors.New("UUID has invalid canonical hyphen placement")
				}
				continue
			}
		}
		if (r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'f') ||
			(r >= 'A' && r <= 'F') {
			continue
		}
		return errors.New("UUID contains a non-hexadecimal character")
	}
	return nil
}

func validateNodeID(value string) error {
	if value == "" {
		return errors.New("stable ID must not be empty")
	}
	if len(value) > 512 {
		return errors.New("stable ID exceeds 512 bytes")
	}
	if strings.TrimSpace(value) != value {
		return errors.New("stable ID must not have leading or trailing whitespace")
	}
	if !utf8.ValidString(value) {
		return errors.New("stable ID is not valid UTF-8")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("stable ID contains a control character")
		}
	}
	return nil
}

func validateNodeToken(label, value string, limit int, required bool) error {
	if required && value == "" {
		return fmt.Errorf("%w: %s must not be empty", ErrInvalidNode, label)
	}
	if len(value) > limit {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidNode, label, limit)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: %s must not have leading or trailing whitespace", ErrInvalidNode, label)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidNode, label)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalidNode, label)
		}
	}
	return nil
}

func validateCredential(value string) error {
	if len(value) > 4096 {
		return errors.New("credential exceeds 4096 bytes")
	}
	if !utf8.ValidString(value) {
		return errors.New("credential is not valid UTF-8")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("credential contains a control character")
		}
	}
	return nil
}

func validateServerHost(value string) error {
	if value == "" {
		return errors.New("host must not be empty")
	}
	if len(value) > 253 {
		return errors.New("host exceeds 253 bytes")
	}
	if strings.TrimSpace(value) != value {
		return errors.New("host must not have leading or trailing whitespace")
	}
	if !utf8.ValidString(value) {
		return errors.New("host is not valid UTF-8")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if address.IsUnspecified() {
			return errors.New("unspecified IP address is not a valid proxy server")
		}
		return nil
	}
	if strings.ContainsAny(value, "/?#@:") {
		return errors.New("host must be a bare DNS name or IP address")
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("host contains an invalid DNS label length")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("DNS label must not start or end with '-'")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("DNS label contains unsupported character %q", r)
		}
	}
	return nil
}
