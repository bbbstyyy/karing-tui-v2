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
	NodeSOCKS NodeKind = "socks"
	NodeHTTP  NodeKind = "http"
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

type Node struct {
	ProfileID string
	NodeID    string
	Kind      NodeKind
	Server    string
	Port      uint16
	SOCKS     *SOCKSNodeOptions
	HTTP      *HTTPNodeOptions
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
		if n.SOCKS == nil || n.HTTP != nil {
			return fmt.Errorf("%w: SOCKS node must contain only SOCKS options", ErrInvalidNode)
		}
		if err := n.SOCKS.Validate(); err != nil {
			return err
		}
	case NodeHTTP:
		if n.HTTP == nil || n.SOCKS != nil {
			return fmt.Errorf("%w: HTTP node must contain only HTTP options", ErrInvalidNode)
		}
		if err := n.HTTP.Validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unsupported node kind %q", ErrInvalidNode, n.Kind)
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
