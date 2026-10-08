package compiler

import (
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

var (
	ErrNodeClosure       = errors.New("node outbound closure is incomplete")
	ErrDuplicateNodeSpec = errors.New("duplicate node specification")
)

type NodeOutboundConfig struct {
	Type                string  `json:"type"`
	Tag                 string  `json:"tag"`
	Server              string  `json:"server"`
	ServerPort          uint16  `json:"server_port"`
	Version             string  `json:"version,omitempty"`
	Username            string  `json:"username,omitempty"`
	Password            string  `json:"password,omitempty"`
	Method              string  `json:"method,omitempty"`
	Plugin              string  `json:"plugin,omitempty"`
	PluginOptions       string  `json:"plugin_opts,omitempty"`
	Network             string  `json:"network,omitempty"`
	UUID                string  `json:"uuid,omitempty"`
	Security            *string `json:"security,omitempty"`
	Flow                string  `json:"flow,omitempty"`
	Encryption          string  `json:"encryption,omitempty"`
	AlterID             uint16  `json:"alter_id,omitempty"`
	GlobalPadding       bool    `json:"global_padding,omitempty"`
	AuthenticatedLength bool    `json:"authenticated_length,omitempty"`
	PacketEncoding      *string `json:"packet_encoding,omitempty"`
	DomainResolver      string  `json:"domain_resolver,omitempty"`
}

type CompiledNodes struct {
	Outbounds []NodeOutboundConfig
	Targets   []domain.TargetRef
	Tags      []string
}

func CompileBasicNodeOutbounds(nodes []domain.Node, catalog TargetCatalog, required []domain.TargetRef) (CompiledNodes, error) {
	if err := catalog.Validate(); err != nil {
		return CompiledNodes{}, err
	}

	byKey := make(map[NodeTargetKey]domain.Node, len(nodes))
	for _, node := range nodes {
		if err := node.Validate(); err != nil {
			return CompiledNodes{}, err
		}
		key := NodeTargetKey{ProfileID: node.ProfileID, NodeID: node.NodeID}
		if _, exists := byKey[key]; exists {
			return CompiledNodes{}, fmt.Errorf("%w: %q/%q", ErrDuplicateNodeSpec, node.ProfileID, node.NodeID)
		}
		if _, exists := catalog.NodeTags[key]; !exists {
			return CompiledNodes{}, fmt.Errorf("%w: node %q/%q has no stable target tag", ErrNodeClosure, node.ProfileID, node.NodeID)
		}
		byKey[key] = node
	}

	var result CompiledNodes
	seen := make(map[NodeTargetKey]struct{}, len(required))
	for _, target := range required {
		if target.Kind != domain.TargetSpecificNode {
			return CompiledNodes{}, fmt.Errorf("%w: required target %q is not a specific node", ErrNodeClosure, target.Kind)
		}
		key := NodeTargetKey{ProfileID: target.ProfileID, NodeID: target.NodeID}
		if _, exists := seen[key]; exists {
			continue
		}
		node, exists := byKey[key]
		if !exists {
			return CompiledNodes{}, fmt.Errorf("%w: node %q/%q is required but not configured", ErrNodeClosure, target.ProfileID, target.NodeID)
		}
		tag, err := catalog.ResolveTarget(target)
		if err != nil {
			return CompiledNodes{}, fmt.Errorf("%w: resolve node %q/%q: %v", ErrNodeClosure, target.ProfileID, target.NodeID, err)
		}
		outbound, err := compileBasicNode(node, tag)
		if err != nil {
			return CompiledNodes{}, err
		}
		seen[key] = struct{}{}
		result.Outbounds = append(result.Outbounds, outbound)
		result.Targets = append(result.Targets, target)
		result.Tags = append(result.Tags, tag)
	}
	return result, nil
}

func compileBasicNode(node domain.Node, tag string) (NodeOutboundConfig, error) {
	switch node.Kind {
	case domain.NodeSOCKS:
		network := ""
		switch node.SOCKS.Network {
		case domain.ProxyNetworkBoth:
		case domain.ProxyNetworkTCP:
			network = "tcp"
		case domain.ProxyNetworkUDP:
			network = "udp"
		default:
			return NodeOutboundConfig{}, fmt.Errorf("%w: unsupported SOCKS network %q", domain.ErrInvalidNode, node.SOCKS.Network)
		}
		return NodeOutboundConfig{
			Type:       "socks",
			Tag:        tag,
			Server:     node.Server,
			ServerPort: node.Port,
			Version:    string(node.SOCKS.Version),
			Username:   node.SOCKS.Username,
			Password:   node.SOCKS.Password,
			Network:    network,
		}, nil
	case domain.NodeHTTP:
		return NodeOutboundConfig{
			Type:       "http",
			Tag:        tag,
			Server:     node.Server,
			ServerPort: node.Port,
			Username:   node.HTTP.Username,
			Password:   node.HTTP.Password,
		}, nil
	case domain.NodeShadowsocks:
		network := ""
		switch node.Shadowsocks.Network {
		case domain.ProxyNetworkBoth:
		case domain.ProxyNetworkTCP:
			network = "tcp"
		case domain.ProxyNetworkUDP:
			network = "udp"
		default:
			return NodeOutboundConfig{}, fmt.Errorf(
				"%w: unsupported Shadowsocks network %q",
				domain.ErrInvalidNode,
				node.Shadowsocks.Network,
			)
		}
		return NodeOutboundConfig{
			Type:          "shadowsocks",
			Tag:           tag,
			Server:        node.Server,
			ServerPort:    node.Port,
			Method:        node.Shadowsocks.Method,
			Password:      node.Shadowsocks.Password,
			Plugin:        node.Shadowsocks.Plugin,
			PluginOptions: node.Shadowsocks.PluginOptions,
			Network:       network,
		}, nil
	case domain.NodeVMess:
		network := ""
		switch node.VMess.Network {
		case domain.ProxyNetworkBoth:
		case domain.ProxyNetworkTCP:
			network = "tcp"
		case domain.ProxyNetworkUDP:
			network = "udp"
		default:
			return NodeOutboundConfig{}, fmt.Errorf(
				"%w: unsupported VMess network %q",
				domain.ErrInvalidNode,
				node.VMess.Network,
			)
		}
		security := node.VMess.Security
		var packetEncoding *string
		if node.VMess.PacketEncoding != "" {
			value := node.VMess.PacketEncoding
			packetEncoding = &value
		}
		return NodeOutboundConfig{
			Type:                "vmess",
			Tag:                 tag,
			Server:              node.Server,
			ServerPort:          node.Port,
			Network:             network,
			UUID:                node.VMess.UUID,
			Security:            &security,
			AlterID:             node.VMess.AlterID,
			GlobalPadding:       node.VMess.GlobalPadding,
			AuthenticatedLength: node.VMess.AuthenticatedLength,
			PacketEncoding:      packetEncoding,
		}, nil
	case domain.NodeVLESS:
		network := ""
		switch node.VLESS.Network {
		case domain.ProxyNetworkBoth:
		case domain.ProxyNetworkTCP:
			network = "tcp"
		case domain.ProxyNetworkUDP:
			network = "udp"
		default:
			return NodeOutboundConfig{}, fmt.Errorf(
				"%w: unsupported VLESS network %q",
				domain.ErrInvalidNode,
				node.VLESS.Network,
			)
		}
		var packetEncoding *string
		if node.VLESS.PacketEncoding != nil {
			value := *node.VLESS.PacketEncoding
			packetEncoding = &value
		}
		return NodeOutboundConfig{
			Type:           "vless",
			Tag:            tag,
			Server:         node.Server,
			ServerPort:     node.Port,
			Network:        network,
			UUID:           node.VLESS.UUID,
			Flow:           node.VLESS.Flow,
			Encryption:     node.VLESS.Encryption,
			PacketEncoding: packetEncoding,
		}, nil
	case domain.NodeTrojan:
		network := ""
		switch node.Trojan.Network {
		case domain.ProxyNetworkBoth:
		case domain.ProxyNetworkTCP:
			network = "tcp"
		case domain.ProxyNetworkUDP:
			network = "udp"
		default:
			return NodeOutboundConfig{}, fmt.Errorf(
				"%w: unsupported Trojan network %q",
				domain.ErrInvalidNode,
				node.Trojan.Network,
			)
		}
		return NodeOutboundConfig{
			Type:       "trojan",
			Tag:        tag,
			Server:     node.Server,
			ServerPort: node.Port,
			Password:   node.Trojan.Password,
			Network:    network,
		}, nil
	default:
		return NodeOutboundConfig{}, fmt.Errorf("%w: unsupported basic node kind %q", domain.ErrInvalidNode, node.Kind)
	}
}
