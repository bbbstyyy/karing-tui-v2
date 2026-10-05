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
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	Server         string `json:"server"`
	ServerPort     uint16 `json:"server_port"`
	Version        string `json:"version,omitempty"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	Network        string `json:"network,omitempty"`
	DomainResolver string `json:"domain_resolver,omitempty"`
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
	default:
		return NodeOutboundConfig{}, fmt.Errorf("%w: unsupported basic node kind %q", domain.ErrInvalidNode, node.Kind)
	}
}
