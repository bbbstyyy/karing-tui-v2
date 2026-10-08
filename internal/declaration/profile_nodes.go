package declaration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

var ErrProfileNodeReplacementInvalid = errors.New("profile node replacement does not produce a valid declaration")

type ProfileNodeReplacementImpact struct {
	AddedNodeIDs    []string
	RemovedNodeIDs  []string
	RetainedNodeIDs []string
}

type ProfileNodeReplacement struct {
	Document []byte
	Impact   ProfileNodeReplacementImpact
}

// ReplaceProfileNodesV1 produces a new declaration document with one profile's
// inline node materialization replaced by an explicit snapshot result. It never
// reads mutable profile state; callers must load/materialize the exact snapshot
// they intend to bind before calling this function.
func ReplaceProfileNodesV1(
	document []byte,
	profileID string,
	nodes []domain.Node,
) (ProfileNodeReplacement, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return ProfileNodeReplacement{}, err
	}
	if _, err := ParseV1(document); err != nil {
		return ProfileNodeReplacement{}, err
	}

	wire, err := decodeDocumentWireV1(document)
	if err != nil {
		return ProfileNodeReplacement{}, err
	}

	replacements := make([]nodeV1, 0, len(nodes))
	newIDs := make(map[string]struct{}, len(nodes))
	for index, node := range nodes {
		if node.ProfileID != profileID {
			return ProfileNodeReplacement{}, fmt.Errorf(
				"replacement node %d belongs to profile %q, want %q",
				index,
				node.ProfileID,
				profileID,
			)
		}
		if _, duplicate := newIDs[node.NodeID]; duplicate {
			return ProfileNodeReplacement{}, fmt.Errorf("replacement profile repeats node ID %q", node.NodeID)
		}
		converted, err := nodeV1FromDomain(node)
		if err != nil {
			return ProfileNodeReplacement{}, fmt.Errorf("replacement node %d: %w", index, err)
		}
		newIDs[node.NodeID] = struct{}{}
		replacements = append(replacements, converted)
	}

	oldIDs := make(map[string]struct{})
	oldOrder := make([]string, 0)
	insertAt := -1
	kept := make([]nodeV1, 0, len(wire.Nodes)-len(oldOrder)+len(replacements))
	for _, node := range wire.Nodes {
		if node.ProfileID == profileID {
			if insertAt == -1 {
				insertAt = len(kept)
			}
			if _, seen := oldIDs[node.NodeID]; !seen {
				oldIDs[node.NodeID] = struct{}{}
				oldOrder = append(oldOrder, node.NodeID)
			}
			continue
		}
		kept = append(kept, node)
	}
	if insertAt == -1 {
		insertAt = len(kept)
	}

	merged := make([]nodeV1, 0, len(kept)+len(replacements))
	merged = append(merged, kept[:insertAt]...)
	merged = append(merged, replacements...)
	merged = append(merged, kept[insertAt:]...)
	wire.Nodes = merged

	impact := ProfileNodeReplacementImpact{}
	for _, node := range nodes {
		if _, existed := oldIDs[node.NodeID]; existed {
			impact.RetainedNodeIDs = append(impact.RetainedNodeIDs, node.NodeID)
		} else {
			impact.AddedNodeIDs = append(impact.AddedNodeIDs, node.NodeID)
		}
	}
	for _, nodeID := range oldOrder {
		if _, retained := newIDs[nodeID]; !retained {
			impact.RemovedNodeIDs = append(impact.RemovedNodeIDs, nodeID)
		}
	}

	output, err := json.Marshal(wire)
	if err != nil {
		return ProfileNodeReplacement{}, fmt.Errorf("marshal profile node replacement: %w", err)
	}
	result := ProfileNodeReplacement{
		Document: append([]byte(nil), output...),
		Impact:   impact,
	}
	if err := ValidateV1(output); err != nil {
		return result, fmt.Errorf("%w: %v", ErrProfileNodeReplacementInvalid, err)
	}
	return result, nil
}

func decodeDocumentWireV1(document []byte) (documentV1, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire documentV1
	if err := decoder.Decode(&wire); err != nil {
		return documentV1{}, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return documentV1{}, fmt.Errorf("%w: multiple JSON values are not allowed", ErrInvalidDocument)
		}
		return documentV1{}, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if wire.SchemaVersion != SchemaVersionV1 {
		return documentV1{}, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedSchema, wire.SchemaVersion, SchemaVersionV1)
	}
	return wire, nil
}

func nodeV1FromDomain(node domain.Node) (nodeV1, error) {
	if err := node.Validate(); err != nil {
		return nodeV1{}, err
	}
	result := nodeV1{
		ProfileID: node.ProfileID,
		NodeID:    node.NodeID,
		Type:      node.Kind,
		Server:    node.Server,
		Port:      node.Port,
	}
	switch node.Kind {
	case domain.NodeSOCKS:
		result.SOCKS = &socksV1{
			Version:  node.SOCKS.Version,
			Username: node.SOCKS.Username,
			Password: node.SOCKS.Password,
			Network:  node.SOCKS.Network,
		}
	case domain.NodeHTTP:
		result.HTTP = &httpV1{
			Username: node.HTTP.Username,
			Password: node.HTTP.Password,
		}
	case domain.NodeShadowsocks:
		result.Shadowsocks = &shadowsocksV1{
			Method:        node.Shadowsocks.Method,
			Password:      node.Shadowsocks.Password,
			Plugin:        node.Shadowsocks.Plugin,
			PluginOptions: node.Shadowsocks.PluginOptions,
			Network:       node.Shadowsocks.Network,
		}
	case domain.NodeVMess:
		result.VMess = &vmessV1{
			UUID:                node.VMess.UUID,
			Security:            node.VMess.Security,
			AlterID:             node.VMess.AlterID,
			GlobalPadding:       node.VMess.GlobalPadding,
			AuthenticatedLength: node.VMess.AuthenticatedLength,
			Network:             node.VMess.Network,
			PacketEncoding:      node.VMess.PacketEncoding,
		}
	default:
		return nodeV1{}, fmt.Errorf("unsupported node type %q", node.Kind)
	}
	return result, nil
}
