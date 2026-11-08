package declaration

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

var ErrInitialProxyOnlyDeclaration = errors.New("invalid initial proxy-only declaration")

// BuildInitialProxyOnlyV1 constructs an explicitly requested first-run,
// proxy-only declaration from accepted, already materialized profile nodes.
// No upstream subscription route is consulted. CN preset routing is NOT
// enabled, and this helper is not evidence for CN/MVP acceptance.
//
// Rule and Selected forward to CurrentSelected; no missing rule/resource
// silently falls back to DIRECT. Direct remains its separate explicit entry.
// Both DNS roles use the operator-supplied IP endpoint, never a default.
func BuildInitialProxyOnlyV1(
	nodes []domain.Node, selectedNodeID string, resolver netip.AddrPort,
) ([]byte, error) {
	if !resolver.IsValid() || resolver.Port() == 0 ||
		resolver.Addr().IsUnspecified() || resolver.Addr().IsMulticast() ||
		resolver.Addr().Zone() != "" {
		return nil, ErrInitialProxyOnlyDeclaration
	}
	if len(nodes) == 0 || selectedNodeID == "" {
		return nil, ErrInitialProxyOnlyDeclaration
	}
	wire := documentV1{
		SchemaVersion: SchemaVersionV1,
		LogLevel:      "warn",
		Nodes:         make([]nodeV1, 0, len(nodes)),
		Selection: selectionV1{
			Current: currentSelectionV1{
				Members: make([]domain.TargetRef, 0, len(nodes)),
			},
		},
		Routing: routingV1{
			Final: domain.TargetRef{Kind: domain.TargetCurrentSelected},
		},
		DNS: dnsV1{
			Profiles: []dnsProfileV1{
				{
					ID:        "first-run-outbound",
					Role:      domain.DNSRoleOutbound,
					Transport: domain.DNSTransportUDP,
					Server:    resolver.Addr().String(),
					Port:      resolver.Port(),
				},
				{
					ID:        "first-run-fallback",
					Role:      domain.DNSRoleFallback,
					Transport: domain.DNSTransportUDP,
					Server:    resolver.Addr().String(),
					Port:      resolver.Port(),
				},
			},
			OutboundProfileID: "first-run-outbound",
			FallbackProfileID: "first-run-fallback",
		},
	}
	profileID := nodes[0].ProfileID
	found := false
	for i, node := range nodes {
		if node.ProfileID != profileID {
			return nil, ErrInitialProxyOnlyDeclaration
		}
		encoded, err := nodeV1FromDomain(node)
		if err != nil {
			return nil, fmt.Errorf("%w: node %d is not supported", ErrInitialProxyOnlyDeclaration, i)
		}
		wire.Nodes = append(wire.Nodes, encoded)
		target := domain.TargetRef{
			Kind:      domain.TargetSpecificNode,
			ProfileID: node.ProfileID,
			NodeID:    node.NodeID,
		}
		wire.Selection.Current.Members = append(wire.Selection.Current.Members, target)
		if node.NodeID == selectedNodeID {
			wire.Selection.Current.Default = target
			found = true
		}
	}
	if !found {
		return nil, ErrInitialProxyOnlyDeclaration
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal initial document", ErrInitialProxyOnlyDeclaration)
	}
	if err := ValidateV1(document); err != nil {
		// Do not leak imported node fields or credentials via error text.
		return nil, ErrInitialProxyOnlyDeclaration
	}
	return document, nil
}
