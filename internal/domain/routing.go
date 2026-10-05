package domain

import (
	"errors"
	"fmt"
)

type RoutingLayer string

const (
	LayerCustom  RoutingLayer = "custom"
	LayerGeoSite RoutingLayer = "geosite"
	LayerGeoIP   RoutingLayer = "geoip"
	LayerACL     RoutingLayer = "acl"
	LayerFinal   RoutingLayer = "final"
)

type TargetKind string

const (
	TargetDirect          TargetKind = "direct"
	TargetBlock           TargetKind = "block"
	TargetCurrentSelected TargetKind = "current_selected"
	TargetGlobalURLTest   TargetKind = "global_urltest"
	TargetCustomURLTest   TargetKind = "custom_urltest"
	TargetSpecificNode    TargetKind = "specific_node"
)

var (
	ErrInvalidRoutingLayer = errors.New("invalid routing layer")
	ErrInvalidRouteTarget  = errors.New("invalid route target")
	ErrInvalidRouteOrder   = errors.New("invalid route order")
	ErrDuplicateRouteGroup = errors.New("duplicate route group")
	ErrInvalidFinalRoute   = errors.New("invalid final route")
)

type TargetRef struct {
	Kind      TargetKind
	GroupID   string
	ProfileID string
	NodeID    string
}

func (t TargetRef) Validate() error {
	switch t.Kind {
	case TargetDirect, TargetBlock, TargetCurrentSelected, TargetGlobalURLTest:
		if t.GroupID != "" || t.ProfileID != "" || t.NodeID != "" {
			return fmt.Errorf("%w: %s target must not carry IDs", ErrInvalidRouteTarget, t.Kind)
		}
	case TargetCustomURLTest:
		if t.GroupID == "" || t.ProfileID != "" || t.NodeID != "" {
			return fmt.Errorf("%w: custom URLTest requires only group ID", ErrInvalidRouteTarget)
		}
	case TargetSpecificNode:
		if t.GroupID != "" || t.ProfileID == "" || t.NodeID == "" {
			return fmt.Errorf("%w: specific node requires profile ID and node ID", ErrInvalidRouteTarget)
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidRouteTarget, t.Kind)
	}
	return nil
}

type RouteBinding struct {
	Enabled      bool
	Target       TargetRef
	DNSProfileID string
}

func (b RouteBinding) Validate() error {
	if !b.Enabled && b.Target.Kind == "" {
		return nil
	}
	if err := b.Target.Validate(); err != nil {
		return err
	}
	if b.Target.Kind == TargetBlock && b.DNSProfileID != "" {
		return fmt.Errorf("%w: BLOCK target cannot bind a DNS profile", ErrInvalidRouteTarget)
	}
	return nil
}

type RouteGroup struct {
	ID      string
	Layer   RoutingLayer
	Order   uint32
	Binding RouteBinding
}

func (g RouteGroup) Validate(expectedLayer RoutingLayer) error {
	if g.ID == "" {
		return errors.New("route group ID must not be empty")
	}
	if g.Layer != expectedLayer {
		return fmt.Errorf("%w: group %q is in %q, want %q", ErrInvalidRoutingLayer, g.ID, g.Layer, expectedLayer)
	}
	if err := g.Binding.Validate(); err != nil {
		return fmt.Errorf("route group %q: %w", g.ID, err)
	}
	return nil
}

type RoutingPlan struct {
	Custom  []RouteGroup
	GeoSite []RouteGroup
	GeoIP   []RouteGroup
	ACL     []RouteGroup
	Final   TargetRef
}

type RouteStep struct {
	Layer        RoutingLayer
	GroupID      string
	Target       TargetRef
	DNSProfileID string
	Final        bool
}

func (p RoutingPlan) Validate() error {
	seen := make(map[string]RoutingLayer)
	for _, layer := range []struct {
		kind   RoutingLayer
		groups []RouteGroup
	}{
		{kind: LayerCustom, groups: p.Custom},
		{kind: LayerGeoSite, groups: p.GeoSite},
		{kind: LayerGeoIP, groups: p.GeoIP},
		{kind: LayerACL, groups: p.ACL},
	} {
		if err := validateRouteLayer(layer.kind, layer.groups, seen); err != nil {
			return err
		}
	}
	if err := p.Final.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFinalRoute, err)
	}
	return nil
}

func (p RoutingPlan) OrderedActiveSteps() ([]RouteStep, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	steps := make([]RouteStep, 0, len(p.Custom)+len(p.GeoSite)+len(p.GeoIP)+len(p.ACL)+1)
	appendLayer := func(layer RoutingLayer, groups []RouteGroup) {
		for _, group := range groups {
			if !group.Binding.Enabled {
				continue
			}
			steps = append(steps, RouteStep{
				Layer:        layer,
				GroupID:      group.ID,
				Target:       group.Binding.Target,
				DNSProfileID: group.Binding.DNSProfileID,
			})
		}
	}
	appendLayer(LayerCustom, p.Custom)
	appendLayer(LayerGeoSite, p.GeoSite)
	appendLayer(LayerGeoIP, p.GeoIP)
	appendLayer(LayerACL, p.ACL)
	steps = append(steps, RouteStep{
		Layer:  LayerFinal,
		Target:  p.Final,
		Final:   true,
	})
	return steps, nil
}

func validateRouteLayer(layer RoutingLayer, groups []RouteGroup, seen map[string]RoutingLayer) error {
	var previous uint32
	for index, group := range groups {
		if err := group.Validate(layer); err != nil {
			return err
		}
		if previousLayer, exists := seen[group.ID]; exists {
			return fmt.Errorf("%w: group %q appears in %s and %s", ErrDuplicateRouteGroup, group.ID, previousLayer, layer)
		}
		seen[group.ID] = layer
		if index > 0 && group.Order <= previous {
			return fmt.Errorf("%w: %s group %q order %d must be greater than previous order %d", ErrInvalidRouteOrder, layer, group.ID, group.Order, previous)
		}
		previous = group.Order
	}
	return nil
}
