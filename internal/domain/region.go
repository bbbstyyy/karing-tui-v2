package domain

import (
	"errors"
	"fmt"
)

var ErrInvalidRegionAppend = errors.New("invalid region auto-append policy")

type RegionAppendPlan struct {
	RegionCode     string
	GeoSiteEnabled bool
	GeoIPEnabled   bool
	Target         TargetRef
}

func DefaultCNRegionAppendPlan() RegionAppendPlan {
	return RegionAppendPlan{
		RegionCode:     "cn",
		GeoSiteEnabled: true,
		GeoIPEnabled:   true,
		Target:         TargetRef{Kind: TargetDirect},
	}
}

func (p RegionAppendPlan) Validate() error {
	if len(p.RegionCode) != 2 ||
		p.RegionCode[0] < 'a' || p.RegionCode[0] > 'z' ||
		p.RegionCode[1] < 'a' || p.RegionCode[1] > 'z' {
		return fmt.Errorf("%w: region code %q must be lowercase ISO-3166 alpha-2", ErrInvalidRegionAppend, p.RegionCode)
	}
	if err := p.Target.Validate(); err != nil {
		return fmt.Errorf("%w: target: %v", ErrInvalidRegionAppend, err)
	}
	if p.Target.Kind != TargetDirect {
		return fmt.Errorf("%w: automatic region entries must target DIRECT", ErrInvalidRegionAppend)
	}
	return nil
}

func (p RegionAppendPlan) RuleSetRefs() ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	refs := make([]string, 0, 2)
	if p.GeoSiteEnabled {
		refs = append(refs, "geosite:"+p.RegionCode)
	}
	if p.GeoIPEnabled {
		refs = append(refs, "geoip:"+p.RegionCode)
	}
	return refs, nil
}

func ApplyRegionAppend(routing RoutingPlan, region RegionAppendPlan) (RoutingPlan, error) {
	if err := routing.Validate(); err != nil {
		return RoutingPlan{}, err
	}
	if err := region.Validate(); err != nil {
		return RoutingPlan{}, err
	}

	result := cloneRoutingPlanForRegionAppend(routing)
	if region.GeoSiteEnabled {
		group, err := regionAppendGroup(
			LayerGeoSite,
			"region:auto-geosite:"+region.RegionCode,
			"geosite:"+region.RegionCode,
			result.GeoSite,
			region.Target,
		)
		if err != nil {
			return RoutingPlan{}, err
		}
		result.GeoSite = append(result.GeoSite, group)
	}
	if region.GeoIPEnabled {
		group, err := regionAppendGroup(
			LayerGeoIP,
			"region:auto-geoip:"+region.RegionCode,
			"geoip:"+region.RegionCode,
			result.GeoIP,
			region.Target,
		)
		if err != nil {
			return RoutingPlan{}, err
		}
		result.GeoIP = append(result.GeoIP, group)
	}
	return result, nil
}

func regionAppendGroup(
	layer RoutingLayer,
	id string,
	ruleSetRef string,
	existing []RouteGroup,
	target TargetRef,
) (RouteGroup, error) {
	order := uint32(1)
	if len(existing) != 0 {
		last := existing[len(existing)-1].Order
		if last == ^uint32(0) {
			return RouteGroup{}, fmt.Errorf("%w: %s layer order overflow", ErrInvalidRegionAppend, layer)
		}
		order = last + 1
	}
	match := Atom(Predicate{Kind: PredicateRuleSet, Value: ruleSetRef})
	return RouteGroup{
		ID:    id,
		Layer: layer,
		Order: order,
		Match: &match,
		Binding: RouteBinding{
			Enabled: true,
			Target:  target,
		},
	}, nil
}

func cloneRoutingPlanForRegionAppend(source RoutingPlan) RoutingPlan {
	result := source
	result.Custom = cloneRegionRouteGroups(source.Custom)
	result.GeoSite = cloneRegionRouteGroups(source.GeoSite)
	result.GeoIP = cloneRegionRouteGroups(source.GeoIP)
	result.ACL = cloneRegionRouteGroups(source.ACL)
	return result
}

func cloneRegionRouteGroups(source []RouteGroup) []RouteGroup {
	if source == nil {
		return nil
	}
	result := make([]RouteGroup, len(source))
	for i, group := range source {
		result[i] = group
		if group.Match != nil {
			match := group.Match.Clone()
			result[i].Match = &match
		}
	}
	return result
}
