package declaration

import (
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

type routingV1 struct {
	CustomEnabled  *bool            `json:"custom_enabled,omitempty"`
	GeoSiteEnabled *bool            `json:"geosite_enabled,omitempty"`
	GeoIPEnabled   *bool            `json:"geoip_enabled,omitempty"`
	ACLEnabled     *bool            `json:"acl_enabled,omitempty"`
	Custom         []routeGroupV1   `json:"custom,omitempty"`
	GeoSite        []routeGroupV1   `json:"geosite,omitempty"`
	GeoIP          []routeGroupV1   `json:"geoip,omitempty"`
	ACL            []routeGroupV1   `json:"acl,omitempty"`
	Final          domain.TargetRef `json:"final"`
}

type routeGroupV1 struct {
	ID           string           `json:"id"`
	Order        uint32           `json:"order"`
	Enabled      bool             `json:"enabled"`
	Target       domain.TargetRef `json:"target,omitempty"`
	DNSProfileID string           `json:"dns_profile_id,omitempty"`
	Match        *matchV1         `json:"match,omitempty"`
}

type matchV1 struct {
	Op        domain.MatchOp `json:"op"`
	Predicate *predicateV1   `json:"predicate,omitempty"`
	Children  []matchV1      `json:"children,omitempty"`
}

type predicateV1 struct {
	Kind    domain.PredicateKind `json:"kind"`
	Value   string               `json:"value,omitempty"`
	CIDR    string               `json:"cidr,omitempty"`
	Port    *portRangeV1         `json:"port,omitempty"`
	Network domain.NetworkType   `json:"network,omitempty"`
}

type portRangeV1 struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

func (r routingV1) toDomain() (domain.RoutingPlan, error) {
	result := domain.RoutingPlan{
		Layers: domain.RoutingLayerSwitches{
			CustomDisabled:  explicitlyDisabled(r.CustomEnabled),
			GeoSiteDisabled: explicitlyDisabled(r.GeoSiteEnabled),
			GeoIPDisabled:   explicitlyDisabled(r.GeoIPEnabled),
			ACLDisabled:     explicitlyDisabled(r.ACLEnabled),
		},
		Final: r.Final,
	}
	var err error
	if result.Custom, err = convertRouteGroups(domain.LayerCustom, r.Custom); err != nil {
		return domain.RoutingPlan{}, err
	}
	if result.GeoSite, err = convertRouteGroups(domain.LayerGeoSite, r.GeoSite); err != nil {
		return domain.RoutingPlan{}, err
	}
	if result.GeoIP, err = convertRouteGroups(domain.LayerGeoIP, r.GeoIP); err != nil {
		return domain.RoutingPlan{}, err
	}
	if result.ACL, err = convertRouteGroups(domain.LayerACL, r.ACL); err != nil {
		return domain.RoutingPlan{}, err
	}
	return result, nil
}

func convertRouteGroups(layer domain.RoutingLayer, groups []routeGroupV1) ([]domain.RouteGroup, error) {
	result := make([]domain.RouteGroup, 0, len(groups))
	for i, group := range groups {
		converted := domain.RouteGroup{
			ID:    group.ID,
			Layer: layer,
			Order: group.Order,
			Binding: domain.RouteBinding{
				Enabled:      group.Enabled,
				Target:       group.Target,
				DNSProfileID: group.DNSProfileID,
			},
		}
		if group.Match != nil {
			match, err := group.Match.toDomain()
			if err != nil {
				return nil, fmt.Errorf("%w: %s group %d match: %v", ErrInvalidDocument, layer, i, err)
			}
			converted.Match = &match
		}
		if !group.Enabled && group.Target.Kind == "" && group.DNSProfileID != "" {
			return nil, fmt.Errorf("%w: disabled group %q cannot carry DNS without a target", ErrInvalidDocument, group.ID)
		}
		result = append(result, converted)
	}
	return result, nil
}

func (m matchV1) toDomain() (domain.MatchExpr, error) {
	result := domain.MatchExpr{Op: m.Op}
	if m.Predicate != nil {
		predicate := domain.Predicate{
			Kind:    m.Predicate.Kind,
			Value:   m.Predicate.Value,
			CIDR:    m.Predicate.CIDR,
			Network: m.Predicate.Network,
		}
		if m.Predicate.Port != nil {
			predicate.Port = domain.PortRange{Start: m.Predicate.Port.Start, End: m.Predicate.Port.End}
		}
		result.Predicate = &predicate
	}
	if len(m.Children) != 0 {
		result.Children = make([]domain.MatchExpr, len(m.Children))
		for i := range m.Children {
			child, err := m.Children[i].toDomain()
			if err != nil {
				return domain.MatchExpr{}, err
			}
			result.Children[i] = child
		}
	}
	if err := result.Validate(); err != nil {
		return domain.MatchExpr{}, err
	}
	return result, nil
}

type dnsV1 struct {
	Profiles          []dnsProfileV1 `json:"profiles"`
	OutboundProfileID string         `json:"outbound_profile_id"`
	DirectProfileID   string         `json:"direct_profile_id,omitempty"`
	ProxyProfileID    string         `json:"proxy_profile_id,omitempty"`
	FallbackProfileID string         `json:"fallback_profile_id,omitempty"`
}

type dnsProfileV1 struct {
	ID                 string              `json:"id"`
	Role               domain.DNSRole      `json:"role"`
	Transport          domain.DNSTransport `json:"transport"`
	Server             string              `json:"server"`
	Port               uint16              `json:"port"`
	BootstrapProfileID string              `json:"bootstrap_profile_id,omitempty"`
	DetourTarget       *domain.TargetRef   `json:"detour_target,omitempty"`
}

func (d dnsV1) toDomain() (domain.DNSPlan, error) {
	result := domain.DNSPlan{
		OutboundProfileID: d.OutboundProfileID,
		DirectProfileID:   d.DirectProfileID,
		ProxyProfileID:    d.ProxyProfileID,
		FallbackProfileID: d.FallbackProfileID,
		Profiles:          make([]domain.DNSProfile, 0, len(d.Profiles)),
	}
	for i, profile := range d.Profiles {
		converted := domain.DNSProfile{
			ID:                 profile.ID,
			Role:               profile.Role,
			Transport:          profile.Transport,
			Server:             profile.Server,
			Port:               profile.Port,
			BootstrapProfileID: profile.BootstrapProfileID,
		}
		if profile.DetourTarget != nil {
			converted.DetourTarget = *profile.DetourTarget
		}
		if err := converted.Validate(); err != nil {
			return domain.DNSPlan{}, fmt.Errorf("%w: DNS profile %d: %v", ErrInvalidDocument, i, err)
		}
		result.Profiles = append(result.Profiles, converted)
	}
	if result.OutboundProfileID == "" {
		return domain.DNSPlan{}, fmt.Errorf("%w: outbound_profile_id is required", ErrInvalidDocument)
	}
	return result, nil
}

func explicitlyDisabled(enabled *bool) bool {
	return enabled != nil && !*enabled
}
