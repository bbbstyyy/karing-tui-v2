package domain

import (
	"errors"
	"fmt"
	"net/netip"
)

type DNSRole string

const (
	DNSRoleBootstrap DNSRole = "bootstrap"
	DNSRoleOutbound  DNSRole = "outbound"
	DNSRoleDirect    DNSRole = "direct"
	DNSRoleProxy     DNSRole = "proxy"
	DNSRoleGroup     DNSRole = "group"
	DNSRoleFallback  DNSRole = "fallback"
)

type DNSTransport string

const (
	DNSTransportUDP DNSTransport = "udp"
	DNSTransportTCP DNSTransport = "tcp"
)

var (
	ErrInvalidDNSPlan      = errors.New("invalid DNS plan")
	ErrDuplicateDNSProfile = errors.New("duplicate DNS profile")
	ErrDNSDependencyCycle  = errors.New("DNS dependency cycle")
	ErrInvalidDNSRouteBind = errors.New("invalid route DNS binding")
)

type DNSProfile struct {
	ID                 string
	Role               DNSRole
	Transport          DNSTransport
	Server             string
	Port               uint16
	BootstrapProfileID string
}

func (p DNSProfile) Validate() error {
	if err := validateNodeID(p.ID); err != nil {
		return fmt.Errorf("%w: profile ID %q: %v", ErrInvalidDNSPlan, p.ID, err)
	}
	switch p.Role {
	case DNSRoleBootstrap, DNSRoleOutbound, DNSRoleDirect, DNSRoleProxy, DNSRoleGroup, DNSRoleFallback:
	default:
		return fmt.Errorf("%w: profile %q has unsupported role %q", ErrInvalidDNSPlan, p.ID, p.Role)
	}
	switch p.Transport {
	case DNSTransportUDP, DNSTransportTCP:
	default:
		return fmt.Errorf("%w: profile %q has unsupported transport %q", ErrInvalidDNSPlan, p.ID, p.Transport)
	}
	if p.Port == 0 {
		return fmt.Errorf("%w: profile %q must use an explicit non-zero port", ErrInvalidDNSPlan, p.ID)
	}
	if err := validateServerHost(p.Server); err != nil {
		return fmt.Errorf("%w: profile %q server: %v", ErrInvalidDNSPlan, p.ID, err)
	}
	if _, err := netip.ParseAddr(p.Server); err == nil {
		if p.BootstrapProfileID != "" {
			return fmt.Errorf("%w: IP-literal DNS profile %q must not declare bootstrap dependency", ErrInvalidDNSPlan, p.ID)
		}
		return nil
	}
	if p.BootstrapProfileID == "" {
		return fmt.Errorf("%w: domain-valued DNS profile %q requires a bootstrap profile", ErrInvalidDNSPlan, p.ID)
	}
	if p.BootstrapProfileID == p.ID {
		return fmt.Errorf("%w: profile %q depends on itself", ErrDNSDependencyCycle, p.ID)
	}
	return nil
}

type DNSPlan struct {
	Profiles          []DNSProfile
	OutboundProfileID string
	DirectProfileID   string
	ProxyProfileID    string
	FallbackProfileID string
}

func (p DNSPlan) Validate() error {
	byID := make(map[string]DNSProfile, len(p.Profiles))
	for _, profile := range p.Profiles {
		if err := profile.Validate(); err != nil {
			return err
		}
		if _, exists := byID[profile.ID]; exists {
			return fmt.Errorf("%w: %q", ErrDuplicateDNSProfile, profile.ID)
		}
		byID[profile.ID] = profile
	}

	for _, profile := range p.Profiles {
		if profile.BootstrapProfileID == "" {
			continue
		}
		bootstrap, exists := byID[profile.BootstrapProfileID]
		if !exists {
			return fmt.Errorf("%w: profile %q references missing bootstrap %q", ErrInvalidDNSPlan, profile.ID, profile.BootstrapProfileID)
		}
		if bootstrap.Role != DNSRoleBootstrap {
			return fmt.Errorf("%w: profile %q bootstrap %q has role %q", ErrInvalidDNSPlan, profile.ID, bootstrap.ID, bootstrap.Role)
		}
	}
	if err := validateDNSBootstrapDAG(byID, p.Profiles); err != nil {
		return err
	}

	for _, binding := range []struct {
		id   string
		role DNSRole
		name string
	}{
		{id: p.OutboundProfileID, role: DNSRoleOutbound, name: "outbound"},
		{id: p.DirectProfileID, role: DNSRoleDirect, name: "direct"},
		{id: p.ProxyProfileID, role: DNSRoleProxy, name: "proxy"},
		{id: p.FallbackProfileID, role: DNSRoleFallback, name: "fallback"},
	} {
		if binding.id == "" {
			continue
		}
		profile, exists := byID[binding.id]
		if !exists {
			return fmt.Errorf("%w: %s DNS profile %q does not exist", ErrInvalidDNSPlan, binding.name, binding.id)
		}
		if profile.Role != binding.role {
			return fmt.Errorf("%w: %s DNS profile %q has role %q, want %q", ErrInvalidDNSPlan, binding.name, binding.id, profile.Role, binding.role)
		}
	}
	return nil
}

func (p DNSPlan) Profile(id string) (DNSProfile, bool) {
	for _, profile := range p.Profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return DNSProfile{}, false
}

func (p DNSPlan) ValidateActiveRouteBindings(routing RoutingPlan) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := routing.Validate(); err != nil {
		return err
	}
	for _, groups := range [][]RouteGroup{routing.Custom, routing.GeoSite, routing.GeoIP, routing.ACL} {
		for _, group := range groups {
			if !group.Binding.Enabled || group.Binding.DNSProfileID == "" {
				continue
			}
			profile, exists := p.Profile(group.Binding.DNSProfileID)
			if !exists {
				return fmt.Errorf("%w: group %q references missing DNS profile %q", ErrInvalidDNSRouteBind, group.ID, group.Binding.DNSProfileID)
			}
			if profile.Role != DNSRoleGroup {
				return fmt.Errorf("%w: group %q DNS profile %q has role %q, want %q", ErrInvalidDNSRouteBind, group.ID, profile.ID, profile.Role, DNSRoleGroup)
			}
		}
	}
	return nil
}

func validateDNSBootstrapDAG(byID map[string]DNSProfile, ordered []DNSProfile) error {
	const (
		unseen uint8 = iota
		visiting
		done
	)
	state := make(map[string]uint8, len(byID))
	var visit func(string) error
	visit = func(id string) error {
		switch state[id] {
		case visiting:
			return fmt.Errorf("%w: %q", ErrDNSDependencyCycle, id)
		case done:
			return nil
		}
		state[id] = visiting
		profile := byID[id]
		if profile.BootstrapProfileID != "" {
			if err := visit(profile.BootstrapProfileID); err != nil {
				return err
			}
		}
		state[id] = done
		return nil
	}
	for _, profile := range ordered {
		if err := visit(profile.ID); err != nil {
			return err
		}
	}
	return nil
}
