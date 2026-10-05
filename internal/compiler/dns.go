package compiler

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

var ErrDNSClosure = errors.New("DNS dependency closure is incomplete")

type DNSServerConfig struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	Server         string `json:"server"`
	ServerPort     uint16 `json:"server_port"`
	Detour         string `json:"detour,omitempty"`
	DomainResolver string `json:"domain_resolver,omitempty"`
}

type DNSProfileBinding struct {
	ProfileID  string
	RuntimeTag string
}

type CompiledDNS struct {
	Servers             []DNSServerConfig
	ProfileBindings     []DNSProfileBinding
	OutboundResolverTag string
}

func CompileOutboundDNS(plan domain.DNSPlan, targets TargetCatalog) (CompiledDNS, error) {
	if err := plan.Validate(); err != nil {
		return CompiledDNS{}, err
	}
	if err := targets.Validate(); err != nil {
		return CompiledDNS{}, err
	}
	if plan.OutboundProfileID == "" {
		return CompiledDNS{}, fmt.Errorf("%w: outbound DNS profile is not configured", ErrDNSClosure)
	}

	byID := make(map[string]domain.DNSProfile, len(plan.Profiles))
	for _, profile := range plan.Profiles {
		byID[profile.ID] = profile
	}

	var result CompiledDNS
	emitted := make(map[string]struct{}, len(plan.Profiles))
	var emit func(string) error
	emit = func(id string) error {
		if _, exists := emitted[id]; exists {
			return nil
		}
		profile, exists := byID[id]
		if !exists {
			return fmt.Errorf("%w: DNS profile %q does not exist", ErrDNSClosure, id)
		}
		if profile.BootstrapProfileID != "" {
			if err := emit(profile.BootstrapProfileID); err != nil {
				return err
			}
		}

		tag := stableDNSTag(profile.ID)
		if err := validateGeneratedTag(tag); err != nil {
			return err
		}
		server := DNSServerConfig{
			Type:       string(profile.Transport),
			Tag:        tag,
			Server:     profile.Server,
			ServerPort: profile.Port,
		}
		if profile.BootstrapProfileID != "" {
			server.DomainResolver = stableDNSTag(profile.BootstrapProfileID)
		}
		result.Servers = append(result.Servers, server)
		result.ProfileBindings = append(result.ProfileBindings, DNSProfileBinding{
			ProfileID:  profile.ID,
			RuntimeTag: tag,
		})
		emitted[id] = struct{}{}
		return nil
	}

	if err := emit(plan.OutboundProfileID); err != nil {
		return CompiledDNS{}, err
	}
	result.OutboundResolverTag = stableDNSTag(plan.OutboundProfileID)
	return result, nil
}

func BindNodeDomainResolver(nodes CompiledNodes, dns CompiledDNS) (CompiledNodes, error) {
	if len(nodes.Outbounds) != len(nodes.Tags) || len(nodes.Outbounds) != len(nodes.Targets) {
		return CompiledNodes{}, fmt.Errorf("%w: node compiler metadata lengths do not match", ErrDNSClosure)
	}

	available := make(map[string]struct{}, len(dns.Servers))
	for _, server := range dns.Servers {
		if server.Tag == "" {
			return CompiledNodes{}, fmt.Errorf("%w: DNS server has no runtime tag", ErrDNSClosure)
		}
		if _, exists := available[server.Tag]; exists {
			return CompiledNodes{}, fmt.Errorf("%w: duplicate DNS server tag %q", ErrDNSClosure, server.Tag)
		}
		available[server.Tag] = struct{}{}
	}
	if dns.OutboundResolverTag != "" {
		if _, exists := available[dns.OutboundResolverTag]; !exists {
			return CompiledNodes{}, fmt.Errorf("%w: outbound resolver tag %q is unavailable", ErrDNSClosure, dns.OutboundResolverTag)
		}
	}

	bound := CompiledNodes{
		Outbounds: append([]NodeOutboundConfig(nil), nodes.Outbounds...),
		Targets:   append([]domain.TargetRef(nil), nodes.Targets...),
		Tags:      append([]string(nil), nodes.Tags...),
	}
	for i := range bound.Outbounds {
		outbound := &bound.Outbounds[i]
		if _, err := netip.ParseAddr(outbound.Server); err == nil {
			if outbound.DomainResolver != "" {
				return CompiledNodes{}, fmt.Errorf("%w: IP-literal node %q already has a domain resolver", ErrDNSClosure, outbound.Tag)
			}
			continue
		}
		if dns.OutboundResolverTag == "" {
			return CompiledNodes{}, fmt.Errorf("%w: node %q requires outbound DNS", ErrDNSClosure, outbound.Tag)
		}
		if outbound.DomainResolver != "" && outbound.DomainResolver != dns.OutboundResolverTag {
			return CompiledNodes{}, fmt.Errorf("%w: node %q has conflicting domain resolver %q", ErrDNSClosure, outbound.Tag, outbound.DomainResolver)
		}
		outbound.DomainResolver = dns.OutboundResolverTag
	}
	return bound, nil
}

func stableDNSTag(profileID string) string {
	return stableTargetTag("dns-", "dns", profileID)
}
