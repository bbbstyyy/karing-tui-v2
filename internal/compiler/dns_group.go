package compiler

import (
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func CompileRuntimeDNSForRouting(
	plan domain.DNSPlan,
	routing domain.RoutingPlan,
	targets TargetCatalog,
) (CompiledDNS, error) {
	if err := plan.ValidateActiveRouteBindings(routing); err != nil {
		return CompiledDNS{}, err
	}
	result, err := CompileRuntimeDNS(plan, targets)
	if err != nil {
		return CompiledDNS{}, err
	}
	steps, err := routing.OrderedActiveSteps()
	if err != nil {
		return CompiledDNS{}, err
	}

	byID := make(map[string]domain.DNSProfile, len(plan.Profiles))
	for _, profile := range plan.Profiles {
		byID[profile.ID] = profile
	}
	emitted := make(map[string]struct{}, len(result.ProfileBindings))
	for _, binding := range result.ProfileBindings {
		emitted[binding.ProfileID] = struct{}{}
	}
	detourSeen := make(map[string]struct{}, len(result.DetourOutboundTags))
	for _, tag := range result.DetourOutboundTags {
		detourSeen[tag] = struct{}{}
	}
	recordDetour := func(tag string) {
		if tag == "" {
			return
		}
		if _, exists := detourSeen[tag]; exists {
			return
		}
		detourSeen[tag] = struct{}{}
		result.DetourOutboundTags = append(result.DetourOutboundTags, tag)
	}

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
		switch profile.Role {
		case domain.DNSRoleBootstrap:
		case domain.DNSRoleGroup:
			detour, err := resolveGroupDNSDetour(profile.DetourTarget, targets)
			if err != nil {
				return fmt.Errorf("%w: Group DNS profile %q detour: %v", ErrDNSClosure, profile.ID, err)
			}
			server.Detour = detour
			recordDetour(detour)
		default:
			return fmt.Errorf("%w: profile %q has role %q", ErrDNSRoleUnsupported, profile.ID, profile.Role)
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

	for _, step := range steps {
		if step.Final || step.DNSProfileID == "" {
			continue
		}
		profile, exists := byID[step.DNSProfileID]
		if !exists {
			return CompiledDNS{}, fmt.Errorf("%w: group %q references missing DNS profile %q", ErrDNSClosure, step.GroupID, step.DNSProfileID)
		}
		if err := emit(profile.ID); err != nil {
			return CompiledDNS{}, err
		}
		detour, err := resolveGroupDNSDetour(profile.DetourTarget, targets)
		if err != nil {
			return CompiledDNS{}, err
		}
		result.GroupBindings = append(result.GroupBindings, DNSGroupBinding{
			GroupID:        step.GroupID,
			ProfileID:      profile.ID,
			RuntimeTag:     stableDNSTag(profile.ID),
			DetourOutbound: detour,
		})
	}
	return result, nil
}

func resolveGroupDNSDetour(target domain.TargetRef, targets TargetCatalog) (string, error) {
	if target.Kind == domain.TargetDirect {
		return "", nil
	}
	tag, err := targets.ResolveTarget(target)
	if err != nil {
		return "", err
	}
	return tag, nil
}

func RuntimeOutboundRequirements(routing CompiledRouting, dns CompiledDNS) []string {
	result := make([]string, 0, len(routing.OutboundTags)+len(dns.DetourOutboundTags))
	seen := make(map[string]struct{}, cap(result))
	appendTag := func(tag string) {
		if tag == "" {
			return
		}
		if _, exists := seen[tag]; exists {
			return
		}
		seen[tag] = struct{}{}
		result = append(result, tag)
	}
	for _, tag := range routing.OutboundTags {
		appendTag(tag)
	}
	for _, tag := range dns.DetourOutboundTags {
		appendTag(tag)
	}
	return result
}

func groupDNSBindingForSource(dns CompiledDNS, entry RouteSourceMapEntry) (DNSGroupBinding, bool) {
	for _, binding := range dns.GroupBindings {
		if binding.GroupID == entry.GroupID && binding.ProfileID == entry.DNSProfileID {
			return binding, true
		}
	}
	return DNSGroupBinding{}, false
}

func compiledDNSDetourPolicy(dns CompiledDNS, targets TargetCatalog) (map[string]string, error) {
	policy := make(map[string]string, 1+len(dns.GroupBindings))
	if dns.ProxyResolverTag != "" {
		policy[dns.ProxyResolverTag] = targets.CurrentSelectedTag
	}
	for _, binding := range dns.GroupBindings {
		if binding.RuntimeTag == "" {
			return nil, fmt.Errorf("%w: group %q has an empty DNS runtime tag", ErrDNSClosure, binding.GroupID)
		}
		if existing, exists := policy[binding.RuntimeTag]; exists && existing != binding.DetourOutbound {
			return nil, fmt.Errorf("%w: DNS server %q has conflicting detours %q and %q", ErrDNSClosure, binding.RuntimeTag, existing, binding.DetourOutbound)
		}
		policy[binding.RuntimeTag] = binding.DetourOutbound
	}
	return policy, nil
}
