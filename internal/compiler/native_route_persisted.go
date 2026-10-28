package compiler

import (
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

// ValidatePersistedRouteProvenance independently rechecks a loaded generation's
// native route rules and source-map metadata before an explanation can attribute
// a decision to a user group. Individual artifact hashes do not establish this
// cross-artifact relationship.
//
// The original declaration and selected DNS detour policy are not recoverable
// from these metadata alone. This is bounded structural evidence, NOT a claim
// of observed routing, signed provenance or full compiler replay.
func ValidatePersistedRouteProvenance(
	rules []RouteRule, sourceMap []RouteSourceMapEntry, dnsServerTags []string,
) error {
	availableDNS := make(map[string]struct{}, len(dnsServerTags))
	for _, tag := range dnsServerTags {
		if _, exists := availableDNS[tag]; exists || tag == "" {
			return fmt.Errorf("%w: invalid or duplicate persisted DNS server tag", ErrNativeConfigClosure)
		}
		availableDNS[tag] = struct{}{}
	}

	var customIDs []string
	var nodeKeys []NodeTargetKey
	customSeen := make(map[string]struct{})
	nodeSeen := make(map[NodeTargetKey]struct{})
	groupSeen := make(map[string]struct{})
	dns := CompiledDNS{}
	proxyResolver := ""

	for _, entry := range sourceMap {
		switch entry.Target.Kind {
		case domain.TargetCustomURLTest:
			if _, exists := customSeen[entry.Target.GroupID]; !exists {
				customSeen[entry.Target.GroupID] = struct{}{}
				customIDs = append(customIDs, entry.Target.GroupID)
			}
		case domain.TargetSpecificNode:
			key := NodeTargetKey{
				ProfileID: entry.Target.ProfileID,
				NodeID:    entry.Target.NodeID,
			}
			if _, exists := nodeSeen[key]; !exists {
				nodeSeen[key] = struct{}{}
				nodeKeys = append(nodeKeys, key)
			}
		}
		if entry.DNSProfileID != "" {
			key := entry.GroupID + "\x00" + entry.DNSProfileID
			if _, exists := groupSeen[key]; !exists {
				groupSeen[key] = struct{}{}
				dns.GroupBindings = append(dns.GroupBindings, DNSGroupBinding{
					GroupID:    entry.GroupID,
					ProfileID:  entry.DNSProfileID,
					RuntimeTag: stableDNSTag(entry.DNSProfileID),
				})
			}
		}
		if entry.Action != "resolve" {
			continue
		}
		if _, exists := availableDNS[entry.Server]; !exists {
			return fmt.Errorf("%w: persisted route resolver is absent from native DNS manifest", ErrNativeConfigClosure)
		}
		if entry.DNSProfileID != "" {
			if entry.Server != stableDNSTag(entry.DNSProfileID) {
				return fmt.Errorf("%w: Group DNS resolver and source profile disagree", ErrNativeConfigClosure)
			}
			continue
		}
		if proxyResolver != "" && proxyResolver != entry.Server {
			return fmt.Errorf("%w: conflicting persisted Proxy DNS resolvers", ErrNativeConfigClosure)
		}
		proxyResolver = entry.Server
	}

	// Proxy DNS synthetic Selected resolves have no source-map entries.
	// Recover the resolver identity from their adjacent native rule pair.
	for index, rule := range rules {
		if !isSelectedSyntheticRoute(rule) || index == 0 {
			continue
		}
		previous := rules[index-1]
		if previous.Action != "resolve" || previous.Server == "" {
			continue
		}
		if proxyResolver != "" && proxyResolver != previous.Server {
			return fmt.Errorf("%w: Selected and user route Proxy DNS resolvers differ", ErrNativeConfigClosure)
		}
		if _, exists := availableDNS[previous.Server]; !exists {
			return fmt.Errorf("%w: Selected Proxy DNS resolver is absent from manifest", ErrNativeConfigClosure)
		}
		proxyResolver = previous.Server
	}

	targets, err := NewTargetCatalog(customIDs, nodeKeys)
	if err != nil {
		return fmt.Errorf("%w: invalid persisted route target catalog: %v", ErrNativeConfigClosure, err)
	}
	dns.ProxyResolverTag = proxyResolver
	bound := BoundRouting{
		CompiledRouting: CompiledRouting{
			Rules:     rules,
			SourceMap: sourceMap,
		},
	}
	if err := validateNativeRouteProvenance(bound, targets, dns); err != nil {
		return err
	}
	if err := validateGroupDNSRouteBindings(bound, dns); err != nil {
		return err
	}
	if proxyResolver != "" {
		if err := validateProxyDNSRouteBindings(bound, dns, targets); err != nil {
			return err
		}
	}
	return nil
}
