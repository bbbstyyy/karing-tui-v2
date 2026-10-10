package compiler

import "fmt"

func BindGroupDNSRouting(bound BoundRouting, dns CompiledDNS) (BoundRouting, error) {
	rebound := cloneBoundRouting(bound)
	if len(dns.GroupBindings) == 0 {
		return rebound, nil
	}

	sourceByIndex := make(map[int]RouteSourceMapEntry, len(bound.SourceMap))
	for _, entry := range bound.SourceMap {
		if _, exists := sourceByIndex[entry.RuleIndex]; exists {
			return BoundRouting{}, fmt.Errorf("%w: duplicate source-map rule index %d", ErrNativeConfigClosure, entry.RuleIndex)
		}
		sourceByIndex[entry.RuleIndex] = entry
	}

	rules := make([]RouteRule, 0, len(bound.Rules)+len(dns.GroupBindings))
	sourceMap := make([]RouteSourceMapEntry, 0, len(bound.SourceMap)+len(dns.GroupBindings))

	for index, original := range bound.Rules {
		rule := cloneRouteRules([]RouteRule{original})[0]
		entry, userRule := sourceByIndex[index]
		if userRule && entry.DNSProfileID != "" {
			if entry.Action != "route" || rule.Action != "route" {
				return BoundRouting{}, fmt.Errorf("%w: group %q DNS binding is attached to non-route action %q", ErrNativeConfigClosure, entry.GroupID, entry.Action)
			}
			binding, exists := groupDNSBindingForSource(dns, entry)
			if !exists {
				return BoundRouting{}, fmt.Errorf("%w: group %q DNS profile %q is not compiled", ErrDNSClosure, entry.GroupID, entry.DNSProfileID)
			}
			if !compiledDNSHasTag(dns, binding.RuntimeTag) {
				return BoundRouting{}, fmt.Errorf("%w: group %q resolver %q is unavailable", ErrDNSClosure, entry.GroupID, binding.RuntimeTag)
			}
			if !routeRulePreResolveSafe(rule) {
				return BoundRouting{}, fmt.Errorf("%w: group %q layer %q DNS override depends on destination IP or opaque rule-set state", ErrDNSRouteResolutionAmbiguous, entry.GroupID, entry.Layer)
			}

			resolve := cloneRouteRules([]RouteRule{rule})[0]
			resolve.Action = "resolve"
			resolve.Outbound = ""
			resolve.Server = binding.RuntimeTag
			resolveIndex := len(rules)
			rules = append(rules, resolve)

			resolveEntry := entry
			resolveEntry.RuleIndex = resolveIndex
			resolveEntry.Action = "resolve"
			resolveEntry.Outbound = ""
			resolveEntry.Server = binding.RuntimeTag
			sourceMap = append(sourceMap, resolveEntry)
		}

		routeIndex := len(rules)
		rules = append(rules, rule)
		if userRule {
			entry.RuleIndex = routeIndex
			entry.Server = ""
			sourceMap = append(sourceMap, entry)
		}
	}

	rebound.Rules = rules
	rebound.SourceMap = sourceMap
	return rebound, nil
}

func validateGroupDNSRouteBindings(routing BoundRouting, dns CompiledDNS) error {
	for _, binding := range dns.GroupBindings {
		resolveFound := false
		routeFound := false
		for _, entry := range routing.SourceMap {
			if entry.GroupID != binding.GroupID || entry.DNSProfileID != binding.ProfileID {
				continue
			}
			switch entry.Action {
			case "resolve":
				if entry.Server == binding.RuntimeTag && entry.Outbound == "" {
					resolveFound = true
				}
			case "route":
				if entry.Server == "" {
					routeFound = true
				}
			}
		}
		if !resolveFound || !routeFound {
			return fmt.Errorf("%w: group %q DNS profile %q is not bound to a resolve/route pair", ErrNativeConfigClosure, binding.GroupID, binding.ProfileID)
		}
	}
	return nil
}
