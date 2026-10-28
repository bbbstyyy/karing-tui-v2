package compiler

import (
	"fmt"
	"reflect"
)

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
	// A source-map entry is evidence only when it describes the actual native rule.
	// An orphan, reordered or fabricated resolve must never satisfy a Group DNS binding.
	entries := make(map[int]RouteSourceMapEntry, len(routing.SourceMap))
	for _, entry := range routing.SourceMap {
		if entry.RuleIndex < 0 || entry.RuleIndex >= len(routing.Rules) {
			return fmt.Errorf("%w: Group DNS source-map index is out of bounds", ErrNativeConfigClosure)
		}
		if _, duplicated := entries[entry.RuleIndex]; duplicated {
			return fmt.Errorf("%w: duplicate Group DNS source-map index", ErrNativeConfigClosure)
		}
		entries[entry.RuleIndex] = entry
	}
	for _, binding := range dns.GroupBindings {
		pairs := 0
		for index, entry := range entries {
			if entry.GroupID != binding.GroupID || entry.DNSProfileID != binding.ProfileID {
				continue
			}
			if entry.Action != "resolve" {
				continue
			}
			if index+1 >= len(routing.Rules) {
				return fmt.Errorf("%w: Group DNS resolve has no following route", ErrNativeConfigClosure)
			}
			routeEntry, exists := entries[index+1]
			if !exists || routeEntry.Action != "route" ||
				routeEntry.GroupID != binding.GroupID ||
				routeEntry.DNSProfileID != binding.ProfileID ||
				routeEntry.Layer != entry.Layer ||
				routeEntry.Final != entry.Final ||
				!reflect.DeepEqual(routeEntry.Target, entry.Target) {
				return fmt.Errorf("%w: Group DNS resolve/route source-map pair is not adjacent", ErrNativeConfigClosure)
			}
			resolveRule := routing.Rules[index]
			routeRule := routing.Rules[index+1]
			if entry.Server != binding.RuntimeTag || entry.Outbound != "" ||
				resolveRule.Action != "resolve" || resolveRule.Server != binding.RuntimeTag || resolveRule.Outbound != "" ||
				routeEntry.Server != "" || routeEntry.Outbound != routeRule.Outbound ||
				routeRule.Action != "route" || routeRule.Server != "" || routeRule.Outbound == "" {
				return fmt.Errorf("%w: Group DNS source-map action differs from native route", ErrNativeConfigClosure)
			}
			// Only action and resolver/outbound are allowed to differ; all
			// matching predicates and ordering constraints must be identical.
			resolveRule.Action, resolveRule.Server, resolveRule.Outbound = "", "", ""
			routeRule.Action, routeRule.Server, routeRule.Outbound = "", "", ""
			if !reflect.DeepEqual(resolveRule, routeRule) {
				return fmt.Errorf("%w: Group DNS resolve and route have different predicates", ErrNativeConfigClosure)
			}
			pairs++
		}
		if pairs == 0 {
			return fmt.Errorf("%w: group %q DNS profile %q is not bound to a resolve/route pair", ErrNativeConfigClosure, binding.GroupID, binding.ProfileID)
		}
	}
	return nil
}
