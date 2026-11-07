package compiler

import (
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

var ErrDNSRouteResolutionAmbiguous = errors.New("route DNS resolution is ambiguous before target selection")

func BindProxyTargetDNSRouting(bound BoundRouting, dns CompiledDNS) (BoundRouting, error) {
	rebound := cloneBoundRouting(bound)
	if dns.ProxyResolverTag == "" {
		return rebound, nil
	}
	if !compiledDNSHasTag(dns, dns.ProxyResolverTag) {
		return BoundRouting{}, fmt.Errorf("%w: proxy resolver %q is unavailable", ErrDNSClosure, dns.ProxyResolverTag)
	}

	sourceByIndex := make(map[int]RouteSourceMapEntry, len(bound.SourceMap))
	for _, entry := range bound.SourceMap {
		if _, exists := sourceByIndex[entry.RuleIndex]; exists {
			return BoundRouting{}, fmt.Errorf("%w: duplicate source-map rule index %d", ErrNativeConfigClosure, entry.RuleIndex)
		}
		sourceByIndex[entry.RuleIndex] = entry
	}

	rules := make([]RouteRule, 0, len(bound.Rules)+1+len(bound.SourceMap))
	sourceMap := make([]RouteSourceMapEntry, 0, len(bound.SourceMap)*2)
	selectedResolveInserted := false

	for index, original := range bound.Rules {
		rule := cloneRouteRules([]RouteRule{original})[0]

		if isSelectedSyntheticRoute(rule) || isGlobalModeSyntheticRoute(rule) {
			resolve := RouteRule{
				Inbound:   append([]string(nil), rule.Inbound...),
				ClashMode: rule.ClashMode,
				Action:    "resolve",
				Server:    dns.ProxyResolverTag,
			}
			rules = append(rules, resolve)
			if isSelectedSyntheticRoute(rule) {
				selectedResolveInserted = true
			}
		}

		entry, userRule := sourceByIndex[index]
		if userRule && entry.Action == "route" && entry.DNSProfileID == "" && isProxyTarget(entry.Target) {
			if !routeRulePreResolveSafe(rule) {
				return BoundRouting{}, fmt.Errorf("%w: group %q layer %q target %q depends on destination IP or opaque rule-set state", ErrDNSRouteResolutionAmbiguous, entry.GroupID, entry.Layer, entry.Target.Kind)
			}
			resolve := cloneRouteRules([]RouteRule{rule})[0]
			resolve.Action = "resolve"
			resolve.Outbound = ""
			resolve.Server = dns.ProxyResolverTag
			resolveIndex := len(rules)
			rules = append(rules, resolve)

			resolveEntry := entry
			resolveEntry.RuleIndex = resolveIndex
			resolveEntry.Action = "resolve"
			resolveEntry.Outbound = ""
			resolveEntry.Server = dns.ProxyResolverTag
			sourceMap = append(sourceMap, resolveEntry)
		}

		routeIndex := len(rules)
		rules = append(rules, rule)
		if userRule {
			entry.RuleIndex = routeIndex
			if entry.Action == "route" {
				entry.Server = ""
			}
			sourceMap = append(sourceMap, entry)
		}
	}

	if !selectedResolveInserted {
		return BoundRouting{}, fmt.Errorf("%w: Selected synthetic route is missing", ErrNativeConfigClosure)
	}

	rebound.Rules = rules
	rebound.SourceMap = sourceMap
	return rebound, nil
}

func cloneBoundRouting(bound BoundRouting) BoundRouting {
	rebound := bound
	rebound.Rules = cloneRouteRules(bound.Rules)
	rebound.RuleSetRefs = append([]string(nil), bound.RuleSetRefs...)
	rebound.OutboundTags = append([]string(nil), bound.OutboundTags...)
	rebound.SourceMap = append([]RouteSourceMapEntry(nil), bound.SourceMap...)
	rebound.RuleSets = append([]RuleSetArtifact(nil), bound.RuleSets...)
	return rebound
}

func compiledDNSHasTag(dns CompiledDNS, tag string) bool {
	for _, server := range dns.Servers {
		if server.Tag == tag {
			return true
		}
	}
	return false
}

func isSelectedSyntheticRoute(rule RouteRule) bool {
	return len(rule.Inbound) == 1 &&
		rule.Inbound[0] == domain.InboundTagSelected &&
		rule.Action == "route" &&
		rule.Outbound != ""
}

func isGlobalModeSyntheticRoute(rule RouteRule) bool {
	return len(rule.Inbound) == 1 &&
		rule.Inbound[0] == domain.InboundTagRule &&
		(rule.ClashMode == "Global" || rule.ClashMode == "GlobalNoPrivate") &&
		!rule.IPIsPrivate &&
		rule.Action == "route" &&
		rule.Outbound == CurrentSelectedOutboundTag
}

func isProxyTarget(target domain.TargetRef) bool {
	switch target.Kind {
	case domain.TargetCurrentSelected, domain.TargetGlobalURLTest, domain.TargetCustomURLTest, domain.TargetSpecificNode:
		return true
	default:
		return false
	}
}

func routeRulePreResolveSafe(rule RouteRule) bool {
	if len(rule.IPCIDR) != 0 || len(rule.RuleSet) != 0 {
		return false
	}
	for _, child := range rule.Rules {
		if !routeRulePreResolveSafe(child) {
			return false
		}
	}
	return true
}
