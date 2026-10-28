package compiler

import (
	"fmt"
	"reflect"
)

// validateProxyDNSRouteBindings checks the *actual* native route sequence.
// A stray resolve rule elsewhere is not proof that Selected/Global or a
// proxy-bound user group will query its declared Proxy DNS before routing.
func validateProxyDNSRouteBindings(bound BoundRouting, dns CompiledDNS, targets TargetCatalog) error {
	tag := dns.ProxyResolverTag
	if tag == "" {
		return nil
	}

	selectedCount := 0
	globalModes := make(map[string]bool, 2)
	for index, rule := range bound.Rules {
		if isSelectedSyntheticRoute(rule) {
			selectedCount++
			if rule.Outbound != targets.CurrentSelectedTag {
				return fmt.Errorf("%w: Selected proxy route changed its application target", ErrNativeConfigClosure)
			}
			if err := requireProxyResolveRoutePair(bound.Rules, index, tag); err != nil {
				return err
			}
		}
		if isGlobalModeSyntheticRoute(rule) {
			if globalModes[rule.ClashMode] {
				return fmt.Errorf("%w: duplicate Global mode proxy route", ErrNativeConfigClosure)
			}
			globalModes[rule.ClashMode] = true
			if err := requireProxyResolveRoutePair(bound.Rules, index, tag); err != nil {
				return err
			}
		}
	}
	if selectedCount != 1 || !globalModes["Global"] || !globalModes["GlobalNoPrivate"] {
		return fmt.Errorf("%w: Proxy DNS requires Selected and both Global mode route pairs", ErrNativeConfigClosure)
	}

	byIndex := make(map[int]RouteSourceMapEntry, len(bound.SourceMap))
	for _, entry := range bound.SourceMap {
		if entry.RuleIndex < 0 || entry.RuleIndex >= len(bound.Rules) {
			return fmt.Errorf("%w: Proxy DNS source-map index is out of range", ErrNativeConfigClosure)
		}
		if _, exists := byIndex[entry.RuleIndex]; exists {
			return fmt.Errorf("%w: duplicate Proxy DNS source-map index", ErrNativeConfigClosure)
		}
		byIndex[entry.RuleIndex] = entry
	}
	for _, entry := range bound.SourceMap {
		if entry.Action == "route" && entry.DNSProfileID == "" && isProxyTarget(entry.Target) {
			expectedOutbound, err := targets.ResolveTarget(entry.Target)
			if err != nil || expectedOutbound == "" || entry.Outbound != expectedOutbound {
				return fmt.Errorf("%w: proxy-bound source-map target/outbound mismatch", ErrNativeConfigClosure)
			}
			if entry.RuleIndex < 1 {
				return fmt.Errorf("%w: proxy-bound user route has no preceding resolve", ErrNativeConfigClosure)
			}
			before, exists := byIndex[entry.RuleIndex-1]
			if !exists || before.Action != "resolve" ||
				before.Server != tag || before.Outbound != "" ||
				before.DNSProfileID != "" ||
				before.GroupID != entry.GroupID || before.Layer != entry.Layer ||
				before.Final != entry.Final || !reflect.DeepEqual(before.Target, entry.Target) ||
				entry.Server != "" || entry.Outbound != bound.Rules[entry.RuleIndex].Outbound {
				return fmt.Errorf("%w: proxy-bound user route has no valid resolve source-map pair", ErrNativeConfigClosure)
			}
			if err := requireProxyResolveRoutePair(bound.Rules, entry.RuleIndex, tag); err != nil {
				return err
			}
		}
		if entry.Action == "resolve" && entry.Server == tag {
			next, exists := byIndex[entry.RuleIndex+1]
			if !exists || next.Action != "route" ||
				next.DNSProfileID != "" || entry.DNSProfileID != "" ||
				next.GroupID != entry.GroupID || next.Layer != entry.Layer ||
				next.Final != entry.Final || !reflect.DeepEqual(next.Target, entry.Target) ||
				!isProxyTarget(next.Target) {
				return fmt.Errorf("%w: orphan Proxy DNS source-map resolve", ErrNativeConfigClosure)
			}
			if err := requireProxyResolveRoutePair(bound.Rules, entry.RuleIndex+1, tag); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireProxyResolveRoutePair(rules []RouteRule, routeIndex int, tag string) error {
	if routeIndex <= 0 || routeIndex >= len(rules) {
		return fmt.Errorf("%w: Proxy DNS route pair is missing", ErrNativeConfigClosure)
	}
	resolve := rules[routeIndex-1]
	route := rules[routeIndex]
	if resolve.Action != "resolve" || resolve.Server != tag || resolve.Outbound != "" ||
		route.Action != "route" || route.Server != "" || route.Outbound == "" {
		return fmt.Errorf("%w: Proxy DNS resolve/route action mismatch", ErrNativeConfigClosure)
	}
	resolve.Action, resolve.Server, resolve.Outbound = "", "", ""
	route.Action, route.Server, route.Outbound = "", "", ""
	if !reflect.DeepEqual(resolve, route) {
		return fmt.Errorf("%w: Proxy DNS resolve and route match different predicates", ErrNativeConfigClosure)
	}
	return nil
}
