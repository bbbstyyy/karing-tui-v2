package compiler

import (
	"fmt"
	"reflect"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

// validateNativeRouteProvenance verifies that the separately persisted source
// map describes actual emitted native rules. A matching checksum on each file
// alone cannot prove that a source-map target or layer is truthful.
func validateNativeRouteProvenance(bound BoundRouting, targets TargetCatalog, dns CompiledDNS) error {
	if len(bound.SourceMap) == 0 {
		return fmt.Errorf("%w: missing FINAL route provenance", ErrNativeConfigClosure)
	}

	byIndex := make(map[int]RouteSourceMapEntry, len(bound.SourceMap))
	previousIndex, previousLayer := -1, -1
	finalRoutes := 0
	groupRoutes := make(map[string]bool)
	for _, entry := range bound.SourceMap {
		if entry.RuleIndex <= previousIndex || entry.RuleIndex >= len(bound.Rules) {
			return fmt.Errorf("%w: source-map indexes are duplicated, reordered or out of range", ErrNativeConfigClosure)
		}
		previousIndex = entry.RuleIndex
		layer, ok := provenanceLayerOrder(entry.Layer)
		if !ok || layer < previousLayer {
			return fmt.Errorf("%w: invalid or reordered route provenance layer", ErrNativeConfigClosure)
		}
		previousLayer = layer
		if entry.Final != (entry.Layer == domain.LayerFinal) {
			return fmt.Errorf("%w: FINAL source-map flag and layer disagree", ErrNativeConfigClosure)
		}
		if entry.Final {
			if entry.GroupID != "" || entry.DNSProfileID != "" {
				return fmt.Errorf("%w: FINAL source-map carries a group or DNS profile", ErrNativeConfigClosure)
			}
		} else if entry.GroupID == "" {
			return fmt.Errorf("%w: user route source-map has no group identity", ErrNativeConfigClosure)
		}
		if err := entry.Target.Validate(); err != nil {
			return fmt.Errorf("%w: invalid source-map target: %v", ErrNativeConfigClosure, err)
		}
		rule := bound.Rules[entry.RuleIndex]
		if rule.Action != entry.Action || rule.Outbound != entry.Outbound || rule.Server != entry.Server {
			return fmt.Errorf("%w: source-map action differs from native rule", ErrNativeConfigClosure)
		}
		if entry.Final {
			terminal := cloneRouteRules([]RouteRule{rule})[0]
			terminal.Action, terminal.Outbound, terminal.Server = "", "", ""
			if !reflect.DeepEqual(terminal, RouteRule{Inbound: []string{domain.InboundTagRule}}) {
				return fmt.Errorf("%w: FINAL native route is not unconditional for Rule inbound", ErrNativeConfigClosure)
			}
		} else if !isProvenanceUserScopedRule(rule) {
			return fmt.Errorf("%w: user route is not scoped to Rule inbound", ErrNativeConfigClosure)
		}

		switch entry.Action {
		case "reject":
			if entry.Target.Kind != domain.TargetBlock || entry.Outbound != "" ||
				entry.Server != "" || entry.DNSProfileID != "" {
				return fmt.Errorf("%w: BLOCK source-map does not match reject action", ErrNativeConfigClosure)
			}
		case "route":
			if entry.Target.Kind == domain.TargetBlock || entry.Server != "" || entry.Outbound == "" {
				return fmt.Errorf("%w: routed target has inconsistent source-map action", ErrNativeConfigClosure)
			}
			tag, err := targets.ResolveTarget(entry.Target)
			if err != nil || tag != entry.Outbound {
				return fmt.Errorf("%w: native route differs from declared target", ErrNativeConfigClosure)
			}
		case "resolve":
			if entry.Target.Kind == domain.TargetBlock || entry.Server == "" || entry.Outbound != "" {
				return fmt.Errorf("%w: DNS resolve source-map has an invalid target or action", ErrNativeConfigClosure)
			}
			if entry.DNSProfileID == "" {
				if dns.ProxyResolverTag == "" || entry.Server != dns.ProxyResolverTag {
					return fmt.Errorf("%w: source-map resolve has no Proxy DNS binding", ErrNativeConfigClosure)
				}
			} else {
				binding, exists := groupDNSBindingForSource(dns, entry)
				if !exists || binding.RuntimeTag != entry.Server {
					return fmt.Errorf("%w: source-map resolve has no Group DNS binding", ErrNativeConfigClosure)
				}
			}
		default:
			return fmt.Errorf("%w: source-map has unsupported native action", ErrNativeConfigClosure)
		}

		if entry.Action == "route" || entry.Action == "reject" {
			if entry.Final {
				finalRoutes++
			} else {
				if groupRoutes[entry.GroupID] {
					return fmt.Errorf("%w: duplicate routed source-map group", ErrNativeConfigClosure)
				}
				groupRoutes[entry.GroupID] = true
			}
		}
		byIndex[entry.RuleIndex] = entry
	}
	if finalRoutes != 1 {
		return fmt.Errorf("%w: expected exactly one FINAL source-map route", ErrNativeConfigClosure)
	}

	// Every generated user-scoped native rule must have provenance. Otherwise
	// dropping the source-map row would make a routed group disappear from T26.
	for index, rule := range bound.Rules {
		if isProvenanceUserScopedRule(rule) {
			if _, exists := byIndex[index]; !exists {
				return fmt.Errorf("%w: user-scoped native rule has no source-map entry", ErrNativeConfigClosure)
			}
		}
	}
	for _, entry := range bound.SourceMap {
		if entry.Action != "resolve" {
			continue
		}
		next, exists := byIndex[entry.RuleIndex+1]
		if !exists || next.Action != "route" ||
			next.Layer != entry.Layer || next.Final != entry.Final ||
			next.GroupID != entry.GroupID || next.DNSProfileID != entry.DNSProfileID ||
			next.Target != entry.Target {
			return fmt.Errorf("%w: source-map DNS resolve has no adjacent target route", ErrNativeConfigClosure)
		}
		if err := requireMatchingResolvePredicates(
			bound.Rules[entry.RuleIndex], bound.Rules[entry.RuleIndex+1],
		); err != nil {
			return err
		}
	}
	return nil
}

func provenanceLayerOrder(layer domain.RoutingLayer) (int, bool) {
	switch layer {
	case domain.LayerCustom:
		return 0, true
	case domain.LayerGeoSite:
		return 1, true
	case domain.LayerGeoIP:
		return 2, true
	case domain.LayerACL:
		return 3, true
	case domain.LayerFinal:
		return 4, true
	default:
		return 0, false
	}
}

func isProvenanceUserScopedRule(rule RouteRule) bool {
	return rule.Type == "logical" && rule.Mode == "and" &&
		len(rule.Rules) == 2 &&
		reflect.DeepEqual(rule.Rules[0], RouteRule{Inbound: []string{domain.InboundTagRule}})
}

func requireMatchingResolvePredicates(resolve, route RouteRule) error {
	resolve.Action, resolve.Outbound, resolve.Server = "", "", ""
	route.Action, route.Outbound, route.Server = "", "", ""
	if !reflect.DeepEqual(resolve, route) {
		return fmt.Errorf("%w: source-map DNS resolve and route have different predicates", ErrNativeConfigClosure)
	}
	return nil
}
