package compiler

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

var (
	ErrUnresolvedTarget      = errors.New("unresolved route target")
	ErrInvalidOutboundTag    = errors.New("invalid generated outbound tag")
	ErrDNSBindingUnsupported = errors.New("group DNS binding is not compiled yet")
)

type TargetResolver interface {
	ResolveTarget(domain.TargetRef) (string, error)
}

type TargetResolverFunc func(domain.TargetRef) (string, error)

func (f TargetResolverFunc) ResolveTarget(target domain.TargetRef) (string, error) {
	return f(target)
}

type RouteRule struct {
	Type          string      `json:"type,omitempty"`
	Mode          string      `json:"mode,omitempty"`
	Rules         []RouteRule `json:"rules,omitempty"`
	Invert        bool        `json:"invert,omitempty"`
	Inbound       []string    `json:"inbound,omitempty"`
	Domain        []string    `json:"domain,omitempty"`
	DomainSuffix  []string    `json:"domain_suffix,omitempty"`
	DomainKeyword []string    `json:"domain_keyword,omitempty"`
	DomainRegex   []string    `json:"domain_regex,omitempty"`
	IPCIDR        []string    `json:"ip_cidr,omitempty"`
	RuleSet       []string    `json:"rule_set,omitempty"`
	Port          []uint16    `json:"port,omitempty"`
	PortRange     []string    `json:"port_range,omitempty"`
	Network       []string    `json:"network,omitempty"`
	ProcessName   []string    `json:"process_name,omitempty"`
	Action        string      `json:"action,omitempty"`
	Outbound      string      `json:"outbound,omitempty"`
}

type RouteSourceMapEntry struct {
	RuleIndex int
	Layer     domain.RoutingLayer
	GroupID   string
	Final     bool
	Target    domain.TargetRef
	Action    string
	Outbound  string
}

type CompiledRouting struct {
	Rules              []RouteRule
	RuleSetRefs        []string
	OutboundTags       []string
	NeedsProcessLookup bool
	SourceMap          []RouteSourceMapEntry
}

func (c CompiledRouting) MarshalRouteObject() ([]byte, error) {
	return json.Marshal(struct {
		Rules []RouteRule `json:"rules"`
	}{
		Rules: c.Rules,
	})
}

func CompileRouting(plan domain.RoutingPlan, resolver TargetResolver) (CompiledRouting, error) {
	if resolver == nil {
		return CompiledRouting{}, errors.New("route target resolver is nil")
	}
	steps, err := plan.OrderedActiveSteps()
	if err != nil {
		return CompiledRouting{}, err
	}

	var result CompiledRouting
	ruleSetSeen := make(map[string]struct{})
	outboundSeen := make(map[string]struct{})

	for _, synthetic := range []struct {
		role   domain.InboundRole
		target domain.TargetRef
	}{
		{role: domain.InboundDirect, target: domain.TargetRef{Kind: domain.TargetDirect}},
		{role: domain.InboundSelected, target: domain.TargetRef{Kind: domain.TargetCurrentSelected}},
	} {
		inbound, err := synthetic.role.RuntimeTag()
		if err != nil {
			return CompiledRouting{}, err
		}
		action, outbound, err := lowerTarget(synthetic.target, resolver)
		if err != nil {
			return CompiledRouting{}, fmt.Errorf("resolve %s inbound target: %w", synthetic.role, err)
		}
		result.Rules = append(result.Rules, RouteRule{
			Inbound:  []string{inbound},
			Action:   action,
			Outbound: outbound,
		})
		recordOutbound(&result, outboundSeen, outbound)
	}

	ruleInbound, err := domain.InboundRule.RuntimeTag()
	if err != nil {
		return CompiledRouting{}, err
	}

	for _, step := range steps {
		if step.DNSProfileID != "" {
			return CompiledRouting{}, fmt.Errorf("%w: group %q references DNS profile %q", ErrDNSBindingUnsupported, step.GroupID, step.DNSProfileID)
		}

		var rule RouteRule
		if !step.Final {
			if step.Match == nil {
				return CompiledRouting{}, fmt.Errorf("route group %q has no matcher after validation", step.GroupID)
			}
			rule, err = lowerMatch(*step.Match, &result, ruleSetSeen)
			if err != nil {
				return CompiledRouting{}, fmt.Errorf("lower route group %q: %w", step.GroupID, err)
			}
			rule = scopeToInbound(rule, ruleInbound)
		} else {
			rule.Inbound = []string{ruleInbound}
		}

		action, outbound, err := lowerTarget(step.Target, resolver)
		if err != nil {
			return CompiledRouting{}, fmt.Errorf("resolve route target for group %q: %w", step.GroupID, err)
		}
		rule.Action = action
		rule.Outbound = outbound
		recordOutbound(&result, outboundSeen, outbound)

		result.Rules = append(result.Rules, rule)
		result.SourceMap = append(result.SourceMap, RouteSourceMapEntry{
			RuleIndex: len(result.Rules) - 1,
			Layer:     step.Layer,
			GroupID:   step.GroupID,
			Final:     step.Final,
			Target:    step.Target,
			Action:    action,
			Outbound:  outbound,
		})
	}

	return result, nil
}

func scopeToInbound(rule RouteRule, inbound string) RouteRule {
	return RouteRule{
		Type: "logical",
		Mode: "and",
		Rules: []RouteRule{
			{Inbound: []string{inbound}},
			rule,
		},
	}
}

func recordOutbound(result *CompiledRouting, seen map[string]struct{}, outbound string) {
	if outbound == "" {
		return
	}
	if _, exists := seen[outbound]; exists {
		return
	}
	seen[outbound] = struct{}{}
	result.OutboundTags = append(result.OutboundTags, outbound)
}

func lowerMatch(expr domain.MatchExpr, result *CompiledRouting, ruleSetSeen map[string]struct{}) (RouteRule, error) {
	switch expr.Op {
	case domain.MatchAtom:
		if expr.Predicate == nil {
			return RouteRule{}, errors.New("atom has no predicate")
		}
		return lowerPredicate(*expr.Predicate, result, ruleSetSeen)
	case domain.MatchAll, domain.MatchAny:
		rules := make([]RouteRule, len(expr.Children))
		for i := range expr.Children {
			rule, err := lowerMatch(expr.Children[i], result, ruleSetSeen)
			if err != nil {
				return RouteRule{}, fmt.Errorf("%s child %d: %w", expr.Op, i, err)
			}
			rules[i] = rule
		}
		mode := "and"
		if expr.Op == domain.MatchAny {
			mode = "or"
		}
		return RouteRule{
			Type:  "logical",
			Mode:  mode,
			Rules: rules,
		}, nil
	case domain.MatchNot:
		if len(expr.Children) != 1 {
			return RouteRule{}, errors.New("not expression does not have exactly one child")
		}
		rule, err := lowerMatch(expr.Children[0], result, ruleSetSeen)
		if err != nil {
			return RouteRule{}, fmt.Errorf("not child: %w", err)
		}
		rule.Invert = !rule.Invert
		return rule, nil
	default:
		return RouteRule{}, fmt.Errorf("unsupported match operator %q", expr.Op)
	}
}

func lowerPredicate(predicate domain.Predicate, result *CompiledRouting, ruleSetSeen map[string]struct{}) (RouteRule, error) {
	switch predicate.Kind {
	case domain.PredicateDomain:
		return RouteRule{Domain: []string{predicate.Value}}, nil
	case domain.PredicateDomainSuffix:
		return RouteRule{DomainSuffix: []string{predicate.Value}}, nil
	case domain.PredicateDomainKeyword:
		return RouteRule{DomainKeyword: []string{predicate.Value}}, nil
	case domain.PredicateDomainRegex:
		return RouteRule{DomainRegex: []string{predicate.Value}}, nil
	case domain.PredicateIPCIDR:
		return RouteRule{IPCIDR: []string{predicate.CIDR}}, nil
	case domain.PredicateRuleSet:
		if _, exists := ruleSetSeen[predicate.Value]; !exists {
			ruleSetSeen[predicate.Value] = struct{}{}
			result.RuleSetRefs = append(result.RuleSetRefs, predicate.Value)
		}
		return RouteRule{RuleSet: []string{predicate.Value}}, nil
	case domain.PredicatePort:
		if predicate.Port.Start == predicate.Port.End {
			return RouteRule{Port: []uint16{predicate.Port.Start}}, nil
		}
		return RouteRule{PortRange: []string{strconv.Itoa(int(predicate.Port.Start)) + ":" + strconv.Itoa(int(predicate.Port.End))}}, nil
	case domain.PredicateNetwork:
		return RouteRule{Network: []string{string(predicate.Network)}}, nil
	case domain.PredicateProcessName:
		result.NeedsProcessLookup = true
		return RouteRule{ProcessName: []string{predicate.Value}}, nil
	default:
		return RouteRule{}, fmt.Errorf("unsupported predicate %q", predicate.Kind)
	}
}

func lowerTarget(target domain.TargetRef, resolver TargetResolver) (action string, outbound string, err error) {
	if target.Kind == domain.TargetBlock {
		return "reject", "", nil
	}
	outbound, err = resolver.ResolveTarget(target)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrUnresolvedTarget, err)
	}
	if err := validateGeneratedTag(outbound); err != nil {
		return "", "", err
	}
	return "route", outbound, nil
}

func validateGeneratedTag(tag string) error {
	if tag == "" || len(tag) > 256 || strings.TrimSpace(tag) != tag {
		return ErrInvalidOutboundTag
	}
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '-', '_', '.', ':', '/':
			continue
		default:
			return fmt.Errorf("%w: unsupported character %q", ErrInvalidOutboundTag, r)
		}
	}
	return nil
}
