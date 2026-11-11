package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

type MatchOp string

const (
	MatchAtom MatchOp = "atom"
	MatchAll  MatchOp = "all"
	MatchAny  MatchOp = "any"
	MatchNot  MatchOp = "not"
)

type PredicateKind string

const (
	PredicateDomain        PredicateKind = "domain"
	PredicateDomainSuffix  PredicateKind = "domain_suffix"
	PredicateDomainKeyword PredicateKind = "domain_keyword"
	PredicateDomainRegex   PredicateKind = "domain_regex"
	PredicateIPCIDR        PredicateKind = "ip_cidr"
	PredicateRuleSet       PredicateKind = "rule_set"
	PredicatePort          PredicateKind = "port"
	PredicateNetwork       PredicateKind = "network"
	PredicateProcessName   PredicateKind = "process_name"
)

type NetworkType string

const (
	NetworkTCP NetworkType = "tcp"
	NetworkUDP NetworkType = "udp"
)

const (
	MaxMatchDepth = 32
	MaxMatchNodes = 4096
)

var (
	ErrInvalidRouteMatch = errors.New("invalid route match expression")
	ErrMatchTooComplex   = errors.New("route match expression exceeds complexity limit")
)

type PortRange struct {
	Start uint16
	End   uint16
}

type Predicate struct {
	Kind    PredicateKind
	Value   string
	CIDR    string
	Port    PortRange
	Network NetworkType
}

type MatchExpr struct {
	Op        MatchOp
	Predicate *Predicate
	Children  []MatchExpr
}

func Atom(predicate Predicate) MatchExpr {
	copy := predicate
	return MatchExpr{Op: MatchAtom, Predicate: &copy}
}

func All(children ...MatchExpr) MatchExpr {
	return MatchExpr{Op: MatchAll, Children: append([]MatchExpr(nil), children...)}
}

func Any(children ...MatchExpr) MatchExpr {
	return MatchExpr{Op: MatchAny, Children: append([]MatchExpr(nil), children...)}
}

func Not(child MatchExpr) MatchExpr {
	return MatchExpr{Op: MatchNot, Children: []MatchExpr{child}}
}

func (e MatchExpr) Validate() error {
	nodes := 0
	return e.validate(1, &nodes)
}

func (e MatchExpr) Clone() MatchExpr {
	clone := MatchExpr{Op: e.Op}
	if e.Predicate != nil {
		predicate := *e.Predicate
		clone.Predicate = &predicate
	}
	if len(e.Children) != 0 {
		clone.Children = make([]MatchExpr, len(e.Children))
		for i := range e.Children {
			clone.Children[i] = e.Children[i].Clone()
		}
	}
	return clone
}

func (e MatchExpr) validate(depth int, nodes *int) error {
	if depth > MaxMatchDepth {
		return fmt.Errorf("%w: depth %d > %d", ErrMatchTooComplex, depth, MaxMatchDepth)
	}
	(*nodes)++
	if *nodes > MaxMatchNodes {
		return fmt.Errorf("%w: nodes %d > %d", ErrMatchTooComplex, *nodes, MaxMatchNodes)
	}

	switch e.Op {
	case MatchAtom:
		if e.Predicate == nil || len(e.Children) != 0 {
			return fmt.Errorf("%w: atom requires exactly one predicate and no children", ErrInvalidRouteMatch)
		}
		if err := e.Predicate.Validate(); err != nil {
			return err
		}
	case MatchAll, MatchAny:
		if e.Predicate != nil || len(e.Children) == 0 {
			return fmt.Errorf("%w: %s requires one or more children and no predicate", ErrInvalidRouteMatch, e.Op)
		}
		for i := range e.Children {
			if err := e.Children[i].validate(depth+1, nodes); err != nil {
				return fmt.Errorf("%w: %s child %d: %w", ErrInvalidRouteMatch, e.Op, i, err)
			}
		}
	case MatchNot:
		if e.Predicate != nil || len(e.Children) != 1 {
			return fmt.Errorf("%w: not requires exactly one child and no predicate", ErrInvalidRouteMatch)
		}
		if err := e.Children[0].validate(depth+1, nodes); err != nil {
			return fmt.Errorf("%w: not child: %w", ErrInvalidRouteMatch, err)
		}
	default:
		return fmt.Errorf("%w: unknown match operator %q", ErrInvalidRouteMatch, e.Op)
	}
	return nil
}

func (p Predicate) Validate() error {
	switch p.Kind {
	case PredicateDomain, PredicateDomainSuffix, PredicateDomainKeyword:
		if err := validatePlainTextPredicate(p.Value); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidRouteMatch, p.Kind, err)
		}
		if p.CIDR != "" || p.Port != (PortRange{}) || p.Network != "" {
			return fmt.Errorf("%w: %s carries unrelated fields", ErrInvalidRouteMatch, p.Kind)
		}
	case PredicateDomainRegex:
		if err := validatePlainTextPredicate(p.Value); err != nil {
			return fmt.Errorf("%w: domain_regex: %v", ErrInvalidRouteMatch, err)
		}
		if _, err := regexp.Compile(p.Value); err != nil {
			return fmt.Errorf("%w: invalid domain_regex: %v", ErrInvalidRouteMatch, err)
		}
		if p.CIDR != "" || p.Port != (PortRange{}) || p.Network != "" {
			return fmt.Errorf("%w: domain_regex carries unrelated fields", ErrInvalidRouteMatch)
		}
	case PredicateIPCIDR:
		if p.Value != "" || p.Port != (PortRange{}) || p.Network != "" {
			return fmt.Errorf("%w: ip_cidr carries unrelated fields", ErrInvalidRouteMatch)
		}
		prefix, err := netip.ParsePrefix(p.CIDR)
		if err != nil {
			return fmt.Errorf("%w: invalid ip_cidr %q: %v", ErrInvalidRouteMatch, p.CIDR, err)
		}
		if prefix != prefix.Masked() {
			return fmt.Errorf("%w: ip_cidr %q is not canonical; use %q", ErrInvalidRouteMatch, p.CIDR, prefix.Masked())
		}
	case PredicateRuleSet:
		if err := validateStableReference(p.Value); err != nil {
			return fmt.Errorf("%w: rule_set: %v", ErrInvalidRouteMatch, err)
		}
		if p.CIDR != "" || p.Port != (PortRange{}) || p.Network != "" {
			return fmt.Errorf("%w: rule_set carries unrelated fields", ErrInvalidRouteMatch)
		}
	case PredicatePort:
		if p.Value != "" || p.CIDR != "" || p.Network != "" {
			return fmt.Errorf("%w: port carries unrelated fields", ErrInvalidRouteMatch)
		}
		if p.Port.Start == 0 || p.Port.End == 0 || p.Port.Start > p.Port.End {
			return fmt.Errorf("%w: invalid port range %d-%d", ErrInvalidRouteMatch, p.Port.Start, p.Port.End)
		}
	case PredicateNetwork:
		if p.Value != "" || p.CIDR != "" || p.Port != (PortRange{}) {
			return fmt.Errorf("%w: network carries unrelated fields", ErrInvalidRouteMatch)
		}
		if p.Network != NetworkTCP && p.Network != NetworkUDP {
			return fmt.Errorf("%w: unsupported network %q", ErrInvalidRouteMatch, p.Network)
		}
	case PredicateProcessName:
		if err := validatePlainTextPredicate(p.Value); err != nil {
			return fmt.Errorf("%w: process_name: %v", ErrInvalidRouteMatch, err)
		}
		if p.CIDR != "" || p.Port != (PortRange{}) || p.Network != "" {
			return fmt.Errorf("%w: process_name carries unrelated fields", ErrInvalidRouteMatch)
		}
	default:
		return fmt.Errorf("%w: unknown predicate kind %q", ErrInvalidRouteMatch, p.Kind)
	}
	return nil
}

func validatePlainTextPredicate(value string) error {
	if value == "" {
		return errors.New("value must not be empty")
	}
	if strings.TrimSpace(value) != value {
		return errors.New("value must not have leading or trailing whitespace")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("value contains a control character")
		}
	}
	return nil
}

func validateStableReference(value string) error {
	if err := validatePlainTextPredicate(value); err != nil {
		return err
	}
	if len(value) > 256 {
		return errors.New("reference exceeds 256 bytes")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '-', '_', '.', ':', '/', '@', '!':
			continue
		default:
			return fmt.Errorf("reference contains unsupported character %q", r)
		}
	}
	return nil
}
