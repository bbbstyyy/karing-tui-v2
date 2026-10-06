package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestMatchExprRequiresExplicitBooleanStructure(t *testing.T) {
	match := All(
		Any(
			Atom(Predicate{Kind: PredicateDomainSuffix, Value: "example.com"}),
			Atom(Predicate{Kind: PredicateDomainKeyword, Value: "cdn"}),
		),
		Not(Atom(Predicate{Kind: PredicateNetwork, Network: NetworkUDP})),
	)
	if err := match.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMatchExprRejectsImplicitOrMalformedLogic(t *testing.T) {
	cases := []MatchExpr{
		{},
		{Op: MatchAtom},
		{Op: MatchAll},
		{Op: MatchAny, Predicate: &Predicate{Kind: PredicateDomain, Value: "example.com"}, Children: []MatchExpr{Atom(Predicate{Kind: PredicateDomain, Value: "example.org"})}},
		{Op: MatchNot},
		{Op: MatchNot, Children: []MatchExpr{
			Atom(Predicate{Kind: PredicateDomain, Value: "a.example"}),
			Atom(Predicate{Kind: PredicateDomain, Value: "b.example"}),
		}},
	}
	for i, match := range cases {
		if err := match.Validate(); !errors.Is(err, ErrInvalidRouteMatch) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

func TestPredicateValidation(t *testing.T) {
	valid := []Predicate{
		{Kind: PredicateDomain, Value: "www.example.com"},
		{Kind: PredicateDomainSuffix, Value: "example.com"},
		{Kind: PredicateDomainKeyword, Value: "edge"},
		{Kind: PredicateDomainRegex, Value: `^([a-z0-9-]+\.)?example\.com$`},
		{Kind: PredicateIPCIDR, CIDR: "192.0.2.0/24"},
		{Kind: PredicateIPCIDR, CIDR: "2001:db8::/32"},
		{Kind: PredicateRuleSet, Value: "acl:ChinaDomain"},
		{Kind: PredicateRuleSet, Value: "geosite:apple@ads"},
		{Kind: PredicatePort, Port: PortRange{Start: 443, End: 443}},
		{Kind: PredicatePort, Port: PortRange{Start: 10000, End: 20000}},
		{Kind: PredicateNetwork, Network: NetworkTCP},
		{Kind: PredicateNetwork, Network: NetworkUDP},
		{Kind: PredicateProcessName, Value: "curl"},
	}
	for _, predicate := range valid {
		if err := predicate.Validate(); err != nil {
			t.Fatalf("valid predicate %+v: %v", predicate, err)
		}
	}

	invalid := []Predicate{
		{},
		{Kind: PredicateDomain, Value: ""},
		{Kind: PredicateDomain, Value: " example.com"},
		{Kind: PredicateDomainRegex, Value: "("},
		{Kind: PredicateIPCIDR, CIDR: "192.0.2.1/24"},
		{Kind: PredicateIPCIDR, CIDR: "not-a-prefix"},
		{Kind: PredicateRuleSet, Value: "acl:China Domain"},
		{Kind: PredicateRuleSet, Value: "acl:China?Domain"},
		{Kind: PredicatePort, Port: PortRange{Start: 0, End: 443}},
		{Kind: PredicatePort, Port: PortRange{Start: 443, End: 80}},
		{Kind: PredicateNetwork, Network: NetworkType("icmp")},
		{Kind: PredicateProcessName, Value: "curl\nsh"},
		{Kind: PredicateDomain, Value: "example.com", CIDR: "192.0.2.0/24"},
	}
	for _, predicate := range invalid {
		if err := predicate.Validate(); !errors.Is(err, ErrInvalidRouteMatch) {
			t.Fatalf("invalid predicate %+v error = %v", predicate, err)
		}
	}
}

func TestMatchExprComplexityLimits(t *testing.T) {
	deep := Atom(Predicate{Kind: PredicateDomain, Value: "example.com"})
	for i := 0; i < MaxMatchDepth; i++ {
		deep = Not(deep)
	}
	if err := deep.Validate(); !errors.Is(err, ErrMatchTooComplex) {
		t.Fatalf("deep expression error = %v", err)
	}

	children := make([]MatchExpr, MaxMatchNodes)
	for i := range children {
		children[i] = Atom(Predicate{Kind: PredicateDomain, Value: "n.example"})
	}
	wide := Any(children...)
	if err := wide.Validate(); !errors.Is(err, ErrMatchTooComplex) {
		t.Fatalf("wide expression error = %v", err)
	}
}

func TestMatchCloneDoesNotAliasOriginal(t *testing.T) {
	original := Any(
		Atom(Predicate{Kind: PredicateDomain, Value: "one.example"}),
		Not(Atom(Predicate{Kind: PredicateDomainSuffix, Value: "two.example"})),
	)
	clone := original.Clone()
	clone.Children[0].Predicate.Value = "changed.example"
	clone.Children[1].Children[0].Predicate.Value = "changed-two.example"

	if original.Children[0].Predicate.Value != "one.example" {
		t.Fatal("clone mutated first original predicate")
	}
	if original.Children[1].Children[0].Predicate.Value != "two.example" {
		t.Fatal("clone mutated nested original predicate")
	}
}

func TestRuleSetReferenceRejectsUnboundedOrControlInput(t *testing.T) {
	if err := (Predicate{Kind: PredicateRuleSet, Value: strings.Repeat("a", 257)}).Validate(); !errors.Is(err, ErrInvalidRouteMatch) {
		t.Fatalf("long rule-set reference error = %v", err)
	}
	if err := (Predicate{Kind: PredicateRuleSet, Value: "acl:	China"}).Validate(); !errors.Is(err, ErrInvalidRouteMatch) {
		t.Fatalf("control rule-set reference error = %v", err)
	}
}
