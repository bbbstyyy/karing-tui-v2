package compiler

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCompileRoutingPreservesOrderAndBooleanSemantics(t *testing.T) {
	customMatch := domain.All(
		domain.Any(
			domain.Atom(domain.Predicate{Kind: domain.PredicateDomain, Value: "one.example"}),
			domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "two.example"}),
		),
		domain.Not(domain.Atom(domain.Predicate{Kind: domain.PredicateNetwork, Network: domain.NetworkUDP})),
	)
	geoMatch := domain.Atom(domain.Predicate{Kind: domain.PredicateRuleSet, Value: "geosite:cn"})
	plan := domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID:    "custom-a",
			Layer: domain.LayerCustom,
			Order: 10,
			Match: &customMatch,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target:  domain.TargetRef{Kind: domain.TargetCurrentSelected},
			},
		}},
		GeoSite: []domain.RouteGroup{{
			ID:    "geosite-cn",
			Layer: domain.LayerGeoSite,
			Order: 10,
			Match: &geoMatch,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target:  domain.TargetRef{Kind: domain.TargetDirect},
			},
		}},
		GeoIP: []domain.RouteGroup{{
			ID:    "disabled",
			Layer: domain.LayerGeoIP,
			Order: 10,
			Binding: domain.RouteBinding{
				Enabled: false,
				Target:  domain.TargetRef{Kind: domain.TargetBlock},
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetBlock},
	}

	result, err := CompileRouting(plan, testResolver())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := result.RuleSetRefs, []string{"geosite:cn"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rule-set refs = %#v, want %#v", got, want)
	}
	if got, want := result.OutboundTags, []string{"out-direct", "out-current"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("outbound tags = %#v, want %#v", got, want)
	}
	if result.NeedsProcessLookup {
		t.Fatal("unexpected process lookup requirement")
	}
	if len(result.SourceMap) != 3 {
		t.Fatalf("source map entries = %d, want 3", len(result.SourceMap))
	}
	if result.SourceMap[0].RuleIndex != 6 ||
		result.SourceMap[1].RuleIndex != 7 ||
		result.SourceMap[2].RuleIndex != 9 ||
		result.SourceMap[0].Layer != domain.LayerCustom ||
		result.SourceMap[1].Layer != domain.LayerGeoSite ||
		result.SourceMap[2].Layer != domain.LayerFinal ||
		!result.SourceMap[2].Final {
		t.Fatalf("unexpected source map order: %+v", result.SourceMap)
	}

	encoded, err := result.MarshalRouteObject()
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `{"rules":[{"inbound":["in-direct"],"action":"route","outbound":"out-direct"},{"inbound":["in-selected"],"action":"route","outbound":"out-current"},{"inbound":["in-rule"],"clash_mode":"Global","ip_is_private":true,"action":"route","outbound":"out-direct"},{"inbound":["in-rule"],"clash_mode":"Global","action":"route","outbound":"out-current"},{"inbound":["in-rule"],"clash_mode":"GlobalNoPrivate","action":"route","outbound":"out-current"},{"inbound":["in-rule"],"clash_mode":"Direct","action":"route","outbound":"out-direct"},{"type":"logical","mode":"and","rules":[{"inbound":["in-rule"]},{"type":"logical","mode":"and","rules":[{"type":"logical","mode":"or","rules":[{"domain":["one.example"]},{"domain_suffix":["two.example"]}]},{"invert":true,"network":["udp"]}]}],"action":"route","outbound":"out-current"},{"type":"logical","mode":"and","rules":[{"inbound":["in-rule"]},{"rule_set":["geosite:cn"]}],"action":"route","outbound":"out-direct"},{"inbound":["in-rule"],"clash_mode":"Rule","ip_is_private":true,"action":"route","outbound":"out-direct"},{"inbound":["in-rule"],"action":"reject"}]}`
	if string(encoded) != wantJSON {
		t.Fatalf("route JSON = %s\nwant       = %s", encoded, wantJSON)
	}
}

func TestCompileRoutingCollectsDependenciesInFirstUseOrder(t *testing.T) {
	match := domain.All(
		domain.Atom(domain.Predicate{Kind: domain.PredicateRuleSet, Value: "acl:first"}),
		domain.Any(
			domain.Atom(domain.Predicate{Kind: domain.PredicateProcessName, Value: "curl"}),
			domain.Atom(domain.Predicate{Kind: domain.PredicateRuleSet, Value: "acl:second"}),
			domain.Atom(domain.Predicate{Kind: domain.PredicateRuleSet, Value: "acl:first"}),
		),
	)
	plan := domain.RoutingPlan{
		ACL: []domain.RouteGroup{{
			ID:    "acl",
			Layer: domain.LayerACL,
			Order: 1,
			Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target: domain.TargetRef{
					Kind:    domain.TargetCustomURLTest,
					GroupID: "asia-auto",
				},
			},
		}},
		Final: domain.TargetRef{
			Kind:      domain.TargetSpecificNode,
			ProfileID: "profile-a",
			NodeID:    "node-a",
		},
	}

	result, err := CompileRouting(plan, testResolver())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := result.RuleSetRefs, []string{"acl:first", "acl:second"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rule-set refs = %#v, want %#v", got, want)
	}
	if got, want := result.OutboundTags, []string{"out-direct", "out-current", "out-auto-asia-auto", "out-node-profile-a-node-a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("outbound tags = %#v, want %#v", got, want)
	}
	if !result.NeedsProcessLookup {
		t.Fatal("process predicate did not request process lookup")
	}
	if result.Rules[len(result.Rules)-1].Action != "route" ||
		result.Rules[len(result.Rules)-1].Outbound != "out-node-profile-a-node-a" ||
		!reflect.DeepEqual(result.Rules[len(result.Rules)-1].Inbound, []string{domain.InboundTagRule}) ||
		len(result.Rules[len(result.Rules)-1].Rules) != 0 {
		t.Fatalf("unexpected explicit FINAL rule: %+v", result.Rules[len(result.Rules)-1])
	}
}

func TestCompileRoutingPreservesGroupDNSBindingForLaterLowering(t *testing.T) {
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomain, Value: "dns.example"})
	plan := domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID:    "dns-bound",
			Layer: domain.LayerCustom,
			Order: 1,
			Match: &match,
			Binding: domain.RouteBinding{
				Enabled:      true,
				Target:       domain.TargetRef{Kind: domain.TargetDirect},
				DNSProfileID: "group-dns",
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}
	compiled, err := CompileRouting(plan, testResolver())
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.SourceMap) != 2 ||
		compiled.SourceMap[0].GroupID != "dns-bound" ||
		compiled.SourceMap[0].DNSProfileID != "group-dns" ||
		compiled.SourceMap[1].DNSProfileID != "" {
		t.Fatalf("group DNS binding was not preserved in source map: %+v", compiled.SourceMap)
	}
}

func TestCompileRoutingRejectsUnresolvedOrUnsafeOutbound(t *testing.T) {
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomain, Value: "example.com"})
	plan := domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID:    "route",
			Layer: domain.LayerCustom,
			Order: 1,
			Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target:  domain.TargetRef{Kind: domain.TargetCurrentSelected},
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetBlock},
	}

	_, err := CompileRouting(plan, TargetResolverFunc(func(domain.TargetRef) (string, error) {
		return "", errors.New("selection missing")
	}))
	if !errors.Is(err, ErrUnresolvedTarget) {
		t.Fatalf("unresolved target error = %v", err)
	}

	_, err = CompileRouting(plan, TargetResolverFunc(func(domain.TargetRef) (string, error) {
		return "bad tag with spaces", nil
	}))
	if !errors.Is(err, ErrInvalidOutboundTag) {
		t.Fatalf("unsafe outbound tag error = %v", err)
	}
}

func TestCompileRoutingIsDeterministic(t *testing.T) {
	match := domain.Any(
		domain.Atom(domain.Predicate{Kind: domain.PredicatePort, Port: domain.PortRange{Start: 443, End: 443}}),
		domain.Atom(domain.Predicate{Kind: domain.PredicatePort, Port: domain.PortRange{Start: 10000, End: 20000}}),
		domain.Atom(domain.Predicate{Kind: domain.PredicateIPCIDR, CIDR: "192.0.2.0/24"}),
	)
	plan := domain.RoutingPlan{
		GeoIP: []domain.RouteGroup{{
			ID:    "stable",
			Layer: domain.LayerGeoIP,
			Order: 1,
			Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target:  domain.TargetRef{Kind: domain.TargetGlobalURLTest},
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}

	first, err := CompileRouting(plan, testResolver())
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileRouting(plan, testResolver())
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := first.MarshalRouteObject()
	secondJSON, _ := second.MarshalRouteObject()
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("non-deterministic output:\n%s\n%s", firstJSON, secondJSON)
	}
	if !reflect.DeepEqual(first.SourceMap, second.SourceMap) ||
		!reflect.DeepEqual(first.RuleSetRefs, second.RuleSetRefs) ||
		!reflect.DeepEqual(first.OutboundTags, second.OutboundTags) {
		t.Fatal("non-deterministic compiler metadata")
	}
}

func TestLowerPredicateMapsEverySupportedAtomToOneField(t *testing.T) {
	cases := []struct {
		name      string
		predicate domain.Predicate
		want      string
	}{
		{name: "domain", predicate: domain.Predicate{Kind: domain.PredicateDomain, Value: "example.com"}, want: `{"domain":["example.com"]}`},
		{name: "suffix", predicate: domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "example.com"}, want: `{"domain_suffix":["example.com"]}`},
		{name: "keyword", predicate: domain.Predicate{Kind: domain.PredicateDomainKeyword, Value: "edge"}, want: `{"domain_keyword":["edge"]}`},
		{name: "regex", predicate: domain.Predicate{Kind: domain.PredicateDomainRegex, Value: "^example"}, want: `{"domain_regex":["^example"]}`},
		{name: "cidr", predicate: domain.Predicate{Kind: domain.PredicateIPCIDR, CIDR: "192.0.2.0/24"}, want: `{"ip_cidr":["192.0.2.0/24"]}`},
		{name: "ruleset", predicate: domain.Predicate{Kind: domain.PredicateRuleSet, Value: "acl:test"}, want: `{"rule_set":["acl:test"]}`},
		{name: "port", predicate: domain.Predicate{Kind: domain.PredicatePort, Port: domain.PortRange{Start: 443, End: 443}}, want: `{"port":[443]}`},
		{name: "range", predicate: domain.Predicate{Kind: domain.PredicatePort, Port: domain.PortRange{Start: 1000, End: 2000}}, want: `{"port_range":["1000:2000"]}`},
		{name: "network", predicate: domain.Predicate{Kind: domain.PredicateNetwork, Network: domain.NetworkTCP}, want: `{"network":["tcp"]}`},
		{name: "process", predicate: domain.Predicate{Kind: domain.PredicateProcessName, Value: "curl"}, want: `{"process_name":["curl"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var result CompiledRouting
			rule, err := lowerPredicate(tc.predicate, &result, make(map[string]struct{}))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(rule)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != tc.want {
				t.Fatalf("predicate JSON = %s, want %s", encoded, tc.want)
			}
		})
	}
}

func TestGeneratedOutboundTagPolicyIsBounded(t *testing.T) {
	valid := []string{"out-direct", "node:profile-a/node-a", "urltest.jp_1"}
	for _, tag := range valid {
		if err := validateGeneratedTag(tag); err != nil {
			t.Fatalf("valid tag %q: %v", tag, err)
		}
	}
	invalid := []string{"", " bad", "bad tag", "bad\ntag", strings.Repeat("a", 257)}
	for _, tag := range invalid {
		if err := validateGeneratedTag(tag); !errors.Is(err, ErrInvalidOutboundTag) {
			t.Fatalf("invalid tag %q error = %v", tag, err)
		}
	}
}

func testResolver() TargetResolver {
	return TargetResolverFunc(func(target domain.TargetRef) (string, error) {
		switch target.Kind {
		case domain.TargetDirect:
			return "out-direct", nil
		case domain.TargetCurrentSelected:
			return "out-current", nil
		case domain.TargetGlobalURLTest:
			return "out-global", nil
		case domain.TargetCustomURLTest:
			return "out-auto-" + target.GroupID, nil
		case domain.TargetSpecificNode:
			return "out-node-" + target.ProfileID + "-" + target.NodeID, nil
		case domain.TargetBlock:
			return "", errors.New("BLOCK must not reach resolver")
		default:
			return "", errors.New("unknown target")
		}
	})
}

func TestCompileRoutingCreatesFixedEntryAndModeRules(t *testing.T) {
	plan := domain.RoutingPlan{Final: domain.TargetRef{Kind: domain.TargetBlock}}
	result, err := CompileRouting(plan, testResolver())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rules) != 8 {
		t.Fatalf("rules = %d, want entry + public/internal mode + private + FINAL rules", len(result.Rules))
	}
	checks := []struct {
		index     int
		inbound   string
		clashMode string
		private   bool
		action    string
		outbound  string
	}{
		{0, domain.InboundTagDirect, "", false, "route", "out-direct"},
		{1, domain.InboundTagSelected, "", false, "route", "out-current"},
		{2, domain.InboundTagRule, "Global", true, "route", "out-direct"},
		{3, domain.InboundTagRule, "Global", false, "route", "out-current"},
		{4, domain.InboundTagRule, "GlobalNoPrivate", false, "route", "out-current"},
		{5, domain.InboundTagRule, "Direct", false, "route", "out-direct"},
		{6, domain.InboundTagRule, "Rule", true, "route", "out-direct"},
		{7, domain.InboundTagRule, "", false, "reject", ""},
	}
	for _, check := range checks {
		rule := result.Rules[check.index]
		if !reflect.DeepEqual(rule.Inbound, []string{check.inbound}) ||
			rule.ClashMode != check.clashMode ||
			rule.IPIsPrivate != check.private ||
			rule.Action != check.action ||
			rule.Outbound != check.outbound {
			t.Fatalf("rule[%d] = %+v, want inbound=%q mode=%q private=%t action=%q outbound=%q",
				check.index, rule, check.inbound, check.clashMode, check.private, check.action, check.outbound)
		}
	}
	if len(result.SourceMap) != 1 || result.SourceMap[0].RuleIndex != 7 || !result.SourceMap[0].Final {
		t.Fatalf("synthetic entry/mode/private rules leaked into route source map: %+v", result.SourceMap)
	}
}

func TestCompileRoutingPlacesPrivateDirectAfterGroupsAndBeforeFinal(t *testing.T) {
	match := domain.Atom(domain.Predicate{Kind: domain.PredicatePort, Port: domain.PortRange{Start: 443, End: 443}})
	result, err := CompileRouting(domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID:      "block-first",
			Layer:   domain.LayerCustom,
			Order:   1,
			Match:   &match,
			Binding: domain.RouteBinding{Enabled: true, Target: domain.TargetRef{Kind: domain.TargetBlock}},
		}},
		Final: domain.TargetRef{Kind: domain.TargetCurrentSelected},
	}, testResolver())
	if err != nil {
		t.Fatal(err)
	}
	var globalPrivate, globalCatch, groupRule, rulePrivate, finalRule = -1, -1, -1, -1, -1
	for i, rule := range result.Rules {
		switch {
		case rule.ClashMode == "Global" && rule.IPIsPrivate:
			globalPrivate = i
		case rule.ClashMode == "Global" && !rule.IPIsPrivate:
			globalCatch = i
		case rule.ClashMode == "Rule" && rule.IPIsPrivate:
			rulePrivate = i
		}
	}
	for _, entry := range result.SourceMap {
		if entry.GroupID == "block-first" {
			groupRule = entry.RuleIndex
		}
		if entry.Final {
			finalRule = entry.RuleIndex
		}
	}
	if globalPrivate < 0 || globalCatch < 0 || globalPrivate >= globalCatch {
		t.Fatalf("Global private order invalid: private=%d catch=%d", globalPrivate, globalCatch)
	}
	if groupRule < 0 || rulePrivate < 0 || finalRule < 0 || !(groupRule < rulePrivate && rulePrivate < finalRule) {
		t.Fatalf("Rule private order invalid: group=%d private=%d final=%d", groupRule, rulePrivate, finalRule)
	}
}
