package domain

import (
	"errors"
	"reflect"
	"testing"
)

func TestRoutingPlanPreservesFiveLayerOrder(t *testing.T) {
	plan := RoutingPlan{
		Custom: []RouteGroup{
			{
				ID:    "custom-a",
				Layer: LayerCustom,
				Order: 10,
				Match: matchDomain("custom.example"),
				Binding: RouteBinding{
					Enabled: true,
					Target:  TargetRef{Kind: TargetDirect},
				},
			},
			{
				ID:    "custom-disabled",
				Layer: LayerCustom,
				Order: 20,
				Binding: RouteBinding{
					Enabled: false,
					Target:  TargetRef{Kind: TargetBlock},
				},
			},
		},
		GeoSite: []RouteGroup{{
			ID:    "geosite-a",
			Layer: LayerGeoSite,
			Order: 10,
			Match: matchRuleSet("geosite:example"),
			Binding: RouteBinding{
				Enabled: true,
				Target:  TargetRef{Kind: TargetCurrentSelected},
			},
		}},
		GeoIP: []RouteGroup{{
			ID:    "geoip-a",
			Layer: LayerGeoIP,
			Order: 10,
			Match: matchRuleSet("geoip:jp"),
			Binding: RouteBinding{
				Enabled: true,
				Target: TargetRef{
					Kind:    TargetCustomURLTest,
					GroupID: "jp-auto",
				},
			},
		}},
		ACL: []RouteGroup{{
			ID:    "acl-a",
			Layer: LayerACL,
			Order: 10,
			Match: matchRuleSet("acl:example"),
			Binding: RouteBinding{
				Enabled:      true,
				Target:       TargetRef{Kind: TargetGlobalURLTest},
				DNSProfileID: "proxy-dns",
			},
		}},
		Final: TargetRef{
			Kind:      TargetSpecificNode,
			ProfileID: "profile-a",
			NodeID:    "node-1",
		},
	}

	steps, err := plan.OrderedActiveSteps()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(steps))
	for _, step := range steps {
		got = append(got, string(step.Layer)+":"+step.GroupID+":"+string(step.Target.Kind))
	}
	want := []string{
		"custom:custom-a:direct",
		"geosite:geosite-a:current_selected",
		"geoip:geoip-a:custom_urltest",
		"acl:acl-a:global_urltest",
		"final::specific_node",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered steps = %#v, want %#v", got, want)
	}
	if !steps[len(steps)-1].Final {
		t.Fatal("last route step is not FINAL")
	}
}

func TestRoutingPlanLayerSwitchesSuppressWholeSources(t *testing.T) {
	customMatch := Atom(Predicate{Kind: PredicateDomain, Value: "custom.example"})
	geoSiteMatch := Atom(Predicate{Kind: PredicateRuleSet, Value: "geosite:example"})
	geoIPMatch := Atom(Predicate{Kind: PredicateRuleSet, Value: "geoip:example"})
	aclMatch := Atom(Predicate{Kind: PredicateRuleSet, Value: "acl:example"})
	plan := RoutingPlan{
		Layers: RoutingLayerSwitches{
			GeoSiteDisabled: true,
			ACLDisabled:     true,
		},
		Custom: []RouteGroup{{
			ID:    "custom",
			Layer: LayerCustom,
			Order: 1,
			Match: &customMatch,
			Binding: RouteBinding{Enabled: true, Target: TargetRef{Kind: TargetDirect}},
		}},
		GeoSite: []RouteGroup{{
			ID:    "geosite",
			Layer: LayerGeoSite,
			Order: 1,
			Match: &geoSiteMatch,
			Binding: RouteBinding{Enabled: true, Target: TargetRef{Kind: TargetDirect}},
		}},
		GeoIP: []RouteGroup{{
			ID:    "geoip",
			Layer: LayerGeoIP,
			Order: 1,
			Match: &geoIPMatch,
			Binding: RouteBinding{Enabled: true, Target: TargetRef{Kind: TargetDirect}},
		}},
		ACL: []RouteGroup{{
			ID:    "acl",
			Layer: LayerACL,
			Order: 1,
			Match: &aclMatch,
			Binding: RouteBinding{Enabled: true, Target: TargetRef{Kind: TargetDirect}},
		}},
		Final: TargetRef{Kind: TargetBlock},
	}

	steps, err := plan.OrderedActiveSteps()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(steps))
	for _, step := range steps {
		got = append(got, string(step.Layer)+":"+step.GroupID)
	}
	want := []string{"custom:custom", "geoip:geoip", "final:"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("active steps = %#v, want %#v", got, want)
	}
	if !plan.GeoSite[0].Binding.Enabled || !plan.ACL[0].Binding.Enabled {
		t.Fatal("layer switch mutated persisted group enable state")
	}
	if !plan.Layers.Enabled(LayerCustom) ||
		plan.Layers.Enabled(LayerGeoSite) ||
		!plan.Layers.Enabled(LayerGeoIP) ||
		plan.Layers.Enabled(LayerACL) ||
		!plan.Layers.Enabled(LayerFinal) {
		t.Fatalf("unexpected layer switch evaluation: %+v", plan.Layers)
	}
}

func TestRoutingPlanRejectsNonNormalizedLayerOrder(t *testing.T) {
	plan := RoutingPlan{
		Custom: []RouteGroup{
			{ID: "a", Layer: LayerCustom, Order: 10},
			{ID: "b", Layer: LayerCustom, Order: 10},
		},
		Final: TargetRef{Kind: TargetDirect},
	}
	if err := plan.Validate(); !errors.Is(err, ErrInvalidRouteOrder) {
		t.Fatalf("duplicate order error = %v", err)
	}

	plan.Custom[1].Order = 5
	if err := plan.Validate(); !errors.Is(err, ErrInvalidRouteOrder) {
		t.Fatalf("descending order error = %v", err)
	}
}

func TestRoutingPlanRejectsDuplicateGroupAcrossLayers(t *testing.T) {
	plan := RoutingPlan{
		Custom: []RouteGroup{{
			ID:    "same",
			Layer: LayerCustom,
			Order: 1,
		}},
		GeoIP: []RouteGroup{{
			ID:    "same",
			Layer: LayerGeoIP,
			Order: 1,
		}},
		Final: TargetRef{Kind: TargetDirect},
	}
	if err := plan.Validate(); !errors.Is(err, ErrDuplicateRouteGroup) {
		t.Fatalf("duplicate group error = %v", err)
	}
}

func TestRoutingPlanRejectsLayerMismatch(t *testing.T) {
	plan := RoutingPlan{
		GeoSite: []RouteGroup{{
			ID:    "wrong-layer",
			Layer: LayerACL,
			Order: 1,
		}},
		Final: TargetRef{Kind: TargetDirect},
	}
	if err := plan.Validate(); !errors.Is(err, ErrInvalidRoutingLayer) {
		t.Fatalf("layer mismatch error = %v", err)
	}
}

func TestTargetRefRequiresTypedIdentity(t *testing.T) {
	valid := []TargetRef{
		{Kind: TargetDirect},
		{Kind: TargetBlock},
		{Kind: TargetCurrentSelected},
		{Kind: TargetGlobalURLTest},
		{Kind: TargetCustomURLTest, GroupID: "us-auto"},
		{Kind: TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"},
	}
	for _, target := range valid {
		if err := target.Validate(); err != nil {
			t.Fatalf("valid target %+v: %v", target, err)
		}
	}

	invalid := []TargetRef{
		{},
		{Kind: TargetKind("none")},
		{Kind: TargetDirect, GroupID: "unexpected"},
		{Kind: TargetCustomURLTest},
		{Kind: TargetCustomURLTest, GroupID: "group", NodeID: "unexpected"},
		{Kind: TargetSpecificNode, NodeID: "node-only"},
		{Kind: TargetSpecificNode, ProfileID: "profile-only"},
	}
	for _, target := range invalid {
		if err := target.Validate(); !errors.Is(err, ErrInvalidRouteTarget) {
			t.Fatalf("invalid target %+v error = %v", target, err)
		}
	}
}

func TestDisabledRouteGroupIsNotAnImplicitTarget(t *testing.T) {
	plan := RoutingPlan{
		Custom: []RouteGroup{{
			ID:      "disabled",
			Layer:   LayerCustom,
			Order:   1,
			Binding: RouteBinding{Enabled: false},
		}},
		Final: TargetRef{Kind: TargetDirect},
	}
	steps, err := plan.OrderedActiveSteps()
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || !steps[0].Final {
		t.Fatalf("disabled group leaked into active routing: %+v", steps)
	}
}

func TestBlockTargetCannotCarryGroupDNS(t *testing.T) {
	plan := RoutingPlan{
		ACL: []RouteGroup{{
			ID:    "block",
			Layer: LayerACL,
			Order: 1,
			Match: matchDomain("blocked.example"),
			Binding: RouteBinding{
				Enabled:      true,
				Target:       TargetRef{Kind: TargetBlock},
				DNSProfileID: "dns-should-not-apply",
			},
		}},
		Final: TargetRef{Kind: TargetDirect},
	}
	if err := plan.Validate(); !errors.Is(err, ErrInvalidRouteTarget) {
		t.Fatalf("BLOCK DNS error = %v", err)
	}
}

func TestFinalMustBeAnExplicitTarget(t *testing.T) {
	plan := RoutingPlan{}
	if err := plan.Validate(); !errors.Is(err, ErrInvalidFinalRoute) {
		t.Fatalf("empty final error = %v", err)
	}
}

func TestEnabledRouteGroupRequiresExplicitMatcher(t *testing.T) {
	plan := RoutingPlan{
		Custom: []RouteGroup{{
			ID:    "missing-match",
			Layer: LayerCustom,
			Order: 1,
			Binding: RouteBinding{
				Enabled: true,
				Target:  TargetRef{Kind: TargetDirect},
			},
		}},
		Final: TargetRef{Kind: TargetDirect},
	}
	if err := plan.Validate(); !errors.Is(err, ErrInvalidRouteMatch) {
		t.Fatalf("missing matcher error = %v", err)
	}
}

func TestOrderedActiveStepsCloneMatcher(t *testing.T) {
	match := Any(
		Atom(Predicate{Kind: PredicateDomain, Value: "one.example"}),
		Atom(Predicate{Kind: PredicateDomain, Value: "two.example"}),
	)
	plan := RoutingPlan{
		Custom: []RouteGroup{{
			ID:    "custom",
			Layer: LayerCustom,
			Order: 1,
			Match: &match,
			Binding: RouteBinding{
				Enabled: true,
				Target:  TargetRef{Kind: TargetDirect},
			},
		}},
		Final: TargetRef{Kind: TargetBlock},
	}
	steps, err := plan.OrderedActiveSteps()
	if err != nil {
		t.Fatal(err)
	}
	steps[0].Match.Children[0].Predicate.Value = "mutated.example"
	if got := plan.Custom[0].Match.Children[0].Predicate.Value; got != "one.example" {
		t.Fatalf("route step matcher aliases plan matcher: %q", got)
	}
}

func matchDomain(value string) *MatchExpr {
	match := Atom(Predicate{Kind: PredicateDomain, Value: value})
	return &match
}

func matchRuleSet(value string) *MatchExpr {
	match := Atom(Predicate{Kind: PredicateRuleSet, Value: value})
	return &match
}
