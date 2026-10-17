package domain

import (
	"errors"
	"reflect"
	"testing"
)

func TestDefaultCNRegionAppendPlanPreservesIndependentUpstreamDefaults(t *testing.T) {
	plan := DefaultCNRegionAppendPlan()
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	if plan.RegionCode != "cn" {
		t.Fatalf("region code = %q, want cn", plan.RegionCode)
	}
	if !plan.GeoSiteEnabled || !plan.GeoIPEnabled {
		t.Fatalf("CN region append defaults = geosite:%v geoip:%v, want both true", plan.GeoSiteEnabled, plan.GeoIPEnabled)
	}
	if plan.Target.Kind != TargetDirect {
		t.Fatalf("region append target = %q, want DIRECT", plan.Target.Kind)
	}
	refs, err := plan.RuleSetRefs()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := refs, []string{"geosite:cn", "geoip:cn"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("region refs = %#v, want %#v", got, want)
	}
}

func TestRegionAppendSwitchesAreIndependent(t *testing.T) {
	cases := []struct {
		name    string
		geosite bool
		geoip   bool
		want    []string
	}{
		{name: "both", geosite: true, geoip: true, want: []string{"geosite:cn", "geoip:cn"}},
		{name: "geosite-only", geosite: true, want: []string{"geosite:cn"}},
		{name: "geoip-only", geoip: true, want: []string{"geoip:cn"}},
		{name: "neither", want: []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := RegionAppendPlan{
				RegionCode:     "cn",
				GeoSiteEnabled: tc.geosite,
				GeoIPEnabled:   tc.geoip,
				Target:         TargetRef{Kind: TargetDirect},
			}
			got, err := plan.RuleSetRefs()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("refs = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestRegionAppendRejectsAmbiguousOrNonDirectPolicy(t *testing.T) {
	cases := []RegionAppendPlan{
		{RegionCode: "", Target: TargetRef{Kind: TargetDirect}},
		{RegionCode: "CN", Target: TargetRef{Kind: TargetDirect}},
		{RegionCode: "chn", Target: TargetRef{Kind: TargetDirect}},
		{RegionCode: "c1", Target: TargetRef{Kind: TargetDirect}},
		{RegionCode: "cn", Target: TargetRef{Kind: TargetCurrentSelected}},
		{RegionCode: "cn", Target: TargetRef{Kind: TargetBlock}},
	}
	for i, plan := range cases {
		if err := plan.Validate(); !errors.Is(err, ErrInvalidRegionAppend) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

func TestApplyRegionAppendPlacesSyntheticEntriesAfterExplicitLayerEntries(t *testing.T) {
	geoSiteMatch := Atom(Predicate{Kind: PredicateRuleSet, Value: "geosite:cn"})
	geoIPMatch := Atom(Predicate{Kind: PredicateRuleSet, Value: "geoip:cn"})
	routing := RoutingPlan{
		GeoSite: []RouteGroup{{
			ID:    "user-geosite-cn",
			Layer: LayerGeoSite,
			Order: 10,
			Match: &geoSiteMatch,
			Binding: RouteBinding{
				Enabled: true,
				Target:  TargetRef{Kind: TargetCurrentSelected},
			},
		}},
		GeoIP: []RouteGroup{{
			ID:    "user-geoip-cn",
			Layer: LayerGeoIP,
			Order: 20,
			Match: &geoIPMatch,
			Binding: RouteBinding{
				Enabled: true,
				Target:  TargetRef{Kind: TargetCurrentSelected},
			},
		}},
		Final: TargetRef{Kind: TargetBlock},
	}

	got, err := ApplyRegionAppend(routing, DefaultCNRegionAppendPlan())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GeoSite) != 2 || len(got.GeoIP) != 2 {
		t.Fatalf("region append sizes = geosite:%d geoip:%d", len(got.GeoSite), len(got.GeoIP))
	}
	if got.GeoSite[0].ID != "user-geosite-cn" ||
		got.GeoSite[1].ID != "region:auto-geosite:cn" ||
		got.GeoSite[1].Order != 11 ||
		got.GeoSite[1].Binding.Target.Kind != TargetDirect {
		t.Fatalf("unexpected GeoSite append order: %+v", got.GeoSite)
	}
	if got.GeoIP[0].ID != "user-geoip-cn" ||
		got.GeoIP[1].ID != "region:auto-geoip:cn" ||
		got.GeoIP[1].Order != 21 ||
		got.GeoIP[1].Binding.Target.Kind != TargetDirect {
		t.Fatalf("unexpected GeoIP append order: %+v", got.GeoIP)
	}

	steps, err := got.OrderedActiveSteps()
	if err != nil {
		t.Fatal(err)
	}
	gotOrder := make([]string, 0, len(steps))
	for _, step := range steps {
		gotOrder = append(gotOrder, string(step.Layer)+":"+step.GroupID+":"+string(step.Target.Kind))
	}
	wantOrder := []string{
		"geosite:user-geosite-cn:current_selected",
		"geosite:region:auto-geosite:cn:direct",
		"geoip:user-geoip-cn:current_selected",
		"geoip:region:auto-geoip:cn:direct",
		"final::block",
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("active order = %#v, want %#v", gotOrder, wantOrder)
	}
}

func TestApplyRegionAppendHonorsIndependentSwitchesAndLayerDisable(t *testing.T) {
	region := DefaultCNRegionAppendPlan()
	region.GeoSiteEnabled = false
	routing := RoutingPlan{
		Layers: RoutingLayerSwitches{GeoIPDisabled: true},
		Final:  TargetRef{Kind: TargetDirect},
	}

	got, err := ApplyRegionAppend(routing, region)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GeoSite) != 0 || len(got.GeoIP) != 1 {
		t.Fatalf("unexpected appended layers: geosite=%+v geoip=%+v", got.GeoSite, got.GeoIP)
	}
	steps, err := got.OrderedActiveSteps()
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || !steps[0].Final {
		t.Fatalf("globally disabled GeoIP layer became active: %+v", steps)
	}
}

func TestApplyRegionAppendPreservesInputAndDoesNotDeduplicateExplicitRegionRule(t *testing.T) {
	match := Atom(Predicate{Kind: PredicateRuleSet, Value: "geosite:cn"})
	routing := RoutingPlan{
		GeoSite: []RouteGroup{{
			ID:    "explicit-cn",
			Layer: LayerGeoSite,
			Order: 1,
			Match: &match,
			Binding: RouteBinding{
				Enabled: true,
				Target:  TargetRef{Kind: TargetCurrentSelected},
			},
		}},
		Final: TargetRef{Kind: TargetDirect},
	}
	got, err := ApplyRegionAppend(routing, DefaultCNRegionAppendPlan())
	if err != nil {
		t.Fatal(err)
	}
	if len(routing.GeoSite) != 1 || routing.GeoSite[0].ID != "explicit-cn" {
		t.Fatalf("input routing mutated: %+v", routing.GeoSite)
	}
	if len(got.GeoSite) != 2 {
		t.Fatalf("explicit region rule was deduplicated: %+v", got.GeoSite)
	}
	if got.GeoSite[0].Binding.Target.Kind != TargetCurrentSelected ||
		got.GeoSite[1].Binding.Target.Kind != TargetDirect {
		t.Fatalf("duplicate priority changed: %+v", got.GeoSite)
	}

	got.GeoSite[0].Match.Predicate.Value = "mutated"
	if routing.GeoSite[0].Match.Predicate.Value != "geosite:cn" {
		t.Fatal("returned routing aliases input matcher")
	}
}

func TestApplyRegionAppendRejectsLayerOrderOverflow(t *testing.T) {
	match := Atom(Predicate{Kind: PredicateRuleSet, Value: "geosite:test"})
	routing := RoutingPlan{
		GeoSite: []RouteGroup{{
			ID:    "last",
			Layer: LayerGeoSite,
			Order: ^uint32(0),
			Match: &match,
			Binding: RouteBinding{
				Enabled: true,
				Target:  TargetRef{Kind: TargetDirect},
			},
		}},
		Final: TargetRef{Kind: TargetDirect},
	}
	_, err := ApplyRegionAppend(routing, DefaultCNRegionAppendPlan())
	if !errors.Is(err, ErrInvalidRegionAppend) {
		t.Fatalf("order overflow error = %v", err)
	}
}
