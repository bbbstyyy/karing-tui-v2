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
