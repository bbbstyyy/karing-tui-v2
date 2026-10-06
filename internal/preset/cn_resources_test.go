package preset

import (
	"errors"
	"reflect"
	"testing"
)

func TestCNOfflineResourcePlanClosesAllPresetAndRegionRefs(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := CNOfflineResourcePlan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != CNResourceExpectedLogicalRefs {
		t.Fatalf("resource plan refs = %d, want %d", len(plan), CNResourceExpectedLogicalRefs)
	}

	files := 0
	absent := make([]CNResourceSpec, 0)
	refs := make([]string, 0, len(plan))
	for _, spec := range plan {
		refs = append(refs, spec.Ref)
		switch spec.Status {
		case CNResourceStatusFile:
			files++
			if spec.RelativePath == "" || spec.Format != CNResourceFormatBinary || spec.Reason != "" {
				t.Fatalf("invalid file resource spec: %+v", spec)
			}
		case CNResourceStatusUpstreamAbsent:
			absent = append(absent, spec)
		default:
			t.Fatalf("unexpected resource status: %+v", spec)
		}
	}
	if files != CNResourceExpectedFiles {
		t.Fatalf("resource plan file count = %d, want %d", files, CNResourceExpectedFiles)
	}
	if len(absent) != 1 ||
		absent[0].Ref != "geoip:bing" ||
		absent[0].RelativePath != "geoip/bing.srs" ||
		absent[0].Reason == "" {
		t.Fatalf("known upstream absence = %+v", absent)
	}

	for _, required := range []string{"geosite:cn", "geoip:cn", "geosite:geolocation-!cn", "acl:ChinaIp"} {
		found := false
		for _, ref := range refs {
			if ref == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("resource plan missing %q", required)
		}
	}
}

func TestCNOfflineResourcePlanPreservesFirstUseOrder(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := CNOfflineResourcePlan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, 8)
	for _, spec := range plan[:8] {
		got = append(got, spec.Ref)
	}
	want := []string{
		"acl:BanAD",
		"geosite:category-ads",
		"acl:BanProgramAD",
		"acl:BanADCompany",
		"geosite:malware",
		"geoip:malware",
		"geoip:phishing",
		"geosite:phishing",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resource plan prefix = %#v, want %#v", got, want)
	}
	if plan[len(plan)-2].Ref != "geosite:cn" || plan[len(plan)-1].Ref != "geoip:cn" {
		t.Fatalf("region append refs are not at closure tail: %+v", plan[len(plan)-2:])
	}
}

func TestCNOfflineResourcePlanRejectsWrongSnapshotProvenance(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.SourceCommit = "different"
	if _, err := CNOfflineResourcePlan(snapshot); !errors.Is(err, ErrInvalidCNResourcePlan) {
		t.Fatalf("provenance error = %v", err)
	}
}

func TestCNResourceRelativePathPreservesQualifiers(t *testing.T) {
	cases := map[string]string{
		"geosite:apple@ads":          "geosite/apple@ads.srs",
		"geosite:geolocation-!cn":    "geosite/geolocation-!cn.srs",
		"geoip:cn":                   "geoip/cn.srs",
		"acl:ChinaCompanyIp":         "acl/ChinaCompanyIp.srs",
	}
	for ref, want := range cases {
		got, err := cnResourceRelativePath(ref)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if got != want {
			t.Fatalf("%s path = %q, want %q", ref, got, want)
		}
	}

	for _, ref := range []string{"", "unknown:test", "geoip:"} {
		if _, err := cnResourceRelativePath(ref); !errors.Is(err, ErrInvalidCNResourcePlan) {
			t.Fatalf("%q error = %v", ref, err)
		}
	}
}
