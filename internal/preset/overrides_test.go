package preset

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestApplyCNOverridesPreservesSnapshotByDefault(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	effective, err := ApplyCNOverrides(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(effective) != len(snapshot.Groups) {
		t.Fatalf("effective groups = %d, want %d", len(effective), len(snapshot.Groups))
	}
	for i := range snapshot.Groups {
		source := snapshot.Groups[i]
		got := effective[i]
		if got.ID != source.ID ||
			got.Order != source.Order ||
			got.DisplayName != source.DisplayName ||
			got.Enabled != source.Enabled ||
			got.Target != source.Target ||
			got.DNSProfileID != "" ||
			!reflect.DeepEqual(got.Source, source.Source) {
			t.Fatalf("group %d drifted without override:\nsource=%+v\neffective=%+v", i, source, got)
		}
	}
}

func TestApplyCNOverridesChangesOnlyMutableBindingFields(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	disable := false
	dnsProfile := "dns.proxy.us"
	target := domain.TargetRef{Kind: domain.TargetCustomURLTest, GroupID: "us-auto"}

	effective, err := ApplyCNOverrides(snapshot, []CNOverride{
		{
			GroupID: "cn.google",
			Enabled: &disable,
		},
		{
			GroupID:      "cn.openai",
			Target:       &target,
			DNSProfileID: &dnsProfile,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	google := effective[9]
	if google.ID != "cn.google" || google.Enabled {
		t.Fatalf("Google override not applied: %+v", google)
	}
	if google.Target.Kind != domain.TargetCurrentSelected {
		t.Fatalf("Google target changed unexpectedly: %+v", google.Target)
	}

	openai := effective[18]
	if openai.ID != "cn.openai" ||
		openai.Target != target ||
		openai.DNSProfileID != dnsProfile {
		t.Fatalf("OpenAI override not applied: %+v", openai)
	}
	if openai.Order != snapshot.Groups[18].Order ||
		openai.DisplayName != snapshot.Groups[18].DisplayName ||
		!reflect.DeepEqual(openai.Source, snapshot.Groups[18].Source) {
		t.Fatal("override changed immutable upstream source fields")
	}
}

func TestApplyCNOverridesCanExplicitlyClearDNSBinding(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	set := "dns.proxy"
	effective, err := ApplyCNOverrides(snapshot, []CNOverride{{
		GroupID:      "cn.telegram",
		DNSProfileID: &set,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if effective[16].DNSProfileID != set {
		t.Fatalf("DNS profile = %q, want %q", effective[16].DNSProfileID, set)
	}

	clear := ""
	effective, err = ApplyCNOverrides(snapshot, []CNOverride{{
		GroupID:      "cn.telegram",
		DNSProfileID: &clear,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if effective[16].DNSProfileID != "" {
		t.Fatalf("cleared DNS profile = %q", effective[16].DNSProfileID)
	}
}

func TestApplyCNOverridesRejectsUnknownDuplicateAndInvalidValues(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	enabled := true

	cases := [][]CNOverride{
		{{GroupID: "cn.unknown", Enabled: &enabled}},
		{
			{GroupID: "cn.google", Enabled: &enabled},
			{GroupID: "cn.google", Enabled: &enabled},
		},
		{{GroupID: ""}},
	}
	for i, overrides := range cases {
		if _, err := ApplyCNOverrides(snapshot, overrides); !errors.Is(err, ErrInvalidCNOverride) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}

	invalidTarget := domain.TargetRef{Kind: domain.TargetCustomURLTest}
	if _, err := ApplyCNOverrides(snapshot, []CNOverride{{
		GroupID: "cn.google",
		Target:  &invalidTarget,
	}}); !errors.Is(err, ErrInvalidCNOverride) {
		t.Fatalf("invalid target error = %v", err)
	}

	badDNS := " dns.proxy"
	if _, err := ApplyCNOverrides(snapshot, []CNOverride{{
		GroupID:      "cn.google",
		DNSProfileID: &badDNS,
	}}); !errors.Is(err, ErrInvalidCNOverride) {
		t.Fatalf("invalid DNS profile error = %v", err)
	}
}

func TestApplyCNOverridesDeepCopiesRawConditions(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	effective, err := ApplyCNOverrides(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := snapshot.Groups[0].Source.RuleSetBuildIn[0]
	effective[0].Source.RuleSetBuildIn[0] = "mutated"
	if snapshot.Groups[0].Source.RuleSetBuildIn[0] != original {
		t.Fatal("effective override view aliases immutable snapshot conditions")
	}
}
