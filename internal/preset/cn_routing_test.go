package preset

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestLowerCNCustomRoutingPreservesDefaultLinuxActiveSet(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	groups, err := LowerCNCustomRouting(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != CNExpectedGroups {
		t.Fatalf("groups = %d, want %d", len(groups), CNExpectedGroups)
	}

	var enabled []string
	for i, group := range groups {
		if group.ID != snapshot.Groups[i].ID || group.Order != snapshot.Groups[i].Order {
			t.Fatalf("group %d identity/order drift: %+v", i+1, group)
		}
		if group.Binding.Enabled {
			enabled = append(enabled, group.ID)
			if group.Match == nil {
				t.Fatalf("enabled group %q has no matcher", group.ID)
			}
			if group.Match.Op != domain.MatchAny {
				t.Fatalf("enabled group %q matcher op = %q, want any", group.ID, group.Match.Op)
			}
		} else if group.Match != nil {
			t.Fatalf("disabled group %q was unnecessarily lowered", group.ID)
		}
	}

	wantEnabled := []string{
		"cn.apple-services",
		"cn.google-play",
		"cn.google",
		"cn.bilibili",
		"cn.domestic-direct",
		"cn.foreign-proxy",
	}
	if !reflect.DeepEqual(enabled, wantEnabled) {
		t.Fatalf("enabled groups = %#v, want %#v", enabled, wantEnabled)
	}

	plan := domain.RoutingPlan{
		Custom: groups,
		Final:  domain.TargetRef{Kind: domain.TargetDirect},
	}
	compiled, err := compiler.CompileRouting(plan, compiler.TargetResolverFunc(func(target domain.TargetRef) (string, error) {
		switch target.Kind {
		case domain.TargetDirect:
			return "out-direct", nil
		case domain.TargetCurrentSelected:
			return "out-current", nil
		default:
			return "", errors.New("unexpected target")
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := compiled.RuleSetRefs, snapshot.RuleSetRefs(true); !reflect.DeepEqual(got, want) {
		t.Fatalf("active CN rule-set closure = %#v, want %#v", got, want)
	}
	if len(compiled.SourceMap) != CNExpectedEnabled+1 {
		t.Fatalf("source-map entries = %d, want %d active groups + FINAL", len(compiled.SourceMap), CNExpectedEnabled)
	}
	for i := 0; i < CNExpectedEnabled; i++ {
		if compiled.SourceMap[i].Layer != domain.LayerCustom {
			t.Fatalf("source-map entry %d layer = %q", i, compiled.SourceMap[i].Layer)
		}
	}
}

func TestLowerCNCustomRoutingDropsAndroidPackageBranchOnLinux(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	groups, err := LowerCNCustomRouting(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	googlePlay := groups[7]
	if googlePlay.ID != "cn.google-play" || googlePlay.Match == nil {
		t.Fatalf("unexpected Google Play group: %+v", googlePlay)
	}
	got := collectCNPredicates(*googlePlay.Match)
	want := []domain.Predicate{{
		Kind:  domain.PredicateRuleSet,
		Value: "geosite:google-play",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Google Play Linux predicates = %#v, want %#v", got, want)
	}
}

func TestLowerCNCustomRoutingPreservesFlatOrSemantics(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	groups, err := LowerCNCustomRouting(snapshot, []CNOverride{{
		GroupID: "cn.apple-push",
		Enabled: &enabled,
	}})
	if err != nil {
		t.Fatal(err)
	}
	push := groups[3]
	if push.Match == nil || push.Match.Op != domain.MatchAny {
		t.Fatalf("Apple push matcher = %+v", push.Match)
	}
	got := collectCNPredicates(*push.Match)
	if len(got) != 12 {
		t.Fatalf("Apple push predicates = %d, want 12", len(got))
	}
	if got[0] != (domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "push.apple.com"}) ||
		got[2] != (domain.Predicate{Kind: domain.PredicateDomainKeyword, Value: "apple.com.edgekey.net"}) ||
		got[3].Kind != domain.PredicateIPCIDR {
		t.Fatalf("Apple push predicate order/content changed: %+v", got)
	}
}

func TestLowerCNCustomRoutingFailsClosedForUnverifiedProcessName(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	_, err = LowerCNCustomRouting(snapshot, []CNOverride{{
		GroupID: "cn.whatsapp",
		Enabled: &enabled,
	}})
	if !errors.Is(err, ErrCNProcessSemanticsUnverified) {
		t.Fatalf("WhatsApp process semantics error = %v", err)
	}
}

func TestLowerCNCustomRoutingFailsWhenLinuxFilteringLeavesNoMatcher(t *testing.T) {
	_, err := lowerCNRuleLinux(CNRule{
		Name:    "android-only",
		Package: []string{"com.example"},
	})
	if !errors.Is(err, ErrCNRuleHasNoLinuxMatch) {
		t.Fatalf("Android-only Linux matcher error = %v", err)
	}
}

func collectCNPredicates(match domain.MatchExpr) []domain.Predicate {
	var result []domain.Predicate
	var walk func(domain.MatchExpr)
	walk = func(expr domain.MatchExpr) {
		if expr.Predicate != nil {
			result = append(result, *expr.Predicate)
		}
		for _, child := range expr.Children {
			walk(child)
		}
	}
	walk(match)
	return result
}
