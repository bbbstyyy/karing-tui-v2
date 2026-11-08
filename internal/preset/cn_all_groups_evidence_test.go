package preset

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCNAll28LinuxGroupsPreserveExactFieldOrderAndFiveLayerIR(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	overrides := make([]CNOverride, len(snapshot.Groups))
	for i, group := range snapshot.Groups {
		overrides[i] = CNOverride{GroupID: group.ID, Enabled: &enabled}
	}
	lowered, err := LowerCNCustomRouting(snapshot, overrides)
	if err != nil {
		t.Fatal(err)
	}
	if len(lowered) != CNExpectedGroups {
		t.Fatalf("all 28 source groups required, got %d", len(lowered))
	}

	for i, group := range lowered {
		source := snapshot.Groups[i]
		if group.ID != source.ID || group.Order != uint32(i+1) ||
			group.Layer != domain.LayerCustom || !group.Binding.Enabled ||
			group.Binding.Target != source.Target || group.Match == nil ||
			group.Match.Op != domain.MatchAny {
			t.Fatalf("CN group %d identity/order/target/OR semantics drift: %+v", i, group)
		}
		var expected []domain.Predicate
		for _, ref := range source.Source.RuleSetBuildIn {
			expected = append(expected, domain.Predicate{
				Kind: domain.PredicateRuleSet, Value: ref,
			})
		}
		for _, suffix := range source.Source.DomainSuffix {
			expected = append(expected, domain.Predicate{
				Kind: domain.PredicateDomainSuffix, Value: suffix,
			})
		}
		for _, keyword := range source.Source.DomainKeyword {
			expected = append(expected, domain.Predicate{
				Kind: domain.PredicateDomainKeyword, Value: keyword,
			})
		}
		for _, cidr := range source.Source.IPCIDR {
			expected = append(expected, domain.Predicate{
				Kind: domain.PredicateIPCIDR, CIDR: cidr,
			})
		}
		for _, process := range source.Source.ProcessName {
			expected = append(expected, domain.Predicate{
				Kind: domain.PredicateProcessName, Value: process,
			})
		}
		// The original Karing Linux branch only excludes Android package
		// names; all the other families and their original order survive.
		actual := collectCNPredicates(*group.Match)
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("CN group %q dropped/reordered Linux source predicates:\n got: %#v\nwant: %#v", group.ID, actual, expected)
		}
	}
	plan := domain.RoutingPlan{
		Custom: lowered,
		Final:  domain.TargetRef{Kind: domain.TargetDirect},
	}
	compiled, err := compiler.CompileRouting(plan, compiler.TargetResolverFunc(
		func(target domain.TargetRef) (string, error) {
			switch target.Kind {
			case domain.TargetDirect:
				return "out-direct", nil
			case domain.TargetCurrentSelected:
				return "out-current", nil
			case domain.TargetBlock:
				return "", nil
			default:
				return "", errors.New("unexpected test target")
			}
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(compiled.RuleSetRefs, snapshot.RuleSetRefs(false)) {
		t.Fatalf("CN active 28-group resource closure changed: got %#v", compiled.RuleSetRefs)
	}
	if len(compiled.SourceMap) != CNExpectedGroups+1 {
		t.Fatalf("CN source-map lost groups or FINAL: %d", len(compiled.SourceMap))
	}
	for i, entry := range compiled.SourceMap[:CNExpectedGroups] {
		if entry.Final || entry.GroupID != snapshot.Groups[i].ID ||
			entry.Target != snapshot.Groups[i].Target ||
			entry.Layer != domain.LayerCustom {
			t.Fatalf("CN group %d source-map provenance lost: %+v", i, entry)
		}
	}
	if !compiled.SourceMap[CNExpectedGroups].Final {
		t.Fatal("CN route omitted FINAL")
	}
	foundBing := false
	for _, ref := range compiled.RuleSetRefs {
		if ref == "geoip:bing" {
			foundBing = true
		}
	}
	if !foundBing {
		t.Fatal("CN all-enabled routing silently pruned missing geoip:bing")
	}
}

func TestCNAllEnabledRoutingRefusesMissingBingArtifactWithoutDirectFallback(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	groups, err := LowerCNCustomRouting(snapshot, []CNOverride{{
		GroupID: "cn.bing", Enabled: &enabled,
	}})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.CompileRouting(domain.RoutingPlan{
		Custom: groups, Final: domain.TargetRef{Kind: domain.TargetDirect},
	}, compiler.TargetResolverFunc(func(target domain.TargetRef) (string, error) {
		switch target.Kind {
		case domain.TargetDirect:
			return "out-direct", nil
		case domain.TargetCurrentSelected:
			return "out-current", nil
		default:
			return "", errors.New("unknown target")
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	var sources []compiler.RuleSetSource
	missing := false
	for _, ref := range compiled.RuleSetRefs {
		if ref == "geoip:bing" {
			missing = true
			continue
		}
		sources = append(sources, compiler.RuleSetSource{
			Ref: ref, Path: "/tmp/cn-test-" + strings.ReplaceAll(ref, ":", "-") + ".srs",
			SHA256: strings.Repeat("a", 64),
			Format: compiler.RuleSetFormatBinary,
		})
	}
	if !missing {
		t.Fatal("Bing enabled but compiled closure lacks the missing upstream ref")
	}
	catalog, err := compiler.NewRuleSetCatalog(sources)
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiler.BindRuleSetArtifacts(compiled, catalog)
	if !errors.Is(err, compiler.ErrUnresolvedRuleSet) {
		t.Fatalf("missing CN resource must block Core artifact binding: %v", err)
	}
}
