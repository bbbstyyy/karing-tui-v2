package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestRuleSetCatalogBuildsStableImmutableMetadata(t *testing.T) {
	catalog, err := NewRuleSetCatalog([]RuleSetSource{
		{
			Ref:    "geosite:cn",
			Path:   "/state/rules/geosite-cn.srs",
			SHA256: strings.Repeat("A", 64),
			Format: RuleSetFormatBinary,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := catalog.Resolve("geosite:cn")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("geosite:cn"))
	if got, want := artifact.RuntimeTag, "rs-"+hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime tag = %q, want %q", got, want)
	}
	if artifact.SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("normalized SHA-256 = %q", artifact.SHA256)
	}
	if artifact.SourcePath != "/state/rules/geosite-cn.srs" {
		t.Fatalf("source path = %q", artifact.SourcePath)
	}
	if _, err := artifact.LocalConfig(); !errors.Is(err, ErrRuleSetNotStaged) {
		t.Fatalf("unstaged local config error = %v", err)
	}

	runtimePath := "/state/core/rule-sets/sha256/" + artifact.SHA256 + ".srs"
	bound, err := BindStagedRuleSetPaths(BoundRouting{RuleSets: []RuleSetArtifact{artifact}}, map[string]string{
		"geosite:cn": runtimePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err := bound.RuleSets[0].LocalConfig()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"local","tag":"` + artifact.RuntimeTag + `","format":"binary","path":"` + runtimePath + `"}`
	if string(encoded) != want {
		t.Fatalf("local rule-set config = %s, want %s", encoded, want)
	}
}

func TestRuleSetClosurePreservesFirstUseAndRejectsMissing(t *testing.T) {
	catalog, err := NewRuleSetCatalog([]RuleSetSource{
		{Ref: "acl:first", Path: "/rules/first.json", SHA256: strings.Repeat("1", 64), Format: RuleSetFormatSource},
		{Ref: "acl:second", Path: "/rules/second.srs", SHA256: strings.Repeat("2", 64), Format: RuleSetFormatBinary},
		{Ref: "acl:unused", Path: "/rules/unused.srs", SHA256: strings.Repeat("3", 64), Format: RuleSetFormatBinary},
	})
	if err != nil {
		t.Fatal(err)
	}
	closure, err := catalog.Closure([]string{"acl:second", "acl:first", "acl:second"})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{closure[0].Ref, closure[1].Ref}
	want := []string{"acl:second", "acl:first"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("closure = %#v, want %#v", got, want)
	}
	if _, err := catalog.Closure([]string{"acl:missing"}); !errors.Is(err, ErrUnresolvedRuleSet) {
		t.Fatalf("missing closure error = %v", err)
	}
}

func TestBindRuleSetArtifactsRewritesOnlyBoundCopy(t *testing.T) {
	match := domain.All(
		domain.Atom(domain.Predicate{Kind: domain.PredicateRuleSet, Value: "acl:first"}),
		domain.Any(
			domain.Atom(domain.Predicate{Kind: domain.PredicateRuleSet, Value: "acl:second"}),
			domain.Atom(domain.Predicate{Kind: domain.PredicateDomain, Value: "example.com"}),
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
				Target:  domain.TargetRef{Kind: domain.TargetDirect},
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetBlock},
	}
	compiled, err := CompileRouting(plan, testResolver())
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewRuleSetCatalog([]RuleSetSource{
		{Ref: "acl:first", Path: "/rules/first.srs", SHA256: strings.Repeat("a", 64), Format: RuleSetFormatBinary},
		{Ref: "acl:second", Path: "/rules/second.srs", SHA256: strings.Repeat("b", 64), Format: RuleSetFormatBinary},
	})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindRuleSetArtifacts(compiled, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := []string{bound.RuleSets[0].Ref, bound.RuleSets[1].Ref}, []string{"acl:first", "acl:second"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bound closure = %#v, want %#v", got, want)
	}

	firstTag := bound.RuleSets[0].RuntimeTag
	secondTag := bound.RuleSets[1].RuntimeTag
	if !routeRulesContainRuleSet(bound.Rules, firstTag) || !routeRulesContainRuleSet(bound.Rules, secondTag) {
		t.Fatalf("bound rules do not contain runtime tags: %+v", bound.Rules)
	}
	if routeRulesContainRuleSet(bound.Rules, "acl:first") || routeRulesContainRuleSet(bound.Rules, "acl:second") {
		t.Fatalf("source rule-set references leaked into bound rules: %+v", bound.Rules)
	}
	if !routeRulesContainRuleSet(compiled.Rules, "acl:first") || !routeRulesContainRuleSet(compiled.Rules, "acl:second") {
		t.Fatal("binding mutated original compiled routing")
	}
}

func TestBindRuleSetArtifactsFailsClosedOnIncompleteCatalog(t *testing.T) {
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateRuleSet, Value: "acl:required"})
	plan := domain.RoutingPlan{
		ACL: []domain.RouteGroup{{
			ID:    "required",
			Layer: domain.LayerACL,
			Order: 1,
			Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target:  domain.TargetRef{Kind: domain.TargetDirect},
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetBlock},
	}
	compiled, err := CompileRouting(plan, testResolver())
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewRuleSetCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindRuleSetArtifacts(compiled, catalog); !errors.Is(err, ErrUnresolvedRuleSet) {
		t.Fatalf("incomplete rule-set catalog error = %v", err)
	}
}

func TestRuleSetCatalogRejectsInvalidMetadata(t *testing.T) {
	validSHA := strings.Repeat("a", 64)
	cases := []RuleSetSource{
		{},
		{Ref: "acl:test", Path: "relative.srs", SHA256: validSHA, Format: RuleSetFormatBinary},
		{Ref: "acl:test", Path: "/rules/../test.srs", SHA256: validSHA, Format: RuleSetFormatBinary},
		{Ref: "acl:test", Path: "/rules/test.json", SHA256: validSHA, Format: RuleSetFormatBinary},
		{Ref: "acl:test", Path: "/rules/test.srs", SHA256: "bad", Format: RuleSetFormatBinary},
		{Ref: "acl:test", Path: "/rules/test.srs", SHA256: validSHA, Format: RuleSetFormat("unknown")},
		{Ref: " bad", Path: "/rules/test.srs", SHA256: validSHA, Format: RuleSetFormatBinary},
	}
	for i, source := range cases {
		if _, err := NewRuleSetCatalog([]RuleSetSource{source}); !errors.Is(err, ErrInvalidRuleSet) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}

	_, err := NewRuleSetCatalog([]RuleSetSource{
		{Ref: "acl:same", Path: "/rules/a.srs", SHA256: validSHA, Format: RuleSetFormatBinary},
		{Ref: "acl:same", Path: "/rules/b.srs", SHA256: validSHA, Format: RuleSetFormatBinary},
	})
	if !errors.Is(err, ErrDuplicateRuleSetRef) {
		t.Fatalf("duplicate rule-set ref error = %v", err)
	}
}

func TestRuleSetClosureIsDeterministicAcrossCatalogInputOrder(t *testing.T) {
	sources := []RuleSetSource{
		{Ref: "geoip:cn", Path: "/rules/cn.srs", SHA256: strings.Repeat("c", 64), Format: RuleSetFormatBinary},
		{Ref: "geosite:cn", Path: "/rules/site.srs", SHA256: strings.Repeat("d", 64), Format: RuleSetFormatBinary},
	}
	first, err := NewRuleSetCatalog(sources)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRuleSetCatalog([]RuleSetSource{sources[1], sources[0]})
	if err != nil {
		t.Fatal(err)
	}
	refs := []string{"geosite:cn", "geoip:cn"}
	a, err := first.Closure(refs)
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Closure(refs)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("closure depends on catalog insertion order:\n%+v\n%+v", a, b)
	}
}

func routeRulesContainRuleSet(rules []RouteRule, value string) bool {
	for _, rule := range rules {
		for _, tag := range rule.RuleSet {
			if tag == value {
				return true
			}
		}
		if routeRulesContainRuleSet(rule.Rules, value) {
			return true
		}
	}
	return false
}

func TestBindStagedRuleSetPathsRequiresCompleteContentAddressedClosure(t *testing.T) {
	catalog, err := NewRuleSetCatalog([]RuleSetSource{
		{Ref: "acl:first", Path: "/package/first.srs", SHA256: strings.Repeat("1", 64), Format: RuleSetFormatBinary},
		{Ref: "acl:second", Path: "/package/second.json", SHA256: strings.Repeat("2", 64), Format: RuleSetFormatSource},
	})
	if err != nil {
		t.Fatal(err)
	}
	closure, err := catalog.Closure([]string{"acl:first", "acl:second"})
	if err != nil {
		t.Fatal(err)
	}
	bound := BoundRouting{RuleSets: closure}

	if _, err := BindStagedRuleSetPaths(bound, map[string]string{
		"acl:first": "/state/core/rule-sets/sha256/" + strings.Repeat("1", 64) + ".srs",
	}); !errors.Is(err, ErrRuleSetNotStaged) {
		t.Fatalf("incomplete staged closure error = %v", err)
	}

	if _, err := BindStagedRuleSetPaths(bound, map[string]string{
		"acl:first":  "/state/core/rule-sets/sha256/not-the-hash.srs",
		"acl:second": "/state/core/rule-sets/sha256/" + strings.Repeat("2", 64) + ".json",
	}); !errors.Is(err, ErrInvalidRuleSet) {
		t.Fatalf("non-content-addressed runtime path error = %v", err)
	}

	rebound, err := BindStagedRuleSetPaths(bound, map[string]string{
		"acl:first":  "/state/core/rule-sets/sha256/" + strings.Repeat("1", 64) + ".srs",
		"acl:second": "/state/core/rule-sets/sha256/" + strings.Repeat("2", 64) + ".json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rebound.RuleSets[0].RuntimePath == "" || rebound.RuleSets[1].RuntimePath == "" {
		t.Fatalf("runtime paths were not bound: %+v", rebound.RuleSets)
	}
	if bound.RuleSets[0].RuntimePath != "" || bound.RuleSets[1].RuntimePath != "" {
		t.Fatal("staged path binding mutated original closure")
	}
}

func TestLocalRuleSetConfigRejectsFormatExtensionMismatch(t *testing.T) {
	artifact := RuleSetArtifact{
		Ref:         "acl:test",
		RuntimeTag:  "rs-test",
		SourcePath:  "/package/test.srs",
		RuntimePath: "/state/core/rule-sets/sha256/" + strings.Repeat("a", 64) + ".json",
		SHA256:      strings.Repeat("a", 64),
		Format:      RuleSetFormatBinary,
	}
	if _, err := artifact.LocalConfig(); !errors.Is(err, ErrInvalidRuleSet) {
		t.Fatalf("format/path mismatch error = %v", err)
	}
}
