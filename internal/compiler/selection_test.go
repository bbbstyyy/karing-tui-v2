package compiler

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCompileSelectionGroupsBuildsDependencyClosure(t *testing.T) {
	nodeA := NodeTargetKey{ProfileID: "profile-a", NodeID: "node-a"}
	nodeB := NodeTargetKey{ProfileID: "profile-b", NodeID: "node-b"}
	nodeC := NodeTargetKey{ProfileID: "profile-c", NodeID: "node-c"}
	catalog, err := NewTargetCatalog([]string{"jp-auto", "unused-auto"}, []NodeTargetKey{nodeA, nodeB, nodeC})
	if err != nil {
		t.Fatal(err)
	}

	refA := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: nodeA.ProfileID, NodeID: nodeA.NodeID}
	refB := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: nodeB.ProfileID, NodeID: nodeB.NodeID}
	refC := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: nodeC.ProfileID, NodeID: nodeC.NodeID}
	custom := domain.TargetRef{Kind: domain.TargetCustomURLTest, GroupID: "jp-auto"}
	global := domain.TargetRef{Kind: domain.TargetGlobalURLTest}

	plan := domain.SelectionPlan{
		Current: domain.CurrentSelection{
			Members: []domain.TargetRef{refA, custom, global},
			Default: custom,
		},
		Global: &domain.URLTestGroup{
			Members: []domain.TargetRef{refC},
			Policy:  selectionTestPolicy("https://global.example/generate_204"),
		},
		Custom: []domain.URLTestGroup{
			{
				GroupID: "jp-auto",
				Members: []domain.TargetRef{refB, refA},
				Policy:  selectionTestPolicy("https://jp.example/generate_204"),
			},
			{
				GroupID: "unused-auto",
				Members: []domain.TargetRef{refC},
				Policy:  selectionTestPolicy("https://unused.example/generate_204"),
			},
		},
	}

	result, err := CompileSelectionGroups(plan, catalog, []string{
		catalog.DirectTag,
		catalog.CurrentSelectedTag,
		catalog.NodeTags[nodeC],
		catalog.CustomURLTestTags["jp-auto"],
	})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := result.NodeTargets, []domain.TargetRef{refC, refA, refB}; !reflect.DeepEqual(got, want) {
		t.Fatalf("node target closure = %#v, want %#v", got, want)
	}
	if got, want := result.NodeTags, []string{
		catalog.NodeTags[nodeC],
		catalog.NodeTags[nodeA],
		catalog.NodeTags[nodeB],
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("node tag closure = %#v, want %#v", got, want)
	}
	if len(result.Groups) != 3 {
		t.Fatalf("group count = %d, want global + jp-auto + current selector", len(result.Groups))
	}

	globalConfig := result.Groups[0]
	if globalConfig.Type != "urltest" ||
		globalConfig.Tag != catalog.GlobalURLTestTag ||
		!reflect.DeepEqual(globalConfig.Outbounds, []string{catalog.NodeTags[nodeC]}) {
		t.Fatalf("unexpected global URLTest config: %+v", globalConfig)
	}

	customConfig := result.Groups[1]
	if customConfig.Type != "urltest" ||
		customConfig.Tag != catalog.CustomURLTestTags["jp-auto"] ||
		!reflect.DeepEqual(customConfig.Outbounds, []string{catalog.NodeTags[nodeB], catalog.NodeTags[nodeA]}) {
		t.Fatalf("unexpected custom URLTest config: %+v", customConfig)
	}

	selector := result.Groups[2]
	if selector.Type != "selector" ||
		selector.Tag != catalog.CurrentSelectedTag ||
		selector.Default != catalog.CustomURLTestTags["jp-auto"] ||
		!reflect.DeepEqual(selector.Outbounds, []string{
			catalog.NodeTags[nodeA],
			catalog.CustomURLTestTags["jp-auto"],
			catalog.GlobalURLTestTag,
		}) {
		t.Fatalf("unexpected CurrentSelected config: %+v", selector)
	}
	for _, group := range result.Groups {
		if group.Tag == catalog.CustomURLTestTags["unused-auto"] {
			t.Fatal("unused URLTest group leaked into runtime closure")
		}
	}
}

func TestCompileSelectionGroupsEmitsApprovedCoreJSONFields(t *testing.T) {
	node := NodeTargetKey{ProfileID: "profile-a", NodeID: "node-a"}
	catalog, err := NewTargetCatalog(nil, []NodeTargetKey{node})
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: node.ProfileID, NodeID: node.NodeID}
	plan := domain.SelectionPlan{
		Current: domain.CurrentSelection{
			Members:                   []domain.TargetRef{ref},
			Default:                   ref,
			InterruptExistConnections: true,
		},
	}
	result, err := CompileSelectionGroups(plan, catalog, []string{catalog.CurrentSelectedTag})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Groups) != 1 {
		t.Fatalf("group count = %d, want 1", len(result.Groups))
	}
	encoded, err := json.Marshal(result.Groups[0])
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"selector","tag":"out-current","outbounds":["` + catalog.NodeTags[node] + `"],"default":"` + catalog.NodeTags[node] + `","interrupt_exist_connections":true}`
	if string(encoded) != want {
		t.Fatalf("selector JSON = %s, want %s", encoded, want)
	}
}

func TestCompileSelectionGroupsRejectsMissingDependencies(t *testing.T) {
	node := NodeTargetKey{ProfileID: "profile-a", NodeID: "node-a"}
	catalog, err := NewTargetCatalog([]string{"missing-auto"}, []NodeTargetKey{node})
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: node.ProfileID, NodeID: node.NodeID}

	base := domain.SelectionPlan{
		Current: domain.CurrentSelection{Members: []domain.TargetRef{ref}, Default: ref},
	}
	if _, err := CompileSelectionGroups(base, catalog, []string{"unknown-outbound"}); !errors.Is(err, ErrSelectionClosure) {
		t.Fatalf("unknown outbound error = %v", err)
	}
	if _, err := CompileSelectionGroups(base, catalog, []string{catalog.GlobalURLTestTag}); !errors.Is(err, ErrSelectionClosure) {
		t.Fatalf("missing global URLTest error = %v", err)
	}
	if _, err := CompileSelectionGroups(base, catalog, []string{catalog.CustomURLTestTags["missing-auto"]}); !errors.Is(err, ErrSelectionClosure) {
		t.Fatalf("missing custom URLTest error = %v", err)
	}
}

func TestCompileSelectionGroupsRejectsNodeMissingFromTargetCatalog(t *testing.T) {
	existing := NodeTargetKey{ProfileID: "profile-a", NodeID: "node-a"}
	catalog, err := NewTargetCatalog(nil, []NodeTargetKey{existing})
	if err != nil {
		t.Fatal(err)
	}
	existingRef := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: existing.ProfileID, NodeID: existing.NodeID}
	missingRef := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-b", NodeID: "node-b"}
	plan := domain.SelectionPlan{
		Current: domain.CurrentSelection{Members: []domain.TargetRef{existingRef}, Default: existingRef},
		Global: &domain.URLTestGroup{
			Members: []domain.TargetRef{missingRef},
			Policy:  selectionTestPolicy("https://global.example/generate_204"),
		},
	}
	if _, err := CompileSelectionGroups(plan, catalog, []string{catalog.GlobalURLTestTag}); !errors.Is(err, ErrSelectionClosure) {
		t.Fatalf("missing URLTest node error = %v", err)
	}
}

func TestCompileSelectionGroupsUsesRoutingOutboundClosure(t *testing.T) {
	nodeA := NodeTargetKey{ProfileID: "profile-a", NodeID: "node-a"}
	nodeB := NodeTargetKey{ProfileID: "profile-b", NodeID: "node-b"}
	catalog, err := NewTargetCatalog([]string{"us-auto"}, []NodeTargetKey{nodeA, nodeB})
	if err != nil {
		t.Fatal(err)
	}
	refA := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: nodeA.ProfileID, NodeID: nodeA.NodeID}
	refB := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: nodeB.ProfileID, NodeID: nodeB.NodeID}
	selection := domain.SelectionPlan{
		Current: domain.CurrentSelection{Members: []domain.TargetRef{refA}, Default: refA},
		Custom: []domain.URLTestGroup{{
			GroupID: "us-auto",
			Members: []domain.TargetRef{refB},
			Policy:  selectionTestPolicy("https://us.example/generate_204"),
		}},
	}

	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "example.com"})
	routing, err := CompileRouting(domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID:    "custom",
			Layer: domain.LayerCustom,
			Order: 1,
			Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target:  domain.TargetRef{Kind: domain.TargetCustomURLTest, GroupID: "us-auto"},
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetCurrentSelected},
	}, catalog)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileSelectionGroups(selection, catalog, routing.OutboundTags)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Groups) != 2 {
		t.Fatalf("groups = %d, want custom URLTest + selector", len(compiled.Groups))
	}
	if compiled.Groups[0].Tag != catalog.CustomURLTestTags["us-auto"] ||
		compiled.Groups[1].Tag != catalog.CurrentSelectedTag {
		t.Fatalf("unexpected group order: %+v", compiled.Groups)
	}
	if got, want := compiled.NodeTags, []string{catalog.NodeTags[nodeA], catalog.NodeTags[nodeB]}; !reflect.DeepEqual(got, want) {
		t.Fatalf("node closure = %#v, want %#v", got, want)
	}
}

func selectionTestPolicy(endpoint string) domain.URLTestPolicy {
	return domain.URLTestPolicy{
		URL:         endpoint,
		Interval:    5 * time.Minute,
		Tolerance:   50,
		IdleTimeout: 30 * time.Minute,
	}
}
