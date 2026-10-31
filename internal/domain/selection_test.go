package domain

import (
	"errors"
	"testing"
	"time"
)

func TestSelectionPlanAcceptsNodeAndAutoGroupCurrentSelection(t *testing.T) {
	nodeA := TargetRef{Kind: TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	nodeB := TargetRef{Kind: TargetSpecificNode, ProfileID: "profile-b", NodeID: "node-b"}
	custom := TargetRef{Kind: TargetCustomURLTest, GroupID: "jp-auto"}
	global := TargetRef{Kind: TargetGlobalURLTest}

	plan := SelectionPlan{
		Current: CurrentSelection{
			Members: []TargetRef{nodeA, custom, global},
			Default: custom,
		},
		Global: &URLTestGroup{
			Members: []TargetRef{nodeA, nodeB},
			Policy:  testURLTestPolicy(),
		},
		Custom: []URLTestGroup{{
			GroupID: "jp-auto",
			Members: []TargetRef{nodeB, nodeA},
			Policy:  testURLTestPolicy(),
		}},
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentSelectionRejectsUnsupportedOrMissingDefault(t *testing.T) {
	node := TargetRef{Kind: TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	cases := []CurrentSelection{
		{},
		{Members: []TargetRef{node}, Default: TargetRef{Kind: TargetSpecificNode, ProfileID: "profile-b", NodeID: "node-b"}},
		{Members: []TargetRef{{Kind: TargetDirect}}, Default: TargetRef{Kind: TargetDirect}},
		{Members: []TargetRef{{Kind: TargetCurrentSelected}}, Default: TargetRef{Kind: TargetCurrentSelected}},
	}
	for i, selection := range cases {
		if err := selection.Validate(); !errors.Is(err, ErrInvalidSelectionPlan) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

func TestCurrentSelectionRejectsDuplicateCandidates(t *testing.T) {
	node := TargetRef{Kind: TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	selection := CurrentSelection{
		Members: []TargetRef{node, node},
		Default: node,
	}
	if err := selection.Validate(); !errors.Is(err, ErrDuplicateSelectionItem) {
		t.Fatalf("duplicate current selection error = %v", err)
	}
}

func TestURLTestGroupRequiresSpecificNodesAndStableOrder(t *testing.T) {
	nodeA := TargetRef{Kind: TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	nodeB := TargetRef{Kind: TargetSpecificNode, ProfileID: "profile-b", NodeID: "node-b"}
	group := URLTestGroup{
		GroupID: "us-auto",
		Members: []TargetRef{nodeA, nodeB},
		Policy:  testURLTestPolicy(),
	}
	if err := group.Validate(true); err != nil {
		t.Fatal(err)
	}
	if group.Members[0] != nodeA || group.Members[1] != nodeB {
		t.Fatal("URLTest candidate order changed during validation")
	}

	group.Members = []TargetRef{{Kind: TargetCustomURLTest, GroupID: "nested"}}
	if err := group.Validate(true); !errors.Is(err, ErrInvalidSelectionPlan) {
		t.Fatalf("nested URLTest error = %v", err)
	}

	group.Members = []TargetRef{nodeA, nodeA}
	if err := group.Validate(true); !errors.Is(err, ErrDuplicateSelectionItem) {
		t.Fatalf("duplicate URLTest node error = %v", err)
	}
}

func TestSelectionPlanRejectsDuplicateCustomGroups(t *testing.T) {
	node := TargetRef{Kind: TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	group := URLTestGroup{
		GroupID: "same",
		Members: []TargetRef{node},
		Policy:  testURLTestPolicy(),
	}
	plan := SelectionPlan{
		Current: CurrentSelection{Members: []TargetRef{node}, Default: node},
		Custom:  []URLTestGroup{group, group},
	}
	if err := plan.Validate(); !errors.Is(err, ErrDuplicateSelectionItem) {
		t.Fatalf("duplicate custom group error = %v", err)
	}
}

func TestURLTestPolicyRejectsUnsafeOrIncompleteEndpoint(t *testing.T) {
	valid := testURLTestPolicy()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}

	cases := []URLTestPolicy{
		{URL: "ftp://example.com/test", Interval: time.Minute, Tolerance: 50, IdleTimeout: time.Minute},
		{URL: "https:///missing-host", Interval: time.Minute, Tolerance: 50, IdleTimeout: time.Minute},
		{URL: "https://user:pass@example.com/test", Interval: time.Minute, Tolerance: 50, IdleTimeout: time.Minute},
		{URL: "https://example.com/test", Interval: 0, Tolerance: 50, IdleTimeout: time.Minute},
		{URL: "https://example.com/test", Interval: time.Minute, Tolerance: 0, IdleTimeout: time.Minute},
		{URL: "https://example.com/test", Interval: time.Minute, Tolerance: 50, IdleTimeout: 0},
	}
	for i, policy := range cases {
		if err := policy.Validate(); !errors.Is(err, ErrInvalidSelectionPlan) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

func TestGlobalURLTestRejectsCustomGroupID(t *testing.T) {
	node := TargetRef{Kind: TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	group := URLTestGroup{
		GroupID: "should-not-exist",
		Members: []TargetRef{node},
		Policy:  testURLTestPolicy(),
	}
	if err := group.Validate(false); !errors.Is(err, ErrInvalidSelectionPlan) {
		t.Fatalf("global group ID error = %v", err)
	}
}

func testURLTestPolicy() URLTestPolicy {
	return URLTestPolicy{
		URL:         "https://example.com/generate_204",
		Interval:    5 * time.Minute,
		Tolerance:   50,
		IdleTimeout: 30 * time.Minute,
	}
}
