package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestTargetCatalogGeneratesStableDisplayIndependentTags(t *testing.T) {
	nodes := []NodeTargetKey{
		{ProfileID: "profile-b", NodeID: "node-2"},
		{ProfileID: "profile-a", NodeID: "node-1"},
	}
	catalog, err := NewTargetCatalog([]string{"jp-auto", "us-auto"}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := NewTargetCatalog([]string{"us-auto", "jp-auto"}, []NodeTargetKey{nodes[1], nodes[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(catalog, reordered) {
		t.Fatalf("catalog changed with input order:\n%+v\n%+v", catalog, reordered)
	}

	customHash := sha256.Sum256([]byte("custom\x00jp-auto"))
	if got, want := catalog.CustomURLTestTags["jp-auto"], "out-auto-"+hex.EncodeToString(customHash[:]); got != want {
		t.Fatalf("custom tag = %q, want %q", got, want)
	}
	nodeHash := sha256.Sum256([]byte("node\x00profile-a\x00node-1"))
	if got, want := catalog.NodeTags[NodeTargetKey{ProfileID: "profile-a", NodeID: "node-1"}], "out-node-"+hex.EncodeToString(nodeHash[:]); got != want {
		t.Fatalf("node tag = %q, want %q", got, want)
	}
}

func TestTargetCatalogResolvesTypedTargets(t *testing.T) {
	catalog, err := NewTargetCatalog(
		[]string{"asia-auto"},
		[]NodeTargetKey{{ProfileID: "profile-a", NodeID: "node-a"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		target domain.TargetRef
		want   string
	}{
		{target: domain.TargetRef{Kind: domain.TargetDirect}, want: "out-direct"},
		{target: domain.TargetRef{Kind: domain.TargetCurrentSelected}, want: "out-current"},
		{target: domain.TargetRef{Kind: domain.TargetGlobalURLTest}, want: "out-global-urltest"},
		{target: domain.TargetRef{Kind: domain.TargetCustomURLTest, GroupID: "asia-auto"}, want: catalog.CustomURLTestTags["asia-auto"]},
		{target: domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}, want: catalog.NodeTags[NodeTargetKey{ProfileID: "profile-a", NodeID: "node-a"}]},
	}
	for _, tc := range cases {
		got, err := catalog.ResolveTarget(tc.target)
		if err != nil {
			t.Fatalf("resolve %+v: %v", tc.target, err)
		}
		if got != tc.want {
			t.Fatalf("resolve %+v = %q, want %q", tc.target, got, tc.want)
		}
	}

	if _, err := catalog.ResolveTarget(domain.TargetRef{Kind: domain.TargetCustomURLTest, GroupID: "missing"}); err == nil {
		t.Fatal("missing custom URLTest unexpectedly resolved")
	}
	if _, err := catalog.ResolveTarget(domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "missing"}); err == nil {
		t.Fatal("missing node unexpectedly resolved")
	}
	if _, err := catalog.ResolveTarget(domain.TargetRef{Kind: domain.TargetBlock}); err == nil {
		t.Fatal("BLOCK unexpectedly resolved to an outbound")
	}
}

func TestTargetCatalogRejectsDuplicateIdentityAndUnsafeIDs(t *testing.T) {
	if _, err := NewTargetCatalog([]string{"same", "same"}, nil); !errors.Is(err, ErrDuplicateTargetID) {
		t.Fatalf("duplicate custom group error = %v", err)
	}
	if _, err := NewTargetCatalog(nil, []NodeTargetKey{
		{ProfileID: "profile", NodeID: "node"},
		{ProfileID: "profile", NodeID: "node"},
	}); !errors.Is(err, ErrDuplicateTargetID) {
		t.Fatalf("duplicate node error = %v", err)
	}
	for _, invalid := range []string{"", " leading", "trailing ", "bad\nvalue", strings.Repeat("a", 513)} {
		if _, err := NewTargetCatalog([]string{invalid}, nil); err == nil {
			t.Fatalf("invalid target ID %q unexpectedly accepted", invalid)
		}
	}
}

func TestTargetCatalogDetectsTagCollisionDeterministically(t *testing.T) {
	first := TargetCatalog{
		DirectTag:          "out-direct",
		CurrentSelectedTag: "out-current",
		GlobalURLTestTag:   "out-global",
		CustomURLTestTags: map[string]string{
			"z-group": "out-collision",
			"a-group": "out-collision",
		},
	}
	second := TargetCatalog{
		DirectTag:          "out-direct",
		CurrentSelectedTag: "out-current",
		GlobalURLTestTag:   "out-global",
		CustomURLTestTags: map[string]string{
			"a-group": "out-collision",
			"z-group": "out-collision",
		},
	}
	err1 := first.Validate()
	err2 := second.Validate()
	if !errors.Is(err1, ErrDuplicateTargetTag) || !errors.Is(err2, ErrDuplicateTargetTag) {
		t.Fatalf("collision errors = %v / %v", err1, err2)
	}
	if err1.Error() != err2.Error() {
		t.Fatalf("collision diagnostic is not deterministic:\n%s\n%s", err1, err2)
	}
}

func TestTargetCatalogFeedsRoutingCompilerWithoutDisplayNames(t *testing.T) {
	catalog, err := NewTargetCatalog(
		[]string{"asia-auto"},
		[]NodeTargetKey{{ProfileID: "profile-stable-id", NodeID: "node-stable-id"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "example.com"})
	plan := domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID:    "group-stable-id",
			Layer: domain.LayerCustom,
			Order: 1,
			Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target: domain.TargetRef{
					Kind:    domain.TargetCustomURLTest,
					GroupID: "asia-auto",
				},
			},
		}},
		Final: domain.TargetRef{
			Kind:      domain.TargetSpecificNode,
			ProfileID: "profile-stable-id",
			NodeID:    "node-stable-id",
		},
	}
	compiled, err := CompileRouting(plan, catalog)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out-direct",
		"out-current",
		catalog.CustomURLTestTags["asia-auto"],
		catalog.NodeTags[NodeTargetKey{ProfileID: "profile-stable-id", NodeID: "node-stable-id"}],
	}
	if !reflect.DeepEqual(compiled.OutboundTags, want) {
		t.Fatalf("compiled outbound tags = %#v, want %#v", compiled.OutboundTags, want)
	}
}
