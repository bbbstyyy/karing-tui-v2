package profile

import (
	"errors"
	"strings"
	"testing"
)

func TestNodeOverlayValidateAndDefault(t *testing.T) {
	nodeID, err := StableNodeID("profile-a", "proxy-a")
	if err != nil {
		t.Fatal(err)
	}
	rank := int64(12)
	overlay := NodeOverlay{
		ProfileID: "profile-a",
		NodeID:    nodeID,
		Disabled:  true,
		Favorite:  true,
		Alias:     "Work HK",
		SortRank:  &rank,
	}
	if err := overlay.Validate(); err != nil {
		t.Fatal(err)
	}
	if overlay.IsDefault() {
		t.Fatal("non-default overlay reported as default")
	}
	if !(NodeOverlay{ProfileID: "profile-a", NodeID: nodeID}).IsDefault() {
		t.Fatal("empty overlay did not report default")
	}
}

func TestNodeOverlayRejectsInvalidAliasAndRank(t *testing.T) {
	nodeID, err := StableNodeID("profile-a", "proxy-a")
	if err != nil {
		t.Fatal(err)
	}
	negative := int64(-1)
	tooLarge := MaxNodeSortRank + 1
	cases := []NodeOverlay{
		{ProfileID: "", NodeID: nodeID},
		{ProfileID: "profile-a", NodeID: ""},
		{ProfileID: "profile-a", NodeID: nodeID, Alias: " padded "},
		{ProfileID: "profile-a", NodeID: nodeID, Alias: "bad\nalias"},
		{ProfileID: "profile-a", NodeID: nodeID, Alias: strings.Repeat("a", MaxNodeAliasBytes+1)},
		{ProfileID: "profile-a", NodeID: nodeID, SortRank: &negative},
		{ProfileID: "profile-a", NodeID: nodeID, SortRank: &tooLarge},
	}
	for i, overlay := range cases {
		if err := overlay.Validate(); !errors.Is(err, ErrInvalidNodeOverlay) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}
