package storage

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

func TestCurrentProfileNodePage(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()
	none, err := store.CurrentProfileNodePage(ctx, "profile-a", 0, 1)
	if err != nil || none.SnapshotID != nil || none.Total != 0 {
		t.Fatalf("empty page: %+v %v", none, err)
	}
	commit, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID: "profile-a", SourceKind: "sing-box", SourceSHA256: strings.Repeat("a", 64),
		Nodes: []profile.SourceNode{
			testProfileSourceNode("a", "Alpha", 8080),
			testProfileSourceNode("b", "Bravo", 8081),
			testProfileSourceNode("c", "Charlie", 8082),
		},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	nodeID := commit.Snapshot.Nodes[1].Identity.NodeID
	rank := int64(3)
	if _, err := store.CommitProfileNodeOverlay(ctx, 0, profile.NodeOverlay{
		ProfileID: "profile-a", NodeID: nodeID, Disabled: true, Alias: "Pinned", SortRank: &rank,
	}); err != nil {
		t.Fatal(err)
	}
	page, err := store.CurrentProfileNodePage(ctx, "profile-a", 1, 1)
	if err != nil || page.Total != 3 || page.SnapshotID == nil ||
		*page.SnapshotID != commit.Snapshot.ID || len(page.Nodes) != 1 ||
		page.Nodes[0].NodeID != nodeID || page.Nodes[0].Alias != "Pinned" ||
		!page.Nodes[0].Disabled || page.Nodes[0].OverlayRevision != 1 {
		t.Fatalf("paged read: %+v %v", page, err)
	}
	tail, err := store.CurrentProfileNodePage(ctx, "profile-a", 2, 2)
	if err != nil || len(tail.Nodes) != 1 || tail.Nodes[0].SourceName != "Charlie" {
		t.Fatalf("tail page: %+v %v", tail, err)
	}
	for _, p := range [][2]int{{-1, 1}, {0, 0}, {0, 201}, {1000001, 1}} {
		_, err := store.CurrentProfileNodePage(ctx, "profile-a", p[0], p[1])
		if !errors.Is(err, ErrInvalidProfileNodePage) {
			t.Fatalf("page %v: %v", p, err)
		}
	}
}
