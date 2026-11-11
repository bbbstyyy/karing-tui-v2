package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

func TestProfileNodeOverlayCASSurvivesSnapshotRefreshAndRemoval(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	first, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("a", 64),
		Nodes:        []profile.SourceNode{testProfileSourceNode("proxy-a", "Proxy A", 8080)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	nodeID := first.Snapshot.Nodes[0].Identity.NodeID
	rank := int64(7)
	created, err := store.CommitProfileNodeOverlay(ctx, 0, profile.NodeOverlay{
		ProfileID: "profile-a",
		NodeID:    nodeID,
		Disabled:  true,
		Favorite:  true,
		Alias:     "Pinned Proxy",
		SortRank:  &rank,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 ||
		!created.Overlay.Disabled ||
		!created.Overlay.Favorite ||
		created.Overlay.Alias != "Pinned Proxy" ||
		created.Overlay.SortRank == nil ||
		*created.Overlay.SortRank != rank {
		t.Fatalf("created overlay = %+v", created)
	}
	if _, err := store.CommitProfileNodeOverlay(ctx, 0, created.Overlay); !errors.Is(err, ErrProfileNodeOverlayRevisionConflict) {
		t.Fatalf("stale overlay CAS error = %v", err)
	}

	second, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("b", 64),
		Nodes:        []profile.SourceNode{testProfileSourceNode("proxy-a", "Proxy A Renamed", 9090)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Snapshot.Nodes[0].Identity.NodeID != nodeID {
		t.Fatalf("snapshot refresh changed node ID: %q -> %q", nodeID, second.Snapshot.Nodes[0].Identity.NodeID)
	}
	preserved, err := store.ProfileNodeOverlay(ctx, "profile-a", nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if preserved.Revision != created.Revision ||
		preserved.Overlay.Alias != created.Overlay.Alias ||
		!preserved.Overlay.Disabled ||
		!preserved.Overlay.Favorite {
		t.Fatalf("snapshot refresh changed overlay: %+v", preserved)
	}

	cleared, err := store.CommitProfileNodeOverlay(ctx, preserved.Revision, profile.NodeOverlay{
		ProfileID: "profile-a",
		NodeID:    nodeID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Revision != preserved.Revision+1 || !cleared.Overlay.IsDefault() {
		t.Fatalf("cleared overlay = %+v", cleared)
	}

	third, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("c", 64),
		Nodes:        []profile.SourceNode{testProfileSourceNode("proxy-b", "Proxy B", 1080)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if third.Snapshot.Nodes[0].Identity.NodeID == nodeID {
		t.Fatalf("changed source key reused removed node ID %q", nodeID)
	}

	dormant, err := store.ProfileNodeOverlay(ctx, "profile-a", nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if dormant.Revision != cleared.Revision || !dormant.Overlay.IsDefault() {
		t.Fatalf("removed node overlay was discarded: %+v", dormant)
	}
	if _, err := store.CommitProfileNodeOverlay(ctx, dormant.Revision, profile.NodeOverlay{
		ProfileID: "profile-a",
		NodeID:    nodeID,
		Favorite:  true,
	}); !errors.Is(err, ErrProfileNodeOverlayNodeUnavailable) {
		t.Fatalf("editing removed node overlay error = %v", err)
	}
}

func TestProfileNodeOverlaysListIsStable(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	commit, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("d", 64),
		Nodes: []profile.SourceNode{
			testProfileSourceNode("proxy-b", "Proxy B", 8081),
			testProfileSourceNode("proxy-a", "Proxy A", 8080),
		},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range commit.Snapshot.Nodes {
		if _, err := store.CommitProfileNodeOverlay(ctx, 0, profile.NodeOverlay{
			ProfileID: "profile-a",
			NodeID:    node.Identity.NodeID,
			Favorite:  true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	items, err := store.ProfileNodeOverlays(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Overlay.NodeID >= items[1].Overlay.NodeID {
		t.Fatalf("overlay ordering = %+v", items)
	}
}

func TestProfileNodeOverlayRequiresCurrentAcceptedNode(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	nodeID, err := profile.StableNodeID("profile-a", "proxy-a")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CommitProfileNodeOverlay(ctx, 0, profile.NodeOverlay{
		ProfileID: "profile-a",
		NodeID:    nodeID,
		Disabled:  true,
	})
	if !errors.Is(err, ErrProfileNodeOverlayNodeUnavailable) {
		t.Fatalf("overlay without accepted node error = %v", err)
	}
	if _, err := store.ProfileNodeOverlay(ctx, "profile-a", nodeID); !errors.Is(err, ErrProfileNodeOverlayNotFound) {
		t.Fatalf("missing overlay read error = %v", err)
	}
}

func TestProfileNodeOverlayLimitFailsClosed(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	commit, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("e", 64),
		Nodes:        []profile.SourceNode{testProfileSourceNode("current-node", "Current", 8080)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	currentNodeID := commit.Snapshot.Nodes[0].Identity.NodeID
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := store.db.ExecContext(ctx, `
		WITH RECURSIVE seq(x) AS (
			SELECT 1
			UNION ALL
			SELECT x + 1 FROM seq WHERE x < ?
		)
		INSERT INTO profile_node_overlays(
			profile_id,
			node_id,
			revision,
			disabled,
			favorite,
			alias,
			sort_rank,
			updated_at
		)
		SELECT
			'profile-a',
			printf('historical-node-%05d', x),
			1,
			0,
			0,
			'',
			NULL,
			?
		FROM seq
	`, MaxProfileNodeOverlaysPerProfile, now); err != nil {
		t.Fatal(err)
	}

	_, err = store.CommitProfileNodeOverlay(ctx, 0, profile.NodeOverlay{
		ProfileID: "profile-a",
		NodeID:    currentNodeID,
		Disabled:  true,
	})
	if !errors.Is(err, ErrProfileNodeOverlayLimit) {
		t.Fatalf("overlay limit error = %v", err)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM profile_node_overlays WHERE profile_id = ?
	`, "profile-a").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != MaxProfileNodeOverlaysPerProfile {
		t.Fatalf("overlay count = %d, want %d", count, MaxProfileNodeOverlaysPerProfile)
	}
}
