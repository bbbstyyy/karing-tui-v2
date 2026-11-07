//go:build linux

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

// ADR 0140: real Go v18 Store CAS/persisted dormant overlay against the
// original read-only Python guest audit. No VM stop, Core or production data.
func TestGuestAuditRealV18DormantNodeOverlayDrift(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	ctx := context.Background()
	store, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("a", 64),
		Nodes:        []profile.SourceNode{testProfileSourceNode("retired-key", "Old Node", 8080)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retiredNodeID := first.Snapshot.Nodes[0].Identity.NodeID
	rank := int64(42)
	retired, err := store.CommitProfileNodeOverlay(ctx, 0, profile.NodeOverlay{
		ProfileID: "profile-a",
		NodeID:    retiredNodeID,
		Disabled:  true,
		Favorite:  true,
		Alias:     "Dormant private user alias",
		SortRank:  &rank,
	})
	if err != nil || retired.Revision != 1 {
		t.Fatalf("failed to commit real user overlay: %+v %v", retired, err)
	}
	second, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("b", 64),
		Nodes:        []profile.SourceNode{testProfileSourceNode("new-key", "New Node", 8081)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	activeNodeID := second.Snapshot.Nodes[0].Identity.NodeID
	if activeNodeID == retiredNodeID {
		t.Fatal("changed source key improperly reused retired node identity")
	}
	if _, err := store.CommitProfileNodeOverlay(ctx, 0, profile.NodeOverlay{
		ProfileID: "profile-a",
		NodeID:    activeNodeID,
		Favorite:  true,
		Alias:     "Current node alias",
	}); err != nil {
		t.Fatal(err)
	}
	dormant, err := store.ProfileNodeOverlay(ctx, "profile-a", retiredNodeID)
	if err != nil || dormant.Revision != retired.Revision ||
		dormant.Overlay.Alias != retired.Overlay.Alias ||
		!dormant.Overlay.Disabled {
		t.Fatalf("removed node overlay was not retained as dormant: %+v %v", dormant, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	originalSHA := g.capture(t)
	g.syntheticStopObservation(t)
	verified := g.run(t, "verify", originalSHA, true)
	if verified["status"] != "sqlite_subset_consistent_manual_review_only" ||
		verified["restore_authorized"] != false ||
		verified["metadata_deletion_authorized"] != false ||
		verified["archive_hmac_verified"] != false ||
		verified["core_health_verified"] != false ||
		verified["guest_reboot_verified"] != false ||
		verified["physical_power_loss_verified"] != false {
		t.Fatalf("dormant overlay audit claimed unproven recovery authority: %+v", verified)
	}
	after, err := os.ReadFile(g.dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("guest overlay audit modified real Go SQLite main bytes: %v", err)
	}

	// Corrupt a detached/dormant row without incrementing its revision.
	// Applied/LKG, current snapshot/node/overlay and declarations remain
	// untouched, so only a COMPLETE retained-overlay ledger can detect it.
	db, err := sql.Open("sqlite", g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.ExecContext(ctx,
		"UPDATE profile_node_overlays SET disabled=0, favorite=0, alias=? "+
			"WHERE profile_id=? AND node_id=?",
		"quietly changed while revision stayed one", "profile-a", retiredNodeID)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		t.Fatalf("tampering did not affect exactly one dormant overlay: %d %v", changed, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", originalSHA, false)
}
