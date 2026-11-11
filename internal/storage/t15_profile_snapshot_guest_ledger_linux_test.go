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

// This uses real Go v18 profile snapshot CAS/history and the unmodified guest
// Python observer. No VM stop, Core startup, restoration or production data.
func TestGuestAuditRealV18OlderProfileSnapshotNodeDrift(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	ctx := context.Background()
	store, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:      "profile-a",
		SourceKind:     "sing-box",
		SourceRevision: "rev-1",
		SourceSHA256:   strings.Repeat("a", 64),
		Nodes:          []profile.SourceNode{testProfileSourceNode("tag-a", "Alpha", 8080)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:      "profile-a",
		SourceKind:     "sing-box",
		SourceRevision: "rev-2",
		SourceSHA256:   strings.Repeat("b", 64),
		Nodes:          []profile.SourceNode{testProfileSourceNode("tag-a", "Alpha renamed", 8081)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	previous, ok, err := store.PreviousProfileSnapshot(ctx, "profile-a")
	if err != nil || !ok || previous.ID != first.Snapshot.ID ||
		second.Snapshot.ID == previous.ID || len(previous.Nodes) != 1 {
		t.Fatalf("profile fixture did not retain current+previous snapshots: %+v %+v %v", previous, second, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	pinned := g.capture(t)
	g.syntheticStopObservation(t)
	report := g.run(t, "verify", pinned, true)
	if report["status"] != "sqlite_subset_consistent_manual_review_only" ||
		report["core_health_verified"] != false ||
		report["archive_hmac_verified"] != false ||
		report["restore_authorized"] != false ||
		report["guest_reboot_verified"] != false ||
		report["physical_power_loss_verified"] != false {
		t.Fatalf("guest profile audit overstated its evidence: %+v", report)
	}
	after, err := os.ReadFile(g.dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("read-only guest profile audit mutated SQLite main file: %v", err)
	}

	// Simulate a rehashed tamper of the previous retained node. Current
	// snapshot/node, Applied/LKG, declaration head and selection remain unchanged.
	forged := []byte(`{"type":"http","tag":"tag-a","server":"127.0.0.1","server_port":9099}`)
	db, err := sql.Open("sqlite", g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.ExecContext(ctx,
		"UPDATE profile_snapshot_nodes SET payload_json=?, payload_sha256=? WHERE snapshot_id=? AND ordinal=0",
		forged, sha256String(forged), first.Snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		t.Fatalf("older node mutation did not affect exactly one row: %d %v", changed, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", pinned, false)
}
