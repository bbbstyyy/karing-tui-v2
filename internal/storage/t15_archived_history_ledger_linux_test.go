//go:build linux

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"testing"
)

// This is a disposable, non-root, real Go v18 cross-language fixture.
// Older completed apply_history rows are often no longer backed by a live
// generation BLOB after retention pruning: their full archived metadata
// must remain digest-pinned rather than trusting only the latest record.
func TestGuestAuditRealV18DetectsOlderArchivedHistoryDrift(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	ctx := context.Background()
	store, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, payload := range []string{
		"two-original-confirmed",
		"three-original-confirmed",
	} {
		a, err := store.PrepareApply(ctx, uint64(i+1), []byte(
			"{\"inbounds\":[],\"lab\":\""+payload+"\"}"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.BeginActivation(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.BeginVerification(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.CommitApplied(ctx, a.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sha := g.capture(t)
	g.syntheticStopObservation(t)
	report := g.run(t, "verify", sha, true)
	if report["status"] != "sqlite_subset_consistent_manual_review_only" ||
		report["restore_authorized"] != false ||
		report["physical_power_loss_verified"] != false {
		t.Fatalf("read-only archival audit claimed unsafe recovery: %+v", report)
	}
	after, err := os.ReadFile(g.dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("Python archive history read modified real SQLite file: %v", err)
	}

	// Test-only direct SQL mutation, never a production operation: change
	// the OLDEST archived row's redacted error, leaving latest archive,
	// Applied/LKG, snapshot revision, and row count unchanged.
	direct, err := sql.Open("sqlite", g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := direct.ExecContext(ctx,
		"UPDATE apply_history SET error = ? WHERE id = (SELECT MIN(id) FROM apply_history)",
		"disposable older-row drift")
	if err != nil {
		t.Fatal(err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("test failed to mutate one older archive row: %d %v", affected, err)
	}
	if err := direct.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", sha, false)
}
