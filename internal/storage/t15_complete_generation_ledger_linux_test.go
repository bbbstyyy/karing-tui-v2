//go:build linux

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"testing"
)

// A retained, non-current generation can be invisible to checks of only
// Applied/LKG, latest apply, and the archived journal metadata. This test
// uses only disposable, owner-private real Go v18 SQLite fixtures.
func TestGuestAuditRealV18OlderRetainedGenerationLedger(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	ctx := context.Background()
	store, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for index, label := range []string{"retained-one", "newest-confirmed"} {
		attempt, err := store.PrepareApply(ctx, uint64(index+1),
			[]byte("{\"inbounds\":[],\"lab\":\""+label+"\"}"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.BeginActivation(ctx, attempt.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.BeginVerification(ctx, attempt.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.CommitApplied(ctx, attempt.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil || snapshot.Revision != 3 ||
		snapshot.AppliedGenerationID == nil ||
		snapshot.LastKnownGoodGenerationID == nil ||
		*snapshot.AppliedGenerationID == 1 ||
		*snapshot.LastKnownGoodGenerationID == 1 {
		t.Fatalf("historical generation is still active: %+v %v", snapshot, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	sqlite, err := sql.Open("sqlite", g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := sqlite.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM generations WHERE id = 1").Scan(&count); err != nil ||
		count != 1 {
		t.Fatalf("Go retention unexpectedly pruned oldest fixture: %d %v", count, err)
	}
	if err := sqlite.Close(); err != nil {
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
		report["guest_reboot_verified"] != false ||
		report["physical_power_loss_verified"] != false ||
		report["archive_hmac_verified"] != false ||
		report["restore_authorized"] != false ||
		report["metadata_deletion_authorized"] != false {
		t.Fatalf("retained generation check overstated evidence: %+v", report)
	}
	after, err := os.ReadFile(g.dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("read-only guest generation audit mutated SQLite: %v", err)
	}

	// The original capture included generation id=1, which is neither
	// Applied nor LKG nor the latest candidate. Mutate and REHASH it,
	// leaving its journal archive identity and all current rows unchanged.
	forged := []byte(`{"inbounds":[],"lab":"older-retained-rehashed"} `)
	sqlite, err = sql.Open("sqlite", g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := sqlite.ExecContext(ctx,
		"UPDATE generations SET config_json=?, config_sha256=? WHERE id = 1",
		forged, sha256String(forged))
	if err != nil {
		t.Fatal(err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("failed to alter only retained old row: %d %v", affected, err)
	}
	if err := sqlite.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", pinned, false)
}
