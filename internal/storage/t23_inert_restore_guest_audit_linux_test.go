//go:build linux

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
)

// A real, disposable Go Store v18 schema and production inert-restore
// preparation API are observed by the original guest-side Python reader.
// This DOES NOT authenticate a ciphertext file, lease or a reboot; all
// candidates/hashes here are synthetic temporary test metadata only.
func newGuestInertRestoreRecord(t *testing.T, g guestBridge) InertRestorePreparation {
	t.Helper()
	ctx := context.Background()
	store, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	decl, err := store.CommitDeclaration(ctx, 0,
		[]byte(`{"schema_version":1,"source":"inert-restore-guest-audit"}`),
		"test:t23-readonly-contract")
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"inbounds":[],"route":{"rules":[]}}`)
	manifest := []byte(fmt.Sprintf(
		`{"schema_id":"test","config_sha256":%q,"declaration_revision":%d,"declaration_sha256":%q}`,
		sha256String(config), decl.Revision, decl.SHA256))
	attempt, err := store.PrepareApplyWithMetadata(ctx, 0, config,
		manifest, []byte(`[]`))
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
	if _, err := store.SetCurrentSelectionIntent(ctx,
		[]byte(`{"kind":"specific_node","profile_id":"synthetic","node_id":"isolated"}`)); err != nil {
		t.Fatal(err)
	}
	fence, err := store.ReadInertRestoreFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.PrepareInertRestoreRecord(ctx, InertRestorePreparationInput{
		CandidateScope:  ".ktui-restore-v1-ABC12345",
		ArchiveSHA256:   strings.Repeat("a", 64),
		InventorySHA256: strings.Repeat("b", 64),
		ArchiveBytes:    42_000,
		Baseline:        fence,
	})
	if err != nil || !record.RequiresRevalidation || record.RestoreSupported ||
		record.RestoreReady || record.Phase != InertRestorePrepared {
		t.Fatalf("synthetic inert journal unexpectedly authorizes a restore: %+v %v", record, err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil || snapshot.ActiveAttemptID != nil || snapshot.RecoveryRequired ||
		snapshot.CoreDesiredState != CoreDesiredStopped {
		t.Fatalf("inert restore changed active Core state: %+v %v", snapshot, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestGuestAuditRealV18InertRestoreJournalMetadataPin(t *testing.T) {
	g := newGuestBridge(t)
	record := newGuestInertRestoreRecord(t, g)
	before, err := os.ReadFile(g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sha := g.capture(t)
	g.syntheticStopObservation(t)
	report := g.run(t, "verify", sha, true)
	if report["status"] != "sqlite_subset_consistent_manual_review_only" ||
		report["guest_reboot_verified"] != false ||
		report["archive_hmac_verified"] != false ||
		report["restore_authorized"] != false ||
		report["metadata_deletion_authorized"] != false {
		t.Fatalf("guest gave extra recovery authority to inert journal: %+v", report)
	}
	after, err := os.ReadFile(g.dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("guest read-only audit mutated real v18 SQLite: %v", err)
	}

	// Mutate a VALID SHA field with test-only direct SQL. Pending count,
	// scope, active state, Applied/LKG and last archived apply do not
	// change; only the newly introduced full inert ledger can refuse it.
	db, err := sql.Open("sqlite", g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.ExecContext(context.Background(),
		"UPDATE inert_restore_preparations SET inventory_sha256 = ? WHERE id = ?",
		strings.Repeat("c", 64), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		t.Fatalf("synthetic inert metadata mutation was not applied once: %d %v", n, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", sha, false)
}

func TestGuestAuditRealV18InertAbandonmentInvalidatesPinnedWitness(t *testing.T) {
	g := newGuestBridge(t)
	record := newGuestInertRestoreRecord(t, g)
	sha := g.capture(t)
	g.syntheticStopObservation(t)
	g.run(t, "verify", sha, true)

	ctx := context.Background()
	store, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AbandonInertRestoreRecord(ctx,
		record.ID, record.CandidateScope, record.ArchiveSHA256); err != nil {
		t.Fatal(err)
	}
	rows, err := store.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 1 ||
		rows[0].Phase != InertRestoreAbandoned ||
		rows[0].RestoreReady || rows[0].RestoreSupported {
		t.Fatalf("inert abandoned record is not manual review only: %+v %v", rows, err)
	}
	after, err := store.Snapshot(ctx)
	if err != nil || after.Revision != before.Revision ||
		after.ActiveAttemptID != nil || after.RecoveryRequired ||
		after.AppliedGenerationID == nil || before.AppliedGenerationID == nil ||
		*after.AppliedGenerationID != *before.AppliedGenerationID {
		t.Fatalf("abandon changed live applied state: %+v -> %+v %v", before, after, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// The old externally pinned baseline is stale; an abandoned record is
	// NOT a successful restore, not even if only its inert metadata changed.
	g.run(t, "verify", sha, false)
}
