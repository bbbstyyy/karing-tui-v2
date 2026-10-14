//go:build linux

package backupclosure

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// The writer must refuse an archive that its own authenticated reader
// necessarily rejects. The journal is checked in the immutable SQLite copy,
// not by racing a separate read of the live database.
func TestBuildClosureRefusesPendingInertRestoreBeforeSeal(t *testing.T) {
	f, candidate, key := createInertDryRunFixture(t)
	ctx := context.Background()
	dryRun, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
	if err != nil {
		t.Fatal(err)
	}
	record, err := PrepareInertRestoreCandidateRecord(ctx, f.store, candidate, key, dryRun)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	closure, err := Build(ctx, f.store, f.stateRoot, f.parent)
	if closure != nil || !errors.Is(err, ErrUnsafeClosure) {
		t.Fatalf("pending journal generated an unusable backup closure: %v %v", closure, err)
	}
	requireNoBackupScopes(t, f)
	if receipt, err := candidate.Verify(ctx, key); err != nil || receipt.RestoreReady {
		t.Fatalf("refused backup altered encrypted recovery candidate: %+v %v", receipt, err)
	}
	rows, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 1 || rows[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("refused backup changed durable inert journal: %+v %v", rows, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("refused backup changed applied state: %+v -> %+v %v", before, after, err)
	}

	// Explicitly abandoning the old inert record permits an independently
	// authenticated backup again; abandonment does not delete ciphertext.
	if err := f.store.AbandonInertRestoreRecord(ctx,
		record.ID, record.CandidateScope, record.ArchiveSHA256); err != nil {
		t.Fatal(err)
	}
	closure, err = Build(ctx, f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatalf("abandoned inert record blocked safe archive: %v", err)
	}
	defer closure.Close()
	// createInertDryRunFixture already created the owned private archive parent.
	dest := filepath.Join(f.stateRoot, "sealed-archives", "abandoned-history.ktbackup")
	if _, err := closure.SealInertArchive(ctx, dest, key); err != nil {
		t.Fatal(err)
	}
	report, err := PreflightInertArchive(ctx, dest, key, nil)
	if err != nil || !report.SchemaCatalogVerified || !report.SQLiteLogicalVerified ||
		report.RestoreReady || report.RestoreSupported {
		t.Fatalf("writer-produced archived journal fails its own reader: %+v %v", report, err)
	}
}

func TestBuildClosureRefusesCorruptAbandonedJournal(t *testing.T) {
	f, candidate, key := createInertDryRunFixture(t)
	ctx := context.Background()
	dryRun, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
	if err != nil {
		t.Fatal(err)
	}
	record, err := PrepareInertRestoreCandidateRecord(ctx, f.store, candidate, key, dryRun)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.AbandonInertRestoreRecord(ctx,
		record.ID, record.CandidateScope, record.ArchiveSHA256); err != nil {
		t.Fatal(err)
	}
	// The row's schema is valid and its status abandoned, but its baseline
	// digest no longer authenticates the stored bytes. A WHERE-phase-only
	// filter would incorrectly allow the writer to create an invalid archive.
	db, err := sql.Open("sqlite", f.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx,
		"UPDATE inert_restore_preparations SET baseline_sha256=? WHERE id=?",
		strings.Repeat("a", 64), record.ID); err != nil {
		t.Fatal(err)
	}
	closure, err := Build(ctx, f.store, f.stateRoot, f.parent)
	if closure != nil || !errors.Is(err, ErrUnsafeClosure) {
		t.Fatalf("invalid archived journal was sealed: %v %v", closure, err)
	}
	requireNoBackupScopes(t, f)
}
