package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func inertPreparationInput(fence InertRestoreFence) InertRestorePreparationInput {
	return InertRestorePreparationInput{
		CandidateScope:  ".ktui-restore-v1-ABC12345",
		ArchiveSHA256:   strings.Repeat("a", 64),
		InventorySHA256: strings.Repeat("b", 64),
		ArchiveBytes:    42_000,
		Baseline:        fence,
	}
}

func TestV17ToV18MigrationPreservesDatabaseAndAttestsBothSchemas(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "historical-v17.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path}
	if err := s.configure(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateThrough(ctx, 17); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != 17 {
		t.Fatalf("failed to create authentic v17 reference: %d %v", version, err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArchivedSchemaAndDomains(ctx, conn, 17); err != nil {
		t.Fatalf("v17 schema was incorrectly rejected: %v", err)
	}
	if _, err := VerifyArchivedSchemaAndDomains(ctx, conn, 18); !errors.Is(err, ErrArchiveDomainInvalid) {
		t.Fatal("v17 schema was silently treated as v18")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	if err := migrated.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != 18 {
		t.Fatalf("v17 upgrade did not reach v18: %d %v", version, err)
	}
	var rows int
	if err := migrated.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM inert_restore_preparations`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("migration inserted a fake restore record: %d %v", rows, err)
	}
	conn, err = migrated.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := VerifyArchivedSchemaAndDomains(ctx, conn, 18); err != nil {
		t.Fatalf("v18 reference differs from migrated original: %v", err)
	}
}

func TestInertRestorePreparationDurableButNeverRestorable(t *testing.T) {
	ctx := context.Background()
	s, fence := newCommittedInertFenceFixture(t)
	input := inertPreparationInput(fence)
	before, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	record, err := s.PrepareInertRestoreRecord(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if record.ID <= 0 || record.Phase != InertRestorePrepared ||
		record.RestoreReady || record.RestoreSupported || !record.RequiresRevalidation ||
		record.ArchiveSHA256 != input.ArchiveSHA256 ||
		record.Baseline != fence {
		t.Fatalf("persistent inert journal has restore authority or corrupt metadata: %+v", record)
	}
	after, err := s.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) ||
		after.ActiveAttemptID != nil {
		t.Fatalf("inert journal changed applied/LKG configuration: %+v -> %+v %v", before, after, err)
	}
	if _, err := s.PrepareInertRestoreRecord(ctx, input); !errors.Is(err, ErrInertRestorePreparationBusy) {
		t.Fatalf("duplicate pending restoration journal accepted: %v", err)
	}
	// A second independently opened SQLite connection represents a daemon
	// restart: no forgotten PID or old lease can authorize the pending row.
	reopened, err := Open(ctx, s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rows, err := reopened.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 1 ||
		rows[0].Phase != InertRestorePrepared ||
		!rows[0].RequiresRevalidation ||
		rows[0].RestoreReady || rows[0].RestoreSupported ||
		rows[0].ID != record.ID || rows[0].Baseline != fence {
		t.Fatalf("reopened journal was not inert: %+v %v", rows, err)
	}
	if err := reopened.AbandonInertRestoreRecord(ctx, record.ID, input.CandidateScope, strings.Repeat("f", 64)); !errors.Is(err, ErrInertRestorePreparationRefused) {
		t.Fatalf("wrong ciphertext digest abandoned a preparation: %v", err)
	}
	if err := reopened.AbandonInertRestoreRecord(ctx, record.ID, input.CandidateScope, input.ArchiveSHA256); err != nil {
		t.Fatal(err)
	}
	rows, err = s.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 1 || rows[0].Phase != InertRestoreAbandoned ||
		!rows[0].RequiresRevalidation || rows[0].RestoreReady {
		t.Fatalf("abandon removed record or created restore rights: %+v %v", rows, err)
	}
	if err := s.AbandonInertRestoreRecord(ctx, record.ID, input.CandidateScope, input.ArchiveSHA256); !errors.Is(err, ErrInertRestorePreparationRefused) {
		t.Fatal("abandoned record transitioned twice")
	}
	if _, err := s.PrepareInertRestoreRecord(ctx, input); err != nil {
		t.Fatalf("abandoned record did not free the single pending slot: %v", err)
	}
}

func TestInertRestorePreparationRollsBackInjectedAndCanceledInserts(t *testing.T) {
	s, fence := newCommittedInertFenceFixture(t)
	input := inertPreparationInput(fence)
	ctx := context.Background()
	var injected = errors.New("fault injection in transaction")
	if record, err := s.prepareInertRestoreRecord(ctx, input, func() error { return injected }); !errors.Is(err, ErrInertRestorePreparationRefused) || record.ID != 0 {
		t.Fatalf("injected error returned a durable record: %+v %v", record, err)
	}
	rows, err := s.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("injected rollback leaked a journal row: %+v %v", rows, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	record, err := s.prepareInertRestoreRecord(canceled, input, func() error {
		cancel()
		return nil
	})
	if err == nil || record.ID != 0 {
		t.Fatalf("context cancellation committed an inert record: %+v %v", record, err)
	}
	rows, err = s.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("cancel leaked pending row: %+v %v", rows, err)
	}
	if _, err := s.PrepareInertRestoreRecord(ctx, input); err != nil {
		t.Fatalf("failed transaction held writer lock: %v", err)
	}
}

func TestInertRestorePreparationRejectsStaleOrForgedInputs(t *testing.T) {
	s, fence := newCommittedInertFenceFixture(t)
	for _, kind := range []string{"traversal", "bad_digest", "empty_fence", "oversize"} {
		input := inertPreparationInput(fence)
		switch kind {
		case "traversal":
			input.CandidateScope = "../unsafe"
		case "bad_digest":
			input.ArchiveSHA256 = "not sha"
		case "empty_fence":
			input.Baseline = InertRestoreFence{}
		case "oversize":
			input.ArchiveBytes = maxInertRestoreArchiveBytes + 1
		}
		if _, err := s.PrepareInertRestoreRecord(context.Background(), input); !errors.Is(err, ErrInertRestorePreparationRefused) {
			t.Fatalf("unsafe input %s accepted: %v", kind, err)
		}
	}
	if _, err := s.SetCurrentSelectionIntent(context.Background(),
		[]byte(`{"kind":"specific_node","profile_id":"a","node_id":"b"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareInertRestoreRecord(context.Background(), inertPreparationInput(fence)); !errors.Is(err, ErrInertRestoreFenceChanged) {
		t.Fatalf("stale CAS record was accepted: %v", err)
	}
	rows, err := s.InspectInertRestoreRecords(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatalf("unsafe attempts persisted rows: %+v %v", rows, err)
	}
}

func TestInertRestorePreparationArchiveAuditRejectsPendingAndCorruptRows(t *testing.T) {
	s, fence := newCommittedInertFenceFixture(t)
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyArchivedSchemaAndDomains(ctx, conn, 18)
	if err != nil {
		t.Fatalf("valid empty journal was refused: %v", err)
	}
	conn.Close()
	input := inertPreparationInput(fence)
	row, err := s.PrepareInertRestoreRecord(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	conn, err = s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyArchivedSchemaAndDomains(ctx, conn, 18)
	conn.Close()
	if !errors.Is(err, ErrArchiveDomainInvalid) {
		t.Fatalf("backup audit treated pending restore as restorable: %v", err)
	}
	if err := s.AbandonInertRestoreRecord(ctx, row.ID, row.CandidateScope, row.ArchiveSHA256); err != nil {
		t.Fatal(err)
	}
	conn, err = s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyArchivedSchemaAndDomains(ctx, conn, 18)
	conn.Close()
	if err != nil {
		t.Fatalf("an inert abandoned journal broke schema domain audit: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE inert_restore_preparations SET baseline_sha256=? WHERE id=?`,
		strings.Repeat("f", 64), row.ID); err != nil {
		t.Fatal(err)
	}
	if records, err := s.InspectInertRestoreRecords(ctx); !errors.Is(err, ErrInertRestorePreparationRefused) || records != nil {
		t.Fatalf("tampered journal returned partial records: %+v %v", records, err)
	}
}
