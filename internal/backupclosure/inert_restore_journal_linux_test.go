//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestInertPreparationJournalCrossRestartStillNeverRestorable(t *testing.T) {
	f, candidate, key := createInertDryRunFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dryRun, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
	if err != nil {
		t.Fatal(err)
	}
	record, err := PrepareInertRestoreCandidateRecord(ctx, f.store, candidate, key, dryRun)
	if err != nil || record.Phase != storage.InertRestorePrepared ||
		!record.RequiresRevalidation || record.RestoreReady || record.RestoreSupported ||
		record.ArchiveSHA256 != dryRun.ArchiveSHA256 {
		t.Fatalf("persisted candidate is not inert: %+v %v", record, err)
	}
	if _, err := PrepareInertRestoreCandidateRecord(ctx, f.store, candidate, key, dryRun);
		!errors.Is(err, storage.ErrInertRestorePreparationBusy) {
		t.Fatalf("duplicate preparation was persisted: %v", err)
	}
	directory := candidate.Directory()
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := ReopenInertRestoreCandidate(ctx, directory, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	freshStore, err := storage.Open(ctx, f.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer freshStore.Close()
	if err := RevalidateInertRestoreCandidateRecord(ctx, freshStore, reopened, key, record.ID); err != nil {
		t.Fatalf("post-restart complete revalidation failed: %v", err)
	}
	if err := RevalidateInertRestoreCandidateRecord(ctx, freshStore, reopened,
		[32]byte{}, record.ID); !errors.Is(err, ErrInertRestoreJournalRefused) {
		t.Fatalf("missing backup key was accepted: %v", err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) ||
		after.ActiveAttemptID != nil || after.RecoveryRequired {
		t.Fatalf("journal overwrote or activated current configuration: %+v -> %+v %v", before, after, err)
	}
	if err := freshStore.AbandonInertRestoreRecord(ctx, record.ID,
		record.CandidateScope, record.ArchiveSHA256); err != nil {
		t.Fatal(err)
	}
	if err := RevalidateInertRestoreCandidateRecord(ctx, freshStore, reopened, key, record.ID);
		!errors.Is(err, ErrInertRestoreJournalRefused) {
		t.Fatalf("abandoned record was still treated as pending: %v", err)
	}
	if err := reopened.Discard(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit encrypted scope discard failed: %v", err)
	}
}

func TestInertPreparationJournalRefusesStaleCandidateAndLiveDrift(t *testing.T) {
	for _, kind := range []string{"selection", "wrong_scope", "tamper_ciphertext"} {
		t.Run(kind, func(t *testing.T) {
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
			switch kind {
			case "selection":
				if _, err := f.store.SetCurrentSelectionIntent(ctx,
					[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`)); err != nil {
					t.Fatal(err)
				}
			case "wrong_scope":
				original := record
				record.CandidateScope = ".ktui-restore-v1-OTHER99"
				if err := f.store.AbandonInertRestoreRecord(ctx,
					original.ID, record.CandidateScope, original.ArchiveSHA256);
					!errors.Is(err, storage.ErrInertRestorePreparationRefused) {
					t.Fatalf("wrong scope was allowed to abandon record: %v", err)
				}
			case "tamper_ciphertext":
				file, err := os.OpenFile(filepath.Join(candidate.Directory(),
					"candidate.ktbackup"), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				var payload [1]byte
				if _, err := file.ReadAt(payload[:], int64(sealedArchiveHeaderBytes+11)); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				payload[0] ^= 0x44
				if _, err := file.WriteAt(payload[:], int64(sealedArchiveHeaderBytes+11)); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "wrong_scope" {
				if err := RevalidateInertRestoreCandidateRecord(ctx, f.store,
					candidate, key, record.ID);
					!errors.Is(err, ErrInertRestoreJournalRefused) {
					t.Fatalf("stale candidate/live state accepted: %v", err)
				}
			}
			if err := f.store.AbandonInertRestoreRecord(ctx,
				record.ID, ".ktui-restore-v1-OTHER99", record.ArchiveSHA256);
				!errors.Is(err, storage.ErrInertRestorePreparationRefused) {
				t.Fatalf("forged scope cancelled record: %v", err)
			}
			if err := f.store.AbandonInertRestoreRecord(ctx,
				record.ID, filepath.Base(candidate.Directory()),
				record.ArchiveSHA256); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInertPreparationJournalNeverAcceptsForgedDryRun(t *testing.T) {
	f, candidate, key := createInertDryRunFixture(t)
	ctx := context.Background()
	dryRun, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
	if err != nil {
		t.Fatal(err)
	}
	claims := dryRun
	claims.RestoreReady = true
	if _, err := PrepareInertRestoreCandidateRecord(ctx, f.store, candidate, key, claims);
		!errors.Is(err, ErrInertRestoreJournalRefused) {
		t.Fatalf("forged restore permission entered durable log: %v", err)
	}
	claims = dryRun
	claims.ArchiveSHA256 = "not a digest"
	if _, err := PrepareInertRestoreCandidateRecord(ctx, f.store, candidate, key, claims);
		!errors.Is(err, ErrInertRestoreJournalRefused) {
		t.Fatalf("forged archive hash entered durable log: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := PrepareInertRestoreCandidateRecord(canceled, f.store, candidate, key, dryRun); err == nil {
		t.Fatal("canceled record commit succeeded")
	}
	rows, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("forged dry run persisted journal: %+v %v", rows, err)
	}
}
