package storage

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInertRestoreRecordCASReadOnlyAcrossRepeatedChecks(t *testing.T) {
	s, fence := newCommittedInertFenceFixture(t)
	ctx := context.Background()
	record, err := s.PrepareInertRestoreRecord(ctx, inertPreparationInput(fence))
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckInertRestoreRecordCAS(ctx, record); err != nil {
		t.Fatalf("complete row and live fence refused: %v", err)
	}
	inspected, err := s.InspectInertRestoreRecords(ctx)
	if err != nil || len(inspected) != 1 {
		t.Fatalf("could not read pending record: %+v %v", inspected, err)
	}
	if err := s.CheckInertRestoreRecordCAS(ctx, inspected[0]); err != nil {
		t.Fatalf("checked persisted row refused: %v", err)
	}
	after, err := s.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) ||
		after.ActiveAttemptID != nil {
		t.Fatalf("repeated write probe mutated apply state: %+v -> %+v %v", before, after, err)
	}
	if _, err := s.PrepareApply(ctx, fence.ConfigRevision,
		[]byte(`{"inbounds":[]}`)); err != nil {
		t.Fatalf("CAS left writer reserved and blocked ordinary apply: %v", err)
	}
	if err := s.CheckInertRestoreRecordCAS(ctx, record); err == nil {
		t.Fatal("active apply journal did not invalidate inert record check")
	}
}

func TestInertRestoreRecordCASRejectsAbandonedChangedAndForgedRows(t *testing.T) {
	for _, kind := range []string{
		"abandoned", "selection_change", "digest_change",
		"forged_record_id", "forged_timestamp", "forged_permission",
	} {
		t.Run(kind, func(t *testing.T) {
			s, fence := newCommittedInertFenceFixture(t)
			ctx := context.Background()
			record, err := s.PrepareInertRestoreRecord(ctx, inertPreparationInput(fence))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "abandoned":
				if err := s.AbandonInertRestoreRecord(ctx,
					record.ID, record.CandidateScope, record.ArchiveSHA256); err != nil {
					t.Fatal(err)
				}
			case "selection_change":
				if _, err := s.SetCurrentSelectionIntent(ctx,
					[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"new"}`)); err != nil {
					t.Fatal(err)
				}
			case "digest_change":
				if _, err := s.db.ExecContext(ctx, `
					UPDATE inert_restore_preparations SET inventory_sha256=?
					WHERE id=?`, strings.Repeat("f", 64), record.ID); err != nil {
					t.Fatal(err)
				}
			case "forged_record_id":
				record.ID++
			case "forged_timestamp":
				record.UpdatedAt = record.UpdatedAt.Add(time.Second)
			case "forged_permission":
				record.RestoreReady = true
			}
			if err := s.CheckInertRestoreRecordCAS(ctx, record); err == nil {
				t.Fatalf("%s accepted stale/journal-forged identity", kind)
			}
		})
	}
}

func TestInertRestoreRecordCASFailureInjectionAlwaysRollsBack(t *testing.T) {
	s, fence := newCommittedInertFenceFixture(t)
	ctx := context.Background()
	record, err := s.PrepareInertRestoreRecord(ctx, inertPreparationInput(fence))
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("fault after writer reservation")
	if err := s.checkInertRestoreRecordCAS(ctx, record,
		func() error { return boom },
	); !errors.Is(err, ErrInertRestorePreparationRefused) {
		t.Fatalf("injected fault accepted: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	err = s.checkInertRestoreRecordCAS(canceled, record, func() error {
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancel under SQLite lock accepted: %v", err)
	}
	after, err := s.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("faulted CAS modified live state: %+v -> %+v %v", before, after, err)
	}
	if err := s.CheckInertRestoreRecordCAS(ctx, record); err != nil {
		t.Fatalf("failed writer transaction kept the lease: %v", err)
	}
}

func TestInertRestoreRecordCASSerializesCompetingJournalWriters(t *testing.T) {
	s, fence := newCommittedInertFenceFixture(t)
	ctx := context.Background()
	record, err := s.PrepareInertRestoreRecord(ctx, inertPreparationInput(fence))
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(ctx, s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.db.ExecContext(ctx, "PRAGMA busy_timeout=100"); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	checked := make(chan error, 1)
	go func() {
		checked <- s.checkInertRestoreRecordCAS(ctx, record, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("writer reservation was not reached")
	}
	timeout, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
	// A different process/SQLite connection must not update the SAME row
	// while the atomic live+record fence holds the SQLite writer slot.
	competing := other.AbandonInertRestoreRecord(timeout,
		record.ID, record.CandidateScope, record.ArchiveSHA256)
	cancel()
	close(release)
	if competing == nil {
		t.Fatal("journal was abandoned while atomic CAS held the writer lock")
	}
	if err := <-checked; err != nil {
		t.Fatalf("CAS did not roll back after competing attempt: %v", err)
	}
	if err := other.AbandonInertRestoreRecord(ctx,
		record.ID, record.CandidateScope, record.ArchiveSHA256); err != nil {
		t.Fatalf("journal writer remained blocked after checked rollback: %v", err)
	}
	if err := s.CheckInertRestoreRecordCAS(ctx, record); !errors.Is(err, ErrInertRestoreRecordChanged) {
		t.Fatalf("abandoned row not detected: %v", err)
	}
}
