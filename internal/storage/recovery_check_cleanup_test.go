package storage

import (
	"context"
	"errors"
	"testing"
)

func TestReclaimAbortedHistoricalCheckArchivesFailureAndPreservesFallback(t *testing.T) {
	store, binding, original, applied := historicalRestoreFixture(t)
	ctx := context.Background()
	before, err := store.RetentionStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := store.PrepareHistoricalRestore(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AbortPrepared(ctx, candidate.ID, HistoricalCheckAbortReason); err != nil {
		t.Fatal(err)
	}
	if err := store.ReclaimAbortedHistoricalCheck(ctx, candidate.ID); err != nil {
		t.Fatal(err)
	}
	after, err := store.RetentionStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.LiveGenerationBytes != before.LiveGenerationBytes ||
		after.LiveGenerationCount != before.LiveGenerationCount || after.ActiveAttemptCount != 0 {
		t.Fatalf("historical dry-run leaked generation quota: before=%+v after=%+v", before, after)
	}
	if _, err := store.GenerationArtifacts(ctx, candidate.GenerationID); err == nil {
		t.Fatal("aborted candidate bytes remained after targeted cleanup")
	}
	for _, gen := range []int64{original.GenerationID, applied.GenerationID} {
		if _, err := store.GenerationArtifacts(ctx, gen); err != nil {
			t.Fatalf("confirmed generation %d was reclaimed: %v", gen, err)
		}
	}
	journal, err := store.Attempt(ctx, candidate.ID)
	if err != nil || journal.Phase != PhaseFailed || journal.Error != HistoricalCheckAbortReason ||
		journal.ConfigSHA256 != candidate.ConfigSHA256 {
		t.Fatalf("reclaimed dry-run lost history tombstone: %+v err=%v", journal, err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil || snapshot.ActiveAttemptID != nil || snapshot.RecoveryRequired ||
		snapshot.Revision != binding.ExpectedConfigRevision ||
		snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != applied.GenerationID ||
		snapshot.LastKnownGoodGenerationID == nil || *snapshot.LastKnownGoodGenerationID != applied.GenerationID {
		t.Fatalf("cleanup altered confirmed core references: %+v err=%v", snapshot, err)
	}
}

func TestReclaimAbortedHistoricalCheckKeepsQuotaAvailableAfterRepeatedChecks(t *testing.T) {
	store, binding, _, _ := historicalRestoreFixture(t)
	ctx := context.Background()
	original, err := store.GenerationArtifacts(ctx, binding.SourceGenerationID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := store.RetentionStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidateSize := int64(len(original.ConfigJSON) + len(original.ManifestJSON) + len(original.SourceMapJSON))
	// Exactly one candidate fits; two leaked prepared candidates would
	// block the next operator config apply or historical compatibility check.
	store.retention.MaxGenerationBytes = report.LiveGenerationBytes + candidateSize + 1
	for i := 0; i < 8; i++ {
		attempt, _, err := store.PrepareHistoricalRestore(ctx, binding)
		if err != nil {
			t.Fatalf("check %d exhausted storage quota: %v", i, err)
		}
		if err := store.AbortPrepared(ctx, attempt.ID, HistoricalCheckAbortReason); err != nil {
			t.Fatal(err)
		}
		if err := store.ReclaimAbortedHistoricalCheck(ctx, attempt.ID); err != nil {
			t.Fatalf("check %d could not reclaim quota: %v", i, err)
		}
	}
	final, err := store.RetentionStatus(ctx)
	if err != nil || final.LiveGenerationBytes != report.LiveGenerationBytes ||
		final.LiveGenerationCount != report.LiveGenerationCount {
		t.Fatalf("repeated checks leaked retained bytes: before=%+v after=%+v err=%v", report, final, err)
	}
}

func TestReclaimAbortedHistoricalCheckRejectsUnsafeJournalStates(t *testing.T) {
	tests := []struct {
		name  string
		setup func(context.Context, *Store, HistoricalRestorePrecondition) (int64, error)
	}{
		{"active historical candidate", func(ctx context.Context, s *Store, p HistoricalRestorePrecondition) (int64, error) {
			a, _, err := s.PrepareHistoricalRestore(ctx, p)
			return a.ID, err
		}},
		{"wrong abort reason", func(ctx context.Context, s *Store, p HistoricalRestorePrecondition) (int64, error) {
			a, _, err := s.PrepareHistoricalRestore(ctx, p)
			if err != nil {
				return 0, err
			}
			return a.ID, s.AbortPrepared(ctx, a.ID, "not a historical dry-run")
		}},
		{"rollback-style failure", func(ctx context.Context, s *Store, p HistoricalRestorePrecondition) (int64, error) {
			a, _, err := s.PrepareHistoricalRestore(ctx, p)
			if err != nil {
				return 0, err
			}
			if err := s.AbortPrepared(ctx, a.ID, HistoricalCheckAbortReason); err != nil {
				return 0, err
			}
			_, err = s.db.ExecContext(ctx, `UPDATE apply_journal
				SET error = ? WHERE id = ?`, "rollback failed: "+HistoricalCheckAbortReason, a.ID)
			return a.ID, err
		}},
		{"user-authored apply", func(ctx context.Context, s *Store, p HistoricalRestorePrecondition) (int64, error) {
			a, err := s.PrepareApply(ctx, p.ExpectedConfigRevision, []byte(`{"ordinary":true}`))
			if err != nil {
				return 0, err
			}
			return a.ID, s.AbortPrepared(ctx, a.ID, HistoricalCheckAbortReason)
		}},
		{"candidate referenced as applied", func(ctx context.Context, s *Store, p HistoricalRestorePrecondition) (int64, error) {
			a, _, err := s.PrepareHistoricalRestore(ctx, p)
			if err != nil {
				return 0, err
			}
			if err := s.AbortPrepared(ctx, a.ID, HistoricalCheckAbortReason); err != nil {
				return 0, err
			}
			_, err = s.db.ExecContext(ctx, `UPDATE daemon_state
				SET applied_generation_id = ? WHERE singleton = 1`, a.GenerationID)
			return a.ID, err
		}},
		{"another journal references candidate", func(ctx context.Context, s *Store, p HistoricalRestorePrecondition) (int64, error) {
			a, _, err := s.PrepareHistoricalRestore(ctx, p)
			if err != nil {
				return 0, err
			}
			if err := s.AbortPrepared(ctx, a.ID, HistoricalCheckAbortReason); err != nil {
				return 0, err
			}
			_, err = s.db.ExecContext(ctx, `INSERT INTO apply_journal(
				generation_id, previous_generation_id, base_revision, target_revision,
				phase, active_slot, error, started_at, updated_at
			) VALUES(?, ?, ?, ?, 'interrupted', NULL, '', ?, ?)`,
				p.ExpectedAppliedGenerationID, a.GenerationID,
				p.ExpectedConfigRevision, p.ExpectedConfigRevision+1,
				"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
			return a.ID, err
		}},
		{"recovery flag set", func(ctx context.Context, s *Store, p HistoricalRestorePrecondition) (int64, error) {
			a, _, err := s.PrepareHistoricalRestore(ctx, p)
			if err != nil {
				return 0, err
			}
			if err := s.AbortPrepared(ctx, a.ID, HistoricalCheckAbortReason); err != nil {
				return 0, err
			}
			_, err = s.db.ExecContext(ctx, `UPDATE daemon_state SET recovery_required = 1 WHERE singleton = 1`)
			return a.ID, err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, binding, _, _ := historicalRestoreFixture(t)
			ctx := context.Background()
			id, err := tt.setup(ctx, store, binding)
			if err != nil {
				t.Fatal(err)
			}
			report, err := store.RetentionStatus(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.ReclaimAbortedHistoricalCheck(ctx, id); !errors.Is(err, ErrHistoricalCheckCleanupUnsafe) {
				t.Fatalf("unsafe cleanup returned %v", err)
			}
			after, err := store.RetentionStatus(ctx)
			if err != nil || report.LiveGenerationBytes != after.LiveGenerationBytes ||
				report.LiveGenerationCount != after.LiveGenerationCount {
				t.Fatalf("refused cleanup mutated history: before=%+v after=%+v err=%v", report, after, err)
			}
			journal, err := store.Attempt(ctx, id)
			if err != nil {
				t.Fatalf("refused cleanup lost journal: %v", err)
			}
			if journal.Phase != PhaseFailed && journal.Phase != PhasePrepared {
				t.Fatalf("refused cleanup changed phase: %+v", journal)
			}
		})
	}
}

func TestReclaimAbortedHistoricalCheckRejectsInterruptedOrPreviouslyReclaimed(t *testing.T) {
	store, binding, _, _ := historicalRestoreFixture(t)
	ctx := context.Background()
	attempt, _, err := store.PrepareHistoricalRestore(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecoverInterrupted(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.ReclaimAbortedHistoricalCheck(ctx, attempt.ID); !errors.Is(err, ErrHistoricalCheckCleanupUnsafe) {
		t.Fatalf("interrupted candidate was treated as a never-activated checked candidate: %v", err)
	}

	// A normal aborted dry-run can be reclaimed exactly once, preserving
	// a terminal audit record. Repeating the cleanup cannot delete more.
	store2, binding2, _, _ := historicalRestoreFixture(t)
	checked, _, err := store2.PrepareHistoricalRestore(ctx, binding2)
	if err != nil {
		t.Fatal(err)
	}
	if err := store2.AbortPrepared(ctx, checked.ID, HistoricalCheckAbortReason); err != nil {
		t.Fatal(err)
	}
	if err := store2.ReclaimAbortedHistoricalCheck(ctx, checked.ID); err != nil {
		t.Fatal(err)
	}
	if err := store2.ReclaimAbortedHistoricalCheck(ctx, checked.ID); !errors.Is(err, ErrHistoricalCheckCleanupUnsafe) {
		t.Fatalf("duplicate cleanup did not fail closed: %v", err)
	}
	if record, err := store2.Attempt(ctx, checked.ID); err != nil || record.Phase != PhaseFailed {
		t.Fatalf("reclaimed audit record lost: %+v err=%v", record, err)
	}
	if err := (*Store)(nil).ReclaimAbortedHistoricalCheck(ctx, checked.ID); !errors.Is(err, ErrHistoricalCheckCleanupUnsafe) {
		t.Fatalf("nil storage accepted: %v", err)
	}
	if err := store2.ReclaimAbortedHistoricalCheck(ctx, -1); !errors.Is(err, ErrHistoricalCheckCleanupUnsafe) {
		t.Fatalf("invalid attempt ID accepted: %v", err)
	}
}

func TestReclaimAbortedHistoricalCheckArchiveCollisionLeavesCandidateUntouched(t *testing.T) {
	store, binding, _, _ := historicalRestoreFixture(t)
	ctx := context.Background()
	attempt, _, err := store.PrepareHistoricalRestore(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AbortPrepared(ctx, attempt.ID, HistoricalCheckAbortReason); err != nil {
		t.Fatal(err)
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO apply_history(
		id, generation_id, base_revision, target_revision, phase, config_sha256,
		error, started_at, updated_at, generation_created_at, archived_at
	) VALUES(?, ?, ?, ?, 'failed', ?, '', ?, ?, ?, ?)`,
		attempt.ID, attempt.GenerationID, attempt.BaseRevision, attempt.TargetRevision,
		attempt.ConfigSHA256, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReclaimAbortedHistoricalCheck(ctx, attempt.ID); err == nil {
		t.Fatal("conflicting archive tombstone allowed partial cleanup")
	}
	if _, err := store.GenerationArtifacts(ctx, attempt.GenerationID); err != nil {
		t.Fatalf("archive failure pruned candidate without audit: %v", err)
	}
	journal, err := store.Attempt(ctx, attempt.ID)
	if err != nil || journal.Phase != PhaseFailed {
		t.Fatalf("archive collision lost original journal: %+v err=%v", journal, err)
	}
	if err := store.ReclaimAbortedHistoricalCheck(ctx, attempt.ID); err == nil {
		t.Fatal("conflicting archive did not continue failing")
	}
}
