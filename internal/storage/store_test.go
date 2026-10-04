package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyLifecycleKeepsRevisionOnRollback(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)
	defer store.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database permissions = %04o, want 0600", got)
	}

	initial, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Revision != 0 || initial.AppliedGenerationID != nil || initial.RecoveryRequired {
		t.Fatalf("unexpected initial snapshot: %+v", initial)
	}

	first, err := store.PrepareApply(ctx, 0, []byte(`{"inbounds":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if first.TargetRevision != 1 || first.Phase != PhasePrepared {
		t.Fatalf("unexpected first attempt: %+v", first)
	}

	if _, err := store.PrepareApply(ctx, 0, []byte(`{"inbounds":[]}`)); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("second concurrent prepare error = %v, want ErrApplyInProgress", err)
	}
	if err := store.BeginActivation(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitApplied(ctx, first.ID, true); err != nil {
		t.Fatal(err)
	}

	afterFirst, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterFirst.Revision != 1 || afterFirst.AppliedGenerationID == nil || *afterFirst.AppliedGenerationID != first.GenerationID {
		t.Fatalf("unexpected snapshot after commit: %+v", afterFirst)
	}
	if afterFirst.LastKnownGoodGenerationID == nil || *afterFirst.LastKnownGoodGenerationID != first.GenerationID {
		t.Fatalf("last known good not promoted: %+v", afterFirst)
	}

	config, hash, err := store.GenerationConfig(ctx, first.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if string(config) != `{"inbounds":[]}` || hash != first.ConfigSHA256 {
		t.Fatalf("unexpected generation payload/hash: %q %q", config, hash)
	}

	if _, err := store.PrepareApply(ctx, 0, []byte(`{"outbounds":[]}`)); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale revision error = %v, want ErrRevisionConflict", err)
	}

	second, err := store.PrepareApply(ctx, 1, []byte(`{"outbounds":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginRollback(ctx, second.ID, "health check failed"); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRollback(ctx, second.ID); err != nil {
		t.Fatal(err)
	}

	afterRollback, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterRollback.Revision != 1 || afterRollback.AppliedGenerationID == nil || *afterRollback.AppliedGenerationID != first.GenerationID {
		t.Fatalf("rollback changed applied state: %+v", afterRollback)
	}
	journal, err := store.Attempt(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != PhaseRolledBack || journal.Error != "health check failed" {
		t.Fatalf("unexpected rollback journal: %+v", journal)
	}
}

func TestRecoverInterruptedActivationRequiresReconcile(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)

	first, err := store.PrepareApply(ctx, 0, []byte(`{"first":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitApplied(ctx, first.ID, true); err != nil {
		t.Fatal(err)
	}

	second, err := store.PrepareApply(ctx, 1, []byte(`{"second":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	recovery, err := reopened.RecoverInterrupted(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !recovery.NeedsReconcile || len(recovery.InterruptedAttemptIDs) != 1 || recovery.InterruptedAttemptIDs[0] != second.ID {
		t.Fatalf("unexpected recovery result: %+v", recovery)
	}

	snapshot, err := reopened.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || !snapshot.RecoveryRequired || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != first.GenerationID {
		t.Fatalf("unexpected recovered snapshot: %+v", snapshot)
	}
	if _, err := reopened.PrepareApply(ctx, 1, []byte(`{"blocked":true}`)); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("prepare during recovery error = %v, want ErrRecoveryRequired", err)
	}

	if err := reopened.ResolveRecovery(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.PrepareApply(ctx, 1, []byte(`{"after_recovery":true}`)); err != nil {
		t.Fatalf("prepare after recovery: %v", err)
	}
}

func TestRecoverPreparedAttemptDoesNotRequireCoreReconcile(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)
	attempt, err := store.PrepareApply(ctx, 0, []byte(`{"prepared":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovery, err := reopened.RecoverInterrupted(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if recovery.NeedsReconcile || len(recovery.InterruptedAttemptIDs) != 1 || recovery.InterruptedAttemptIDs[0] != attempt.ID {
		t.Fatalf("unexpected prepared recovery: %+v", recovery)
	}
	snapshot, err := reopened.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RecoveryRequired {
		t.Fatalf("prepared-only interruption should not require core reconcile: %+v", snapshot)
	}
}

func TestInvalidTransitionIsRejected(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	attempt, err := store.PrepareApply(ctx, 0, []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, attempt.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid transition error = %v, want ErrInvalidTransition", err)
	}
}

func newTestStore(t *testing.T, ctx context.Context) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}
