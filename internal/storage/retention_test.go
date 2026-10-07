package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetentionArchivesAuditAndKeepsConfiguredConfirmedGenerations(t *testing.T) {
	ctx := context.Background()
	store := openRetentionTestStore(t, ctx, RetentionPolicy{
		ConfirmedGenerations: 2,
		MaxGenerationBytes:   1 << 20,
	})
	defer store.Close()

	attempts := make([]Attempt, 0, 4)
	for revision := uint64(0); revision < 4; revision++ {
		attempts = append(attempts, commitRetentionGeneration(t, ctx, store, revision))
	}

	report, err := store.PruneRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.LiveGenerationCount != 2 || report.ProtectedGenerationCount != 2 {
		t.Fatalf("unexpected retained generations: %+v", report)
	}
	if report.ArchivedAttemptCount != 4 {
		t.Fatalf("archived attempts = %d, want 4", report.ArchivedAttemptCount)
	}
	if report.OverBudget {
		t.Fatalf("small retained fixtures unexpectedly exceed quota: %+v", report)
	}

	for _, attempt := range attempts[2:] {
		if _, _, err := store.GenerationConfig(ctx, attempt.GenerationID); err != nil {
			t.Fatalf("retained generation %d unavailable: %v", attempt.GenerationID, err)
		}
	}
	for _, attempt := range attempts[:2] {
		if _, _, err := store.GenerationConfig(ctx, attempt.GenerationID); err == nil {
			t.Fatalf("old generation %d was not pruned", attempt.GenerationID)
		}
		archived, err := store.Attempt(ctx, attempt.ID)
		if err != nil {
			t.Fatalf("archived attempt %d unavailable: %v", attempt.ID, err)
		}
		if archived.Phase != PhaseCommitted || archived.ConfigSHA256 != attempt.ConfigSHA256 {
			t.Fatalf("archived attempt changed: %+v", archived)
		}
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != attempts[3].GenerationID ||
		snapshot.LastKnownGoodGenerationID == nil || *snapshot.LastKnownGoodGenerationID != attempts[3].GenerationID {
		t.Fatalf("retention changed confirmed state: %+v", snapshot)
	}
}

func TestRetentionProtectsActiveCandidateAndPreviousGeneration(t *testing.T) {
	ctx := context.Background()
	store := openRetentionTestStore(t, ctx, RetentionPolicy{
		ConfirmedGenerations: 2,
		MaxGenerationBytes:   1 << 20,
	})
	defer store.Close()

	for revision := uint64(0); revision < 3; revision++ {
		commitRetentionGeneration(t, ctx, store, revision)
	}
	active, err := store.PrepareApply(ctx, 3, []byte(`{"candidate":4}`))
	if err != nil {
		t.Fatal(err)
	}

	report, err := store.PruneRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.ActiveAttemptCount != 1 || report.LiveGenerationCount != 3 {
		t.Fatalf("active retention report = %+v, want 1 active and 3 live generations", report)
	}
	if _, _, err := store.GenerationConfig(ctx, active.GenerationID); err != nil {
		t.Fatalf("active candidate pruned: %v", err)
	}
	if active.PreviousGenerationID == nil {
		t.Fatal("active attempt did not record previous generation")
	}
	if _, _, err := store.GenerationConfig(ctx, *active.PreviousGenerationID); err != nil {
		t.Fatalf("active previous generation pruned: %v", err)
	}

	if err := store.AbortPrepared(ctx, active.ID, "fixture complete"); err != nil {
		t.Fatal(err)
	}
	report, err = store.PruneRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.LiveGenerationCount != 2 || report.ActiveAttemptCount != 0 {
		t.Fatalf("terminal candidate was not reclaimed: %+v", report)
	}
	if _, _, err := store.GenerationConfig(ctx, active.GenerationID); err == nil {
		t.Fatal("failed candidate payload remained after prune")
	}
	archived, err := store.Attempt(ctx, active.ID)
	if err != nil {
		t.Fatal(err)
	}
	if archived.Phase != PhaseFailed || archived.Error != "fixture complete" {
		t.Fatalf("failed candidate audit changed: %+v", archived)
	}
}

func TestGenerationBudgetRejectsNewPayloadWithoutChangingState(t *testing.T) {
	ctx := context.Background()
	store := openRetentionTestStore(t, ctx, RetentionPolicy{
		ConfirmedGenerations: 2,
		MaxGenerationBytes:   64,
	})
	defer store.Close()

	config := []byte(fmt.Sprintf(`{"data":"%s"}`, strings.Repeat("x", 80)))
	if _, err := store.PrepareApply(ctx, 0, config); !errors.Is(err, ErrGenerationStorageBudget) {
		t.Fatalf("prepare error = %v, want ErrGenerationStorageBudget", err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 0 || snapshot.ActiveAttemptID != nil || snapshot.AppliedGenerationID != nil {
		t.Fatalf("budget rejection changed durable state: %+v", snapshot)
	}
	report, err := store.RetentionStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.LiveGenerationCount != 0 || report.LiveGenerationBytes != 0 {
		t.Fatalf("budget rejection left generation payloads: %+v", report)
	}
}

func TestRetentionPolicyRejectsUnsafeConfirmedGenerationCount(t *testing.T) {
	policy := DefaultRetentionPolicy()
	policy.ConfirmedGenerations = 1
	if err := policy.Validate(); err == nil {
		t.Fatal("expected retention policy with one confirmed generation to be rejected")
	}
}

func openRetentionTestStore(t *testing.T, ctx context.Context, policy RetentionPolicy) *Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenWithRetention(ctx, filepath.Join(dir, "state.db"), policy)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func commitRetentionGeneration(t *testing.T, ctx context.Context, store *Store, revision uint64) Attempt {
	t.Helper()
	attempt, err := store.PrepareApply(ctx, revision, []byte(fmt.Sprintf(`{"revision":%d}`, revision+1)))
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
	return attempt
}
