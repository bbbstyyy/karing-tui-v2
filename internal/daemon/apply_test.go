package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type fakeApplyCore struct {
	events      []string
	checkErr    error
	checkFn     func(context.Context, Generation) error
	activateErr error
	verifyErr   error
	rollbackErr error
	rollbacks   []*Generation
}

func (c *fakeApplyCore) Check(ctx context.Context, generation Generation) error {
	c.events = append(c.events, "check")
	if c.checkFn != nil {
		return c.checkFn(ctx, generation)
	}
	return c.checkErr
}

func (c *fakeApplyCore) Activate(context.Context, Generation) error {
	c.events = append(c.events, "activate")
	return c.activateErr
}

func (c *fakeApplyCore) Verify(context.Context, Generation) error {
	c.events = append(c.events, "verify")
	return c.verifyErr
}

func (c *fakeApplyCore) Rollback(_ context.Context, previous *Generation) error {
	c.events = append(c.events, "rollback")
	if previous == nil {
		c.rollbacks = append(c.rollbacks, nil)
	} else {
		copyGeneration := *previous
		copyGeneration.Config = append([]byte(nil), previous.Config...)
		c.rollbacks = append(c.rollbacks, &copyGeneration)
	}
	return c.rollbackErr
}

type commitFaultStore struct {
	*storage.Store
	commitErr error
}

func (s *commitFaultStore) CommitApplied(ctx context.Context, attemptID int64, promoteLastKnownGood bool) error {
	if s.commitErr != nil {
		return s.commitErr
	}
	return s.Store.CommitApplied(ctx, attemptID, promoteLastKnownGood)
}

func testApplyPolicy() ApplyPolicy {
	return ApplyPolicy{
		StateTimeout:    time.Second,
		CheckTimeout:    time.Second,
		ActivateTimeout: time.Second,
		VerifyTimeout:   time.Second,
		RollbackTimeout: time.Second,
	}
}

func TestApplyCoordinatorCommitsOnlyAfterCheckActivationAndVerification(t *testing.T) {
	ctx := context.Background()
	store := newApplyStore(t, ctx)
	defer store.Close()
	core := &fakeApplyCore{}
	coordinator, err := NewApplyCoordinator(store, core, testApplyPolicy())
	if err != nil {
		t.Fatal(err)
	}

	attempt, err := coordinator.Apply(ctx, 0, []byte(`{"generation":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(core.events, ","); got != "check,activate,verify" {
		t.Fatalf("core events = %q", got)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != attempt.GenerationID {
		t.Fatalf("verified candidate was not committed: %+v", snapshot)
	}
	if snapshot.LastKnownGoodGenerationID == nil || *snapshot.LastKnownGoodGenerationID != attempt.GenerationID {
		t.Fatalf("verified candidate was not promoted to last-known-good: %+v", snapshot)
	}

	journal, err := store.Attempt(ctx, attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != storage.PhaseCommitted {
		t.Fatalf("journal phase = %s, want committed", journal.Phase)
	}
}

func TestApplyCoordinatorCheckFailureNeverActivatesCandidate(t *testing.T) {
	ctx := context.Background()
	store := newApplyStore(t, ctx)
	defer store.Close()
	checkErr := errors.New("core config check rejected candidate")
	core := &fakeApplyCore{checkErr: checkErr}
	coordinator, _ := NewApplyCoordinator(store, core, testApplyPolicy())

	attempt, err := coordinator.Apply(ctx, 0, []byte(`{"bad":true}`))
	if !errors.Is(err, checkErr) {
		t.Fatalf("apply error = %v, want check error", err)
	}
	if got := strings.Join(core.events, ","); got != "check" {
		t.Fatalf("core events = %q, candidate should not activate", got)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 0 || snapshot.AppliedGenerationID != nil || snapshot.RecoveryRequired || snapshot.ActiveAttemptID != nil {
		t.Fatalf("check failure changed confirmed state: %+v", snapshot)
	}
	journal, err := store.Attempt(ctx, attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != storage.PhaseFailed {
		t.Fatalf("journal phase = %s, want failed", journal.Phase)
	}
}

func TestApplyCoordinatorActivationFailureRollsBackWithoutAdvancingRevision(t *testing.T) {
	ctx := context.Background()
	store := newApplyStore(t, ctx)
	defer store.Close()
	activateErr := errors.New("candidate failed to start")
	core := &fakeApplyCore{activateErr: activateErr}
	coordinator, _ := NewApplyCoordinator(store, core, testApplyPolicy())

	attempt, err := coordinator.Apply(ctx, 0, []byte(`{"candidate":true}`))
	if !errors.Is(err, activateErr) {
		t.Fatalf("apply error = %v, want activation error", err)
	}
	if got := strings.Join(core.events, ","); got != "check,activate,rollback" {
		t.Fatalf("core events = %q", got)
	}
	if len(core.rollbacks) != 1 || core.rollbacks[0] != nil {
		t.Fatalf("first apply rollback should restore no previous generation: %+v", core.rollbacks)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 0 || snapshot.AppliedGenerationID != nil || snapshot.RecoveryRequired {
		t.Fatalf("activation failure changed confirmed state: %+v", snapshot)
	}
	journal, err := store.Attempt(ctx, attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != storage.PhaseRolledBack {
		t.Fatalf("journal phase = %s, want rolled_back", journal.Phase)
	}
}

func TestApplyCoordinatorVerificationFailureRestoresPreviousGeneration(t *testing.T) {
	ctx := context.Background()
	store := newApplyStore(t, ctx)
	defer store.Close()
	core := &fakeApplyCore{}
	coordinator, _ := NewApplyCoordinator(store, core, testApplyPolicy())

	first, err := coordinator.Apply(ctx, 0, []byte(`{"generation":1}`))
	if err != nil {
		t.Fatal(err)
	}
	core.events = nil
	core.verifyErr = errors.New("local proxy behavior did not verify")

	second, err := coordinator.Apply(ctx, 1, []byte(`{"generation":2}`))
	if !errors.Is(err, core.verifyErr) {
		t.Fatalf("apply error = %v, want verification error", err)
	}
	if got := strings.Join(core.events, ","); got != "check,activate,verify,rollback" {
		t.Fatalf("core events = %q", got)
	}
	if len(core.rollbacks) != 1 || core.rollbacks[0] == nil || core.rollbacks[0].ID != first.GenerationID {
		t.Fatalf("rollback did not restore generation %d: %+v", first.GenerationID, core.rollbacks)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != first.GenerationID {
		t.Fatalf("verification failure replaced applied generation: %+v", snapshot)
	}
	journal, err := store.Attempt(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != storage.PhaseRolledBack {
		t.Fatalf("journal phase = %s, want rolled_back", journal.Phase)
	}
}

func TestApplyCoordinatorCommitFailureRestoresPreviousGeneration(t *testing.T) {
	ctx := context.Background()
	baseStore := newApplyStore(t, ctx)
	defer baseStore.Close()
	store := &commitFaultStore{Store: baseStore}
	core := &fakeApplyCore{}
	coordinator, _ := NewApplyCoordinator(store, core, testApplyPolicy())

	first, err := coordinator.Apply(ctx, 0, []byte(`{"generation":1}`))
	if err != nil {
		t.Fatal(err)
	}
	core.events = nil
	store.commitErr = errors.New("simulated durable commit failure")

	second, err := coordinator.Apply(ctx, 1, []byte(`{"generation":2}`))
	if !errors.Is(err, store.commitErr) {
		t.Fatalf("apply error = %v, want commit failure", err)
	}
	if got := strings.Join(core.events, ","); got != "check,activate,verify,rollback" {
		t.Fatalf("core events = %q", got)
	}
	if len(core.rollbacks) != 1 || core.rollbacks[0] == nil || core.rollbacks[0].ID != first.GenerationID {
		t.Fatalf("commit failure did not restore generation %d: %+v", first.GenerationID, core.rollbacks)
	}

	snapshot, err := baseStore.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != first.GenerationID {
		t.Fatalf("commit failure advanced confirmed state: %+v", snapshot)
	}
	journal, err := baseStore.Attempt(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != storage.PhaseRolledBack {
		t.Fatalf("journal phase = %s, want rolled_back", journal.Phase)
	}
}

func TestApplyCoordinatorRollbackFailureRequiresRecovery(t *testing.T) {
	ctx := context.Background()
	store := newApplyStore(t, ctx)
	defer store.Close()
	core := &fakeApplyCore{}
	coordinator, _ := NewApplyCoordinator(store, core, testApplyPolicy())

	first, err := coordinator.Apply(ctx, 0, []byte(`{"generation":1}`))
	if err != nil {
		t.Fatal(err)
	}
	core.verifyErr = errors.New("candidate verification failed")
	core.rollbackErr = errors.New("previous generation failed to restart")

	second, err := coordinator.Apply(ctx, 1, []byte(`{"generation":2}`))
	if !errors.Is(err, core.verifyErr) || !errors.Is(err, core.rollbackErr) {
		t.Fatalf("apply error = %v, want verification and rollback errors", err)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != first.GenerationID || !snapshot.RecoveryRequired {
		t.Fatalf("failed rollback did not preserve confirmed state and require recovery: %+v", snapshot)
	}
	journal, err := store.Attempt(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != storage.PhaseFailed || !strings.Contains(journal.Error, "rollback failed") {
		t.Fatalf("unexpected failed rollback journal: %+v", journal)
	}
	if _, err := store.PrepareApply(ctx, 1, []byte(`{"blocked":true}`)); !errors.Is(err, storage.ErrRecoveryRequired) {
		t.Fatalf("new apply after failed rollback error = %v, want ErrRecoveryRequired", err)
	}
}

func TestApplyCoordinatorCheckTimeoutAbortsPreparedAttempt(t *testing.T) {
	ctx := context.Background()
	store := newApplyStore(t, ctx)
	defer store.Close()
	core := &fakeApplyCore{
		checkFn: func(ctx context.Context, _ Generation) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	coordinator, _ := NewApplyCoordinator(store, core, ApplyPolicy{
		StateTimeout:    time.Second,
		CheckTimeout:    time.Millisecond,
		ActivateTimeout: time.Second,
		VerifyTimeout:   time.Second,
		RollbackTimeout: time.Second,
	})

	attempt, err := coordinator.Apply(ctx, 0, []byte(`{"timeout":true}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("apply error = %v, want deadline exceeded", err)
	}
	journal, err := store.Attempt(ctx, attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != storage.PhaseFailed {
		t.Fatalf("timed out check left journal phase %s", journal.Phase)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ActiveAttemptID != nil || snapshot.Revision != 0 {
		t.Fatalf("timed out check left active or advanced state: %+v", snapshot)
	}
}

func newApplyStore(t *testing.T, ctx context.Context) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(ctx, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestApplyCoordinatorCompiledArtifactsPersistMetadata(t *testing.T) {
	ctx := context.Background()
	store := newApplyStore(t, ctx)
	defer store.Close()
	core := &fakeApplyCore{}
	coordinator, err := NewApplyCoordinator(store, core, testApplyPolicy())
	if err != nil {
		t.Fatal(err)
	}

	artifacts := CompiledGenerationArtifacts{
		Config:    []byte(`{"generation":1}`),
		Manifest:  []byte(`{"schema_id":"test","config_sha256":"placeholder"}`),
		SourceMap: []byte(`[{"rule_index":0,"group_id":"FINAL"}]`),
	}
	configCopy := append([]byte(nil), artifacts.Config...)
	manifestCopy := append([]byte(nil), artifacts.Manifest...)
	sourceMapCopy := append([]byte(nil), artifacts.SourceMap...)

	attempt, err := coordinator.ApplyCompiled(ctx, 0, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	artifacts.Config[0] = 'x'
	artifacts.Manifest[0] = 'x'
	artifacts.SourceMap[0] = 'x'

	persisted, err := store.GenerationArtifacts(ctx, attempt.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if string(persisted.ConfigJSON) != string(configCopy) ||
		string(persisted.ManifestJSON) != string(manifestCopy) ||
		string(persisted.SourceMapJSON) != string(sourceMapCopy) {
		t.Fatalf("compiled generation metadata changed: %+v", persisted)
	}
	if got := strings.Join(core.events, ","); got != "check,activate,verify" {
		t.Fatalf("core events = %q", got)
	}
}

type legacyOnlyApplyStore struct {
	applyStore
}

func TestApplyCoordinatorCompiledArtifactsRequiresMetadataStore(t *testing.T) {
	ctx := context.Background()
	store := newApplyStore(t, ctx)
	defer store.Close()
	core := &fakeApplyCore{}
	coordinator, err := NewApplyCoordinator(legacyOnlyApplyStore{applyStore: store}, core, testApplyPolicy())
	if err != nil {
		t.Fatal(err)
	}

	_, err = coordinator.ApplyCompiled(ctx, 0, CompiledGenerationArtifacts{
		Config:    []byte(`{"generation":1}`),
		Manifest:  []byte(`{}`),
		SourceMap: []byte(`[]`),
	})
	if err == nil || !strings.Contains(err.Error(), "does not support generation metadata") {
		t.Fatalf("metadata capability error = %v", err)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ActiveAttemptID != nil || snapshot.Revision != 0 {
		t.Fatalf("unsupported metadata apply changed durable state: %+v", snapshot)
	}
}
