package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type fakeCoreController struct {
	start func(context.Context) error
	stop  func(context.Context) error
}

func (c *fakeCoreController) Start(ctx context.Context) error {
	if c.start != nil {
		return c.start(ctx)
	}
	return nil
}

func (c *fakeCoreController) Stop(ctx context.Context) error {
	if c.stop != nil {
		return c.stop(ctx)
	}
	return nil
}

func TestLifecycleStartPersistsIntentBeforeControllerStart(t *testing.T) {
	ctx := context.Background()
	store := newLifecycleStore(t, ctx)
	defer store.Close()

	startErr := errors.New("deterministic start failure")
	controller := &fakeCoreController{
		start: func(ctx context.Context) error {
			snapshot, err := store.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.CoreDesiredState != storage.CoreDesiredRunning {
				t.Fatalf("desired state at controller start = %q, want running", snapshot.CoreDesiredState)
			}
			return startErr
		},
	}
	coordinator, err := NewLifecycleCoordinator(store, controller)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(ctx); !errors.Is(err, startErr) {
		t.Fatalf("start error = %v, want %v", err, startErr)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.CoreDesiredState != storage.CoreDesiredRunning {
		t.Fatalf("failed observed start rewrote desired state: %+v", snapshot)
	}
}

func TestLifecycleStopPersistsIntentBeforeControllerStop(t *testing.T) {
	ctx := context.Background()
	store := newLifecycleStore(t, ctx)
	defer store.Close()
	if err := store.SetCoreDesiredState(ctx, storage.CoreDesiredRunning); err != nil {
		t.Fatal(err)
	}

	stopErr := errors.New("stop failed")
	controller := &fakeCoreController{
		stop: func(ctx context.Context) error {
			snapshot, err := store.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.CoreDesiredState != storage.CoreDesiredStopped {
				t.Fatalf("desired state at controller stop = %q, want stopped", snapshot.CoreDesiredState)
			}
			return stopErr
		},
	}
	coordinator, err := NewLifecycleCoordinator(store, controller)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Stop(ctx); !errors.Is(err, stopErr) {
		t.Fatalf("stop error = %v, want %v", err, stopErr)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.CoreDesiredState != storage.CoreDesiredStopped {
		t.Fatalf("failed observed stop rewrote durable stop intent: %+v", snapshot)
	}
}

func TestLifecycleRestoreHonorsPersistedStopAndRunIntent(t *testing.T) {
	ctx := context.Background()
	store := newLifecycleStore(t, ctx)
	defer store.Close()

	starts := 0
	controller := &fakeCoreController{
		start: func(context.Context) error {
			starts++
			return nil
		},
	}
	coordinator, err := NewLifecycleCoordinator(store, controller)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if starts != 0 {
		t.Fatalf("restore started core for persisted stopped intent: starts=%d", starts)
	}

	if err := store.SetCoreDesiredState(ctx, storage.CoreDesiredRunning); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if starts != 1 {
		t.Fatalf("restore starts = %d, want 1", starts)
	}
}

func TestLifecycleRestoreBlocksWhileApplyRecoveryIsRequired(t *testing.T) {
	ctx := context.Background()
	store := newLifecycleStore(t, ctx)
	defer store.Close()
	if err := store.SetCoreDesiredState(ctx, storage.CoreDesiredRunning); err != nil {
		t.Fatal(err)
	}
	attempt, err := store.PrepareApply(ctx, 0, []byte(`{"test":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	recovery, err := store.RecoverInterrupted(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !recovery.NeedsReconcile {
		t.Fatal("expected activation interruption to require recovery")
	}

	starts := 0
	coordinator, err := NewLifecycleCoordinator(store, &fakeCoreController{
		start: func(context.Context) error {
			starts++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Restore(ctx); !errors.Is(err, storage.ErrRecoveryRequired) {
		t.Fatalf("restore error = %v, want ErrRecoveryRequired", err)
	}
	if starts != 0 {
		t.Fatalf("controller start called during recovery: %d", starts)
	}
}

func TestLifecycleStopIsAllowedDuringRecovery(t *testing.T) {
	ctx := context.Background()
	store := newLifecycleStore(t, ctx)
	defer store.Close()
	if err := store.SetCoreDesiredState(ctx, storage.CoreDesiredRunning); err != nil {
		t.Fatal(err)
	}
	attempt, err := store.PrepareApply(ctx, 0, []byte(`{"test":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecoverInterrupted(ctx); err != nil {
		t.Fatal(err)
	}

	stops := 0
	coordinator, err := NewLifecycleCoordinator(store, &fakeCoreController{
		stop: func(context.Context) error {
			stops++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if stops != 1 {
		t.Fatalf("controller stops = %d, want 1", stops)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.RecoveryRequired || snapshot.CoreDesiredState != storage.CoreDesiredStopped {
		t.Fatalf("stop during recovery did not preserve recovery flag and stop intent: %+v", snapshot)
	}
}

func newLifecycleStore(t *testing.T, ctx context.Context) *storage.Store {
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
