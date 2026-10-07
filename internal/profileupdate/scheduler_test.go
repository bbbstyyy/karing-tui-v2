package profileupdate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestRefreshSchedulerBoundsGlobalConcurrency(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	for _, profileID := range []string{"profile-a", "profile-b", "profile-c"} {
		spec := scheduledSourceState(profileID).Spec
		if _, err := store.CommitProfileSource(ctx, 0, spec); err != nil {
			t.Fatal(err)
		}
	}

	started := make(chan string, 6)
	release := make(chan struct{})
	runner := func(
		ctx context.Context,
		profileID string,
		revision uint64,
		updateID string,
	) error {
		lease, err := store.BeginProfileUpdate(ctx, profileID, revision, updateID)
		if err != nil {
			return err
		}
		started <- profileID
		select {
		case <-ctx.Done():
			return store.FinishProfileUpdateFailure(ctx, lease, "scheduler canceled", nil)
		case <-release:
			return store.FinishProfileUpdateSuccess(
				ctx,
				lease,
				storage.ProfileUpdateSuccess{SourceRevision: "scheduled-test"},
			)
		}
	}

	options := DefaultSchedulerOptions()
	options.MaxConcurrent = 2
	options.Policy.StartupSpread = 0
	scheduler, err := NewRefreshScheduler(store, runner, options)
	if err != nil {
		t.Fatal(err)
	}

	now := scheduler.startedAt.Add(time.Second)
	if err := scheduler.dispatchDue(ctx, now); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case profileID := <-started:
			seen[profileID] = true
		case <-time.After(2 * time.Second):
			t.Fatal("scheduled refresh did not start")
		}
	}
	if !seen["profile-a"] || !seen["profile-b"] || seen["profile-c"] {
		t.Fatalf("first dispatch started profiles = %+v", seen)
	}
	select {
	case profileID := <-started:
		t.Fatalf("global concurrency limit leaked extra worker %q", profileID)
	case <-time.After(50 * time.Millisecond):
	}

	if err := scheduler.dispatchDue(ctx, now); err != nil {
		t.Fatal(err)
	}
	select {
	case profileID := <-started:
		t.Fatalf("second scan duplicated an active worker %q", profileID)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	scheduler.wait()

	if err := scheduler.dispatchDue(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	select {
	case profileID := <-started:
		if profileID != "profile-c" {
			t.Fatalf("post-capacity dispatch started %q, want profile-c", profileID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("profile-c was not dispatched after capacity freed")
	}
	scheduler.wait()
}

func TestRefreshSchedulerNeverDuplicatesSameProfileInMemory(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	spec := scheduledSourceState("profile-a").Spec
	if _, err := store.CommitProfileSource(ctx, 0, spec); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{}, 2)
	release := make(chan struct{})
	runner := func(
		ctx context.Context,
		_ string,
		_ uint64,
		_ string,
	) error {
		started <- struct{}{}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	}

	options := DefaultSchedulerOptions()
	options.Policy.StartupSpread = 0
	scheduler, err := NewRefreshScheduler(store, runner, options)
	if err != nil {
		t.Fatal(err)
	}

	now := scheduler.startedAt.Add(time.Second)
	if err := scheduler.dispatchDue(ctx, now); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first scheduled worker did not start")
	}
	if err := scheduler.dispatchDue(ctx, now); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
		t.Fatal("same profile was dispatched twice while first worker was active")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	scheduler.wait()
}

func TestRefreshSchedulerCancellationWaitsForWorkers(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	spec := scheduledSourceState("profile-a").Spec
	if _, err := store.CommitProfileSource(ctx, 0, spec); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	exited := make(chan struct{})
	runner := func(
		ctx context.Context,
		_ string,
		_ uint64,
		_ string,
	) error {
		close(started)
		<-ctx.Done()
		close(exited)
		return ctx.Err()
	}

	options := DefaultSchedulerOptions()
	options.ScanInterval = 5 * time.Millisecond
	options.Policy.StartupSpread = 0
	scheduler, err := NewRefreshScheduler(store, runner, options)
	if err != nil {
		t.Fatal(err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- scheduler.Run(runCtx)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not start due worker")
	}
	cancel()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not observe scheduler cancellation")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("scheduler cancellation error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not wait for worker shutdown")
	}
}

func TestRefreshSchedulerValidatesResourceLimits(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	runner := ScheduledRefreshFunc(func(context.Context, string, uint64, string) error {
		return nil
	})

	options := DefaultSchedulerOptions()
	options.MaxConcurrent = 0
	if _, err := NewRefreshScheduler(store, runner, options); err == nil {
		t.Fatal("zero scheduler concurrency was accepted")
	}
	options = DefaultSchedulerOptions()
	options.MaxConcurrent = MaxRefreshConcurrency + 1
	if _, err := NewRefreshScheduler(store, runner, options); err == nil {
		t.Fatal("excessive scheduler concurrency was accepted")
	}
	options = DefaultSchedulerOptions()
	options.ScanInterval = 0
	if _, err := NewRefreshScheduler(store, runner, options); err == nil {
		t.Fatal("zero scheduler scan interval was accepted")
	}
	if _, err := NewRefreshScheduler(nil, runner, DefaultSchedulerOptions()); err == nil {
		t.Fatal("nil scheduler store was accepted")
	}
	if _, err := NewRefreshScheduler(store, nil, DefaultSchedulerOptions()); err == nil {
		t.Fatal("nil scheduler runner was accepted")
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	options = DefaultSchedulerOptions()
	options.Policy.StartupSpread = 0
	scheduler, err := NewRefreshScheduler(store, runner, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Run(cancelled); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled scheduler error = %v", err)
	}
}
