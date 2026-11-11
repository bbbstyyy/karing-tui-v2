package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type fakeRecoveryStore struct {
	snapshot     storage.Snapshot
	snapshotErr  error
	resolveErr   error
	resolveCalls int
	order        *[]string
}

func (s *fakeRecoveryStore) Snapshot(context.Context) (storage.Snapshot, error) {
	return s.snapshot, s.snapshotErr
}

func (s *fakeRecoveryStore) ResolveRecovery(context.Context) error {
	s.resolveCalls++
	if s.order != nil {
		*s.order = append(*s.order, "resolve")
	}
	return s.resolveErr
}

type fakeRecoveryCore struct {
	err   error
	calls int
	order *[]string
}

func (c *fakeRecoveryCore) ReconcileRecovery(context.Context) error {
	c.calls++
	if c.order != nil {
		*c.order = append(*c.order, "core")
	}
	return c.err
}

func TestRecoveryCoordinatorSkipsCleanState(t *testing.T) {
	store := &fakeRecoveryStore{}
	core := &fakeRecoveryCore{}
	coordinator, err := NewRecoveryCoordinator(store, core)
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := coordinator.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if recovered || core.calls != 0 || store.resolveCalls != 0 {
		t.Fatalf("clean state triggered reconcile: recovered=%t core=%d resolve=%d", recovered, core.calls, store.resolveCalls)
	}
}

func TestRecoveryCoordinatorClearsFlagOnlyAfterCoreReconcile(t *testing.T) {
	order := []string{}
	store := &fakeRecoveryStore{
		snapshot: storage.Snapshot{RecoveryRequired: true},
		order:    &order,
	}
	core := &fakeRecoveryCore{order: &order}
	coordinator, err := NewRecoveryCoordinator(store, core)
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := coordinator.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !recovered || core.calls != 1 || store.resolveCalls != 1 {
		t.Fatalf("unexpected reconcile calls: recovered=%t core=%d resolve=%d", recovered, core.calls, store.resolveCalls)
	}
	if len(order) != 2 || order[0] != "core" || order[1] != "resolve" {
		t.Fatalf("unsafe recovery ordering: %#v", order)
	}
}

func TestRecoveryCoordinatorKeepsFlagWhenCoreReconcileFails(t *testing.T) {
	reconcileErr := errors.New("restore confirmed generation failed")
	store := &fakeRecoveryStore{snapshot: storage.Snapshot{RecoveryRequired: true}}
	core := &fakeRecoveryCore{err: reconcileErr}
	coordinator, err := NewRecoveryCoordinator(store, core)
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := coordinator.Reconcile(context.Background())
	if !recovered || !errors.Is(err, reconcileErr) {
		t.Fatalf("reconcile result = recovered=%t err=%v", recovered, err)
	}
	if store.resolveCalls != 0 {
		t.Fatalf("recovery flag cleared after failed reconcile: %d", store.resolveCalls)
	}
}
