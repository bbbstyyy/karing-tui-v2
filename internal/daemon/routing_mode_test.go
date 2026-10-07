package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type fakeRoutingModeStore struct {
	snapshot storage.Snapshot
	setMode  storage.RoutingMode
	setErr   error
}

func (s *fakeRoutingModeStore) Snapshot(context.Context) (storage.Snapshot, error) {
	return s.snapshot, nil
}

func (s *fakeRoutingModeStore) SetRoutingMode(_ context.Context, mode storage.RoutingMode) error {
	if s.setErr != nil {
		return s.setErr
	}
	s.setMode = mode
	s.snapshot.RoutingMode = mode
	return nil
}

type fakeRoutingModeCore struct {
	snapshot core.Snapshot
	mode     storage.RoutingMode
	setCalls int
	setErr   error
	readErr  error
}

func (c *fakeRoutingModeCore) Snapshot() core.Snapshot {
	return c.snapshot
}

func (c *fakeRoutingModeCore) SetRoutingMode(_ context.Context, mode storage.RoutingMode) error {
	c.setCalls++
	if c.setErr != nil {
		return c.setErr
	}
	c.mode = mode
	return nil
}

func (c *fakeRoutingModeCore) CurrentRoutingMode(context.Context) (storage.RoutingMode, error) {
	if c.readErr != nil {
		return "", c.readErr
	}
	return c.mode, nil
}

func TestRoutingModeCoordinatorPersistsAndUpdatesRunningCore(t *testing.T) {
	store := &fakeRoutingModeStore{snapshot: storage.Snapshot{RoutingMode: storage.RoutingModeRule}}
	coreRuntime := &fakeRoutingModeCore{
		snapshot: core.Snapshot{State: core.StateRunning, PID: 123},
		mode:     storage.RoutingModeRule,
	}
	coordinator, err := NewRoutingModeCoordinator(store, coreRuntime)
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Set(context.Background(), storage.RoutingModeGlobal)
	if err != nil {
		t.Fatal(err)
	}
	if store.setMode != storage.RoutingModeGlobal ||
		coreRuntime.setCalls != 1 ||
		!state.Applied ||
		state.LiveMode != storage.RoutingModeGlobal {
		t.Fatalf("routing mode state = %+v store=%q calls=%d", state, store.setMode, coreRuntime.setCalls)
	}
}

func TestRoutingModeCoordinatorPersistsWhileStopped(t *testing.T) {
	store := &fakeRoutingModeStore{snapshot: storage.Snapshot{RoutingMode: storage.RoutingModeRule}}
	coreRuntime := &fakeRoutingModeCore{snapshot: core.Snapshot{State: core.StateStopped}}
	coordinator, _ := NewRoutingModeCoordinator(store, coreRuntime)
	state, err := coordinator.Set(context.Background(), storage.RoutingModeDirect)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != storage.RoutingModeDirect || state.Applied || state.LiveMode != "" ||
		coreRuntime.setCalls != 0 {
		t.Fatalf("stopped routing mode state = %+v calls=%d", state, coreRuntime.setCalls)
	}
}

func TestRoutingModeCoordinatorRetainsIntentOnLiveFailure(t *testing.T) {
	store := &fakeRoutingModeStore{snapshot: storage.Snapshot{RoutingMode: storage.RoutingModeRule}}
	coreRuntime := &fakeRoutingModeCore{
		snapshot: core.Snapshot{State: core.StateRunning, PID: 123},
		mode:     storage.RoutingModeRule,
		setErr:   errors.New("core rejected mode"),
	}
	coordinator, _ := NewRoutingModeCoordinator(store, coreRuntime)
	if _, err := coordinator.Set(context.Background(), storage.RoutingModeGlobal); !errors.Is(err, ErrLiveRoutingModeUpdate) {
		t.Fatalf("live update error = %v", err)
	}
	if store.snapshot.RoutingMode != storage.RoutingModeGlobal {
		t.Fatalf("failed live update did not retain durable mode: %q", store.snapshot.RoutingMode)
	}
}
