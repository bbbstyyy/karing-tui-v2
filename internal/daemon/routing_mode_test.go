package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
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

func TestRoutingModeAPIPersistsWhileCoreUnavailable(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	handler := New(runtimepath.Paths{}).handler(store, nil)

	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/v1/routing/mode", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("mode GET status=%d body=%s", get.Code, get.Body.String())
	}
	var initial apiv1.RoutingModeResponse
	if err := json.NewDecoder(get.Body).Decode(&initial); err != nil {
		t.Fatal(err)
	}
	if initial.Mode != string(storage.RoutingModeRule) || initial.Applied {
		t.Fatalf("initial mode response = %+v", initial)
	}

	put := httptest.NewRecorder()
	handler.ServeHTTP(
		put,
		httptest.NewRequest(http.MethodPut, "/v1/routing/mode", strings.NewReader(`{"mode":"global"}`)),
	)
	if put.Code != http.StatusOK {
		t.Fatalf("mode PUT status=%d body=%s", put.Code, put.Body.String())
	}
	var updated apiv1.RoutingModeResponse
	if err := json.NewDecoder(put.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if updated.Mode != string(storage.RoutingModeGlobal) || updated.Applied {
		t.Fatalf("updated mode response = %+v", updated)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RoutingMode != storage.RoutingModeGlobal {
		t.Fatalf("persisted routing mode = %q", snapshot.RoutingMode)
	}

	bad := httptest.NewRecorder()
	handler.ServeHTTP(
		bad,
		httptest.NewRequest(http.MethodPut, "/v1/routing/mode", strings.NewReader(`{"mode":"unsupported"}`)),
	)
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid mode status=%d body=%s", bad.Code, bad.Body.String())
	}
}
