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
	setPriv  bool
	setErr   error
}

func (s *fakeRoutingModeStore) Snapshot(context.Context) (storage.Snapshot, error) {
	return s.snapshot, nil
}

func (s *fakeRoutingModeStore) SetRoutingPolicy(
	_ context.Context,
	mode storage.RoutingMode,
	privateDirect bool,
) error {
	if s.setErr != nil {
		return s.setErr
	}
	s.setMode = mode
	s.setPriv = privateDirect
	s.snapshot.RoutingMode = mode
	s.snapshot.PrivateDirect = privateDirect
	return nil
}

type fakeRoutingModeCore struct {
	snapshot core.Snapshot
	mode     storage.RoutingMode
	priv     bool
	setCalls int
	setErr   error
	readErr  error
}

func (c *fakeRoutingModeCore) Snapshot() core.Snapshot {
	return c.snapshot
}

func (c *fakeRoutingModeCore) SetRoutingPolicy(
	_ context.Context,
	mode storage.RoutingMode,
	privateDirect bool,
) error {
	c.setCalls++
	if c.setErr != nil {
		return c.setErr
	}
	c.mode = mode
	c.priv = privateDirect
	return nil
}

func (c *fakeRoutingModeCore) CurrentRoutingPolicy(context.Context) (storage.RoutingMode, bool, error) {
	if c.readErr != nil {
		return "", false, c.readErr
	}
	return c.mode, c.priv, nil
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
	privateDirect := true
	state, err := coordinator.SetPolicy(context.Background(), storage.RoutingModeGlobal, &privateDirect)
	if err != nil {
		t.Fatal(err)
	}
	if store.setMode != storage.RoutingModeGlobal || !store.setPriv ||
		coreRuntime.setCalls != 1 || !state.Applied ||
		state.LiveMode != storage.RoutingModeGlobal ||
		state.LivePrivateDirect == nil || !*state.LivePrivateDirect {
		t.Fatalf("routing policy state = %+v store=%q/%t calls=%d", state, store.setMode, store.setPriv, coreRuntime.setCalls)
	}
}

func TestRoutingModeCoordinatorPersistsWhileStopped(t *testing.T) {
	store := &fakeRoutingModeStore{snapshot: storage.Snapshot{
		RoutingMode:   storage.RoutingModeRule,
		PrivateDirect: true,
	}}
	coreRuntime := &fakeRoutingModeCore{snapshot: core.Snapshot{State: core.StateStopped}}
	coordinator, _ := NewRoutingModeCoordinator(store, coreRuntime)
	state, err := coordinator.Set(context.Background(), storage.RoutingModeDirect)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != storage.RoutingModeDirect || !state.PrivateDirect ||
		state.Applied || state.LiveMode != "" || state.LivePrivateDirect != nil ||
		coreRuntime.setCalls != 0 {
		t.Fatalf("stopped routing policy state = %+v calls=%d", state, coreRuntime.setCalls)
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
	privateDirect := true
	if _, err := coordinator.SetPolicy(context.Background(), storage.RoutingModeGlobal, &privateDirect); !errors.Is(err, ErrLiveRoutingModeUpdate) {
		t.Fatalf("live update error = %v", err)
	}
	if store.snapshot.RoutingMode != storage.RoutingModeGlobal || !store.snapshot.PrivateDirect {
		t.Fatalf("failed live update did not retain durable policy: %+v", store.snapshot)
	}
}

func TestRoutingModeCoreNamesKeepPrivatePolicyIndependent(t *testing.T) {
	cases := []struct {
		mode    storage.RoutingMode
		private bool
		want    string
	}{
		{storage.RoutingModeRule, true, "Rule"},
		{storage.RoutingModeRule, false, "RuleNoPrivate"},
		{storage.RoutingModeGlobal, true, "Global"},
		{storage.RoutingModeGlobal, false, "GlobalNoPrivate"},
		{storage.RoutingModeDirect, true, "Direct"},
		{storage.RoutingModeDirect, false, "Direct"},
	}
	for _, tc := range cases {
		got, err := routingModeCoreName(tc.mode, tc.private)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("core mode for %q/%t = %q, want %q", tc.mode, tc.private, got, tc.want)
		}
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
	if initial.Mode != string(storage.RoutingModeRule) || initial.PrivateDirect || initial.Applied {
		t.Fatalf("initial policy response = %+v", initial)
	}

	put := httptest.NewRecorder()
	handler.ServeHTTP(
		put,
		httptest.NewRequest(
			http.MethodPut,
			"/v1/routing/mode",
			strings.NewReader(`{"mode":"global","private_direct":true}`),
		),
	)
	if put.Code != http.StatusOK {
		t.Fatalf("policy PUT status=%d body=%s", put.Code, put.Body.String())
	}
	var updated apiv1.RoutingModeResponse
	if err := json.NewDecoder(put.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if updated.Mode != string(storage.RoutingModeGlobal) || !updated.PrivateDirect || updated.Applied {
		t.Fatalf("updated policy response = %+v", updated)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RoutingMode != storage.RoutingModeGlobal || !snapshot.PrivateDirect {
		t.Fatalf("persisted routing policy = %+v", snapshot)
	}

	privateOnly := httptest.NewRecorder()
	handler.ServeHTTP(
		privateOnly,
		httptest.NewRequest(
			http.MethodPut,
			"/v1/routing/mode",
			strings.NewReader(`{"private_direct":false}`),
		),
	)
	if privateOnly.Code != http.StatusOK {
		t.Fatalf("private-only PUT status=%d body=%s", privateOnly.Code, privateOnly.Body.String())
	}
	var privateUpdated apiv1.RoutingModeResponse
	if err := json.NewDecoder(privateOnly.Body).Decode(&privateUpdated); err != nil {
		t.Fatal(err)
	}
	if privateUpdated.Mode != string(storage.RoutingModeGlobal) || privateUpdated.PrivateDirect {
		t.Fatalf("private-only response = %+v", privateUpdated)
	}
	snapshot, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RoutingMode != storage.RoutingModeGlobal || snapshot.PrivateDirect {
		t.Fatalf("private-only update changed wrong fields: %+v", snapshot)
	}

	empty := httptest.NewRecorder()
	handler.ServeHTTP(
		empty,
		httptest.NewRequest(http.MethodPut, "/v1/routing/mode", strings.NewReader(`{}`)),
	)
	if empty.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty policy status=%d body=%s", empty.Code, empty.Body.String())
	}

	bad := httptest.NewRecorder()
	handler.ServeHTTP(
		bad,
		httptest.NewRequest(http.MethodPut, "/v1/routing/mode", strings.NewReader(`{"mode":"unsupported"}`)),
	)
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid mode status=%d body=%s", bad.Code, bad.Body.String())
	}

	unknown := httptest.NewRecorder()
	handler.ServeHTTP(
		unknown,
		httptest.NewRequest(
			http.MethodPut,
			"/v1/routing/mode",
			strings.NewReader(`{"private_direct":true,"unknown":1}`),
		),
	)
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown-field status=%d body=%s", unknown.Code, unknown.Body.String())
	}
}
