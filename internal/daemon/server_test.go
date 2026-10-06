package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestServerStatusAndSingleInstance(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KARING_TUI_RUNTIME_DIR", base)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "data"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(base, "state"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(base, "cache"))
	t.Setenv(corePathEnv, "")
	t.Setenv(coreControlPortEnv, "")

	paths, err := runtimepath.Resolve()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := New(paths)
	errCh := make(chan error, 1)
	go func() { errCh <- first.Run(ctx) }()

	api := client.New(paths.Socket)
	deadline := time.Now().Add(4 * time.Second)
	var statusErr error
	for time.Now().Before(deadline) {
		requestCtx, requestCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		_, statusErr = api.Status(requestCtx)
		requestCancel()
		if statusErr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if statusErr != nil {
		t.Fatalf("daemon did not become ready: %v", statusErr)
	}

	status, err := api.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.APIVersion != "v1" || status.CoreConfigured || status.CoreState != "not-configured" || status.CoreDesiredState != "stopped" || status.ConfigRevision != 0 || status.RecoveryRequired {
		t.Fatalf("unexpected status: %+v", status)
	}

	caps, err := api.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !caps.Capabilities["daemon"] ||
		!caps.Capabilities["sqlite_state"] ||
		!caps.Capabilities["apply_journal"] ||
		!caps.Capabilities["apply_coordinator"] ||
		caps.Capabilities["managed_apply"] ||
		caps.Capabilities["managed_apply_runtime"] ||
		!caps.Capabilities["persisted_core_intent"] ||
		!caps.Capabilities["core_build_approved"] ||
		!caps.Capabilities["core_artifact_verifier"] ||
		!caps.Capabilities["generation_artifacts"] ||
		!caps.Capabilities["generation_bound_runner"] ||
		!caps.Capabilities["managed_core_adapter"] ||
		!caps.Capabilities["operation_serialization"] ||
		!caps.Capabilities["core_runtime_options"] ||
		!caps.Capabilities["core_verified_exec_runner"] ||
		caps.Capabilities["core_distribution"] ||
		caps.Capabilities["core_lifecycle_api"] ||
		caps.Capabilities["core_supervision"] ||
		!caps.Capabilities["proxy_inbound_model"] ||
		!caps.Capabilities["mixed_inbound_probe"] ||
		!caps.Capabilities["routing_ir_model"] ||
		!caps.Capabilities["routing_match_ast"] ||
		!caps.Capabilities["routing_rule_lowerer"] ||
		!caps.Capabilities["routing_entry_scoping"] ||
		!caps.Capabilities["routing_target_registry"] ||
		!caps.Capabilities["routing_rule_set_closure"] ||
		!caps.Capabilities["routing_rule_set_store"] ||
		!caps.Capabilities["selection_group_model"] ||
		!caps.Capabilities["selection_group_lowerer"] ||
		!caps.Capabilities["basic_node_model"] ||
		!caps.Capabilities["basic_node_lowerer"] ||
		!caps.Capabilities["native_config_emitter"] ||
		!caps.Capabilities["generation_metadata_store"] ||
		!caps.Capabilities["compiled_artifact_apply"] ||
		!caps.Capabilities["dns_dependency_model"] ||
		!caps.Capabilities["outbound_dns_lowerer"] ||
		!caps.Capabilities["native_outbound_dns"] ||
		!caps.Capabilities["direct_proxy_dns_lowerer"] ||
		!caps.Capabilities["proxy_dns_route_binding"] ||
		!caps.Capabilities["group_dns_lowerer"] ||
		!caps.Capabilities["group_dns_route_binding"] ||
		!caps.Capabilities["cn_preset_snapshot"] ||
		!caps.Capabilities["cn_preset_resource_refs"] ||
		!caps.Capabilities["region_append_model"] ||
		caps.Capabilities["proxy_inbounds"] ||
		caps.Capabilities["routing_ir"] {
		t.Fatalf("unexpected capabilities: %+v", caps.Capabilities)
	}

	dbInfo, err := os.Stat(paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	if got := dbInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("database permissions = %04o, want 0600", got)
	}

	second := New(paths)
	secondCtx, secondCancel := context.WithCancel(context.Background())
	defer secondCancel()
	if err := second.Run(secondCtx); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second daemon error = %v, want ErrAlreadyRunning", err)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("daemon shutdown: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("daemon did not shut down")
	}
}

type fakeDaemonCore struct {
	mu       sync.Mutex
	snapshot core.Snapshot
	startErr error
	stopErr  error
}

func (f *fakeDaemonCore) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (f *fakeDaemonCore) WaitReady(context.Context) error {
	return nil
}

func (f *fakeDaemonCore) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.snapshot = core.Snapshot{State: core.StateRunning, DesiredRunning: true, PID: 4321}
	return nil
}

func (f *fakeDaemonCore) Stop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopErr != nil {
		return f.stopErr
	}
	f.snapshot = core.Snapshot{State: core.StateStopped}
	return nil
}

func (f *fakeDaemonCore) Snapshot() core.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot
}

func TestCoreLifecycleAPIUpdatesPersistedIntentAndStatus(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()

	fake := &fakeDaemonCore{snapshot: core.Snapshot{State: core.StateStopped}}
	lifecycle, err := NewLifecycleCoordinator(store, fake)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &serverRuntime{
		core:      fake,
		lifecycle: lifecycle,
		gate:      NewOperationGate(),
	}
	handler := New(runtimepath.Paths{}).handler(store, runtime)

	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/v1/core/start", nil))
	if start.Code != http.StatusNoContent {
		t.Fatalf("start status = %d, body=%s", start.Code, start.Body.String())
	}
	persisted, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.CoreDesiredState != storage.CoreDesiredRunning {
		t.Fatalf("desired state = %q, want running", persisted.CoreDesiredState)
	}

	statusRecorder := httptest.NewRecorder()
	handler.ServeHTTP(statusRecorder, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if statusRecorder.Code != http.StatusOK {
		t.Fatalf("status code = %d", statusRecorder.Code)
	}
	var status apiv1.StatusResponse
	if err := json.NewDecoder(statusRecorder.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if !status.CoreConfigured || status.CoreState != string(core.StateRunning) || status.CorePID != 4321 {
		t.Fatalf("unexpected managed core status: %+v", status)
	}

	capsRecorder := httptest.NewRecorder()
	handler.ServeHTTP(capsRecorder, httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil))
	var caps apiv1.CapabilitiesResponse
	if err := json.NewDecoder(capsRecorder.Body).Decode(&caps); err != nil {
		t.Fatal(err)
	}
	if !caps.Capabilities["core_lifecycle_api"] || !caps.Capabilities["core_supervision"] {
		t.Fatalf("managed runtime capabilities not enabled: %+v", caps.Capabilities)
	}
	if caps.Capabilities["managed_apply_runtime"] {
		t.Fatalf("manually constructed lifecycle-only runtime unexpectedly advertises managed apply: %+v", caps.Capabilities)
	}

	stop := httptest.NewRecorder()
	handler.ServeHTTP(stop, httptest.NewRequest(http.MethodPost, "/v1/core/stop", nil))
	if stop.Code != http.StatusNoContent {
		t.Fatalf("stop status = %d, body=%s", stop.Code, stop.Body.String())
	}
	persisted, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.CoreDesiredState != storage.CoreDesiredStopped {
		t.Fatalf("desired state = %q, want stopped", persisted.CoreDesiredState)
	}
}

func TestCoreLifecycleAPIRejectsUnconfiguredRuntime(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()

	handler := New(runtimepath.Paths{}).handler(store, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/core/start", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("start without runtime status = %d, want 503", recorder.Code)
	}
}

func openServerTestStore(t *testing.T, ctx context.Context) *storage.Store {
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
