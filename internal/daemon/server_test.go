package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
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
	if status.APIVersion != "v1" || status.CoreState != "not-configured" || status.CoreDesiredState != "stopped" || status.ConfigRevision != 0 || status.RecoveryRequired {
		t.Fatalf("unexpected status: %+v", status)
	}

	caps, err := api.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !caps.Capabilities["daemon"] || !caps.Capabilities["sqlite_state"] || !caps.Capabilities["apply_journal"] || !caps.Capabilities["apply_coordinator"] || caps.Capabilities["managed_apply"] || !caps.Capabilities["persisted_core_intent"] || !caps.Capabilities["core_build_approved"] || !caps.Capabilities["core_artifact_verifier"] || !caps.Capabilities["generation_artifacts"] || !caps.Capabilities["generation_bound_runner"] || !caps.Capabilities["managed_core_adapter"] || !caps.Capabilities["core_verified_exec_runner"] || caps.Capabilities["core_distribution"] || !caps.Capabilities["proxy_inbound_model"] || !caps.Capabilities["mixed_inbound_probe"] || caps.Capabilities["proxy_inbounds"] || caps.Capabilities["routing_ir"] {
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
