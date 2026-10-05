package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
	"github.com/bbbstyyy/karing-tui-v2/internal/version"
)

var ErrAlreadyRunning = errors.New("daemon already running")

type Server struct {
	paths   runtimepath.Paths
	started time.Time
}

func New(paths runtimepath.Paths) *Server {
	return &Server{paths: paths, started: time.Now().UTC()}
}

func (s *Server) Run(ctx context.Context) error {
	if err := s.paths.Ensure(); err != nil {
		return err
	}
	if err := prepareSocket(s.paths.Socket); err != nil {
		return err
	}

	listener, err := net.Listen("unix", s.paths.Socket)
	if err != nil {
		if isSocketActive(s.paths.Socket) {
			return ErrAlreadyRunning
		}
		return fmt.Errorf("listen on unix socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(s.paths.Socket)

	if err := os.Chmod(s.paths.Socket, 0o600); err != nil {
		return fmt.Errorf("secure unix socket: %w", err)
	}

	store, err := storage.Open(ctx, s.paths.Database)
	if err != nil {
		return fmt.Errorf("open daemon state: %w", err)
	}
	defer store.Close()
	if _, err := store.RecoverInterrupted(ctx); err != nil {
		return fmt.Errorf("recover interrupted apply journal: %w", err)
	}

	daemonCtx, daemonCancel := context.WithCancel(ctx)
	defer daemonCancel()

	runtime, coreErrCh, coreCancel, err := buildServerRuntime(daemonCtx, store, s.paths)
	if err != nil {
		return fmt.Errorf("configure managed core runtime: %w", err)
	}
	if coreCancel != nil {
		defer coreCancel()
	}

	httpServer := &http.Server{
		Handler:           s.handler(store, runtime),
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	httpErrCh := make(chan error, 1)
	go func() {
		err := httpServer.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErrCh <- err
			return
		}
		httpErrCh <- nil
	}()

	if runtime != nil {
		go runtime.Restore(daemonCtx)
	}

	var (
		cause    error
		httpDone bool
		coreDone bool
	)
	select {
	case <-ctx.Done():
	case err := <-httpErrCh:
		httpDone = true
		cause = err
	case err := <-coreErrCh:
		coreDone = true
		if ctx.Err() == nil {
			if err == nil {
				err = errors.New("core supervisor exited unexpectedly")
			}
			cause = fmt.Errorf("core supervisor engine: %w", err)
		} else {
			cause = err
		}
	}

	daemonCancel()
	if coreCancel != nil {
		coreCancel()
	}

	if !httpDone {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		shutdownErr := httpServer.Shutdown(shutdownCtx)
		cancel()
		if shutdownErr != nil {
			cause = errors.Join(cause, fmt.Errorf("shutdown daemon API: %w", shutdownErr))
		}
		if err := waitError(httpErrCh, 3*time.Second); err != nil {
			cause = errors.Join(cause, fmt.Errorf("wait for daemon API shutdown: %w", err))
		}
	}

	if coreErrCh != nil && !coreDone {
		if err := waitError(coreErrCh, 12*time.Second); err != nil {
			cause = errors.Join(cause, fmt.Errorf("wait for core supervisor shutdown: %w", err))
		}
	}
	return cause
}

func (s *Server) handler(store *storage.Store, runtime *serverRuntime) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := store.Snapshot(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "state database unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, apiv1.HealthResponse{Status: "ok"})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		snapshot, err := store.Snapshot(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiv1.ErrorResponse{Error: "read persistent state"})
			return
		}
		now := time.Now().UTC()
		response := apiv1.StatusResponse{
			APIVersion:                apiv1.Version,
			DaemonVersion:             version.Version,
			DaemonCommit:              version.Commit,
			PID:                       os.Getpid(),
			StartedAt:                 s.started.Format(time.RFC3339Nano),
			UptimeSeconds:             int64(now.Sub(s.started).Seconds()),
			ConfigRevision:            snapshot.Revision,
			AppliedGenerationID:       snapshot.AppliedGenerationID,
			LastKnownGoodGenerationID: snapshot.LastKnownGoodGenerationID,
			RecoveryRequired:          snapshot.RecoveryRequired,
			CoreDesiredState:          string(snapshot.CoreDesiredState),
			CoreState:                 "not-configured",
		}
		if runtime != nil {
			coreSnapshot := runtime.Snapshot()
			response.CoreConfigured = true
			response.CoreState = string(coreSnapshot.State)
			response.CorePID = coreSnapshot.PID
			response.CoreCircuitOpen = coreSnapshot.CircuitOpen
			response.CoreConsecutiveFailures = coreSnapshot.ConsecutiveFails
			response.CoreLastError = coreSnapshot.LastError
			if response.CoreLastError == "" {
				response.CoreLastError = runtime.RestoreError()
			}
			response.ActiveOperation = runtime.ActiveOperation().Name
		}
		writeJSON(w, http.StatusOK, response)
	})
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, _ *http.Request) {
		coreEnabled := runtime != nil
		managedApplyRuntime := runtime != nil && runtime.ManagedApplyReady()
		writeJSON(w, http.StatusOK, apiv1.CapabilitiesResponse{
			APIVersion: apiv1.Version,
			Capabilities: map[string]bool{
				"daemon":                    true,
				"unix_socket_api":           true,
				"secure_runtime_paths":      true,
				"proxy_only_import_guard":   true,
				"sqlite_state":              true,
				"apply_journal":             true,
				"apply_coordinator":         true,
				"managed_apply":             false,
				"managed_apply_runtime":     managedApplyRuntime,
				"crash_recovery_state":      true,
				"persisted_core_intent":     true,
				"core_supervisor_engine":    true,
				"core_exec_runner":          true,
				"core_readiness_gate":       true,
				"core_clash_version_probe":  true,
				"core_build_approved":       true,
				"core_artifact_verifier":    true,
				"generation_artifacts":      true,
				"core_verified_exec_runner": true,
				"generation_bound_runner":   true,
				"managed_core_adapter":      true,
				"operation_serialization":   true,
				"core_runtime_options":      true,
				"core_distribution":         false,
				"lifecycle_coordinator":     true,
				"core_lifecycle_api":        coreEnabled,
				"proxy_inbound_model":       true,
				"mixed_inbound_probe":       true,
				"routing_ir_model":          true,
				"routing_match_ast":         true,
				"routing_rule_lowerer":      true,
				"routing_entry_scoping":     true,
				"routing_target_registry":   true,
				"routing_rule_set_closure":  true,
				"routing_rule_set_store":    true,
				"selection_group_model":     true,
				"selection_group_lowerer":   true,
				"basic_node_model":          true,
				"basic_node_lowerer":        true,
				"native_config_emitter":     true,
				"dns_dependency_model":      true,
				"outbound_dns_lowerer":      true,
				"native_outbound_dns":       true,
				"direct_proxy_dns_lowerer":  true,
				"proxy_dns_route_binding":   true,
				"group_dns_lowerer":         true,
				"group_dns_route_binding":   true,
				"bounded_core_log_buffer":   true,
				"core_supervision":          coreEnabled,
				"proxy_inbounds":            false,
				"routing_ir":                false,
				"cn_preset":                 false,
				"subscriptions":             false,
				"tui":                       false,
			},
		})
	})
	mux.HandleFunc("POST /v1/core/start", func(w http.ResponseWriter, r *http.Request) {
		runCoreOperation(w, r, runtime, "start")
	})
	mux.HandleFunc("POST /v1/core/stop", func(w http.ResponseWriter, r *http.Request) {
		runCoreOperation(w, r, runtime, "stop")
	})
	return mux
}

func runCoreOperation(w http.ResponseWriter, r *http.Request, runtime *serverRuntime, operation string) {
	if runtime == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "core runtime is not configured"})
		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Second)
	defer cancel()

	var err error
	switch operation {
	case "start":
		err = runtime.Start(ctx)
	case "stop":
		err = runtime.Stop(ctx)
	default:
		writeJSON(w, http.StatusNotFound, apiv1.ErrorResponse{Error: "unknown core operation"})
		return
	}
	if err == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, storage.ErrRecoveryRequired),
		errors.Is(err, ErrNoAppliedGeneration),
		errors.Is(err, core.ErrCircuitOpen):
		status = http.StatusConflict
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	}
	writeJSON(w, status, apiv1.ErrorResponse{Error: err.Error()})
}

func waitError(ch <-chan error, timeout time.Duration) error {
	if ch == nil {
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-ch:
		return err
	case <-timer.C:
		return errors.New("timed out waiting for component shutdown")
	}
}

func prepareSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect unix socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket runtime path %s", path)
	}
	if isSocketActive(path) {
		return ErrAlreadyRunning
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale unix socket: %w", err)
	}
	return nil
}

func isSocketActive(path string) bool {
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func SocketDir(path string) string {
	return filepath.Dir(path)
}
