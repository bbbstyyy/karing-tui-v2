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

	httpServer := &http.Server{
		Handler:           s.handler(store),
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		err := httpServer.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown daemon API: %w", err)
		}
		return <-errCh
	case err := <-errCh:
		return err
	}
}

func (s *Server) handler(store *storage.Store) http.Handler {
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
		writeJSON(w, http.StatusOK, apiv1.StatusResponse{
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
		})
	})
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, apiv1.CapabilitiesResponse{
			APIVersion: apiv1.Version,
			Capabilities: map[string]bool{
				"daemon":                   true,
				"unix_socket_api":          true,
				"secure_runtime_paths":     true,
				"proxy_only_import_guard":  true,
				"sqlite_state":             true,
				"apply_journal":            true,
				"apply_coordinator":        true,
				"managed_apply":            false,
				"crash_recovery_state":     true,
				"persisted_core_intent":    true,
				"core_supervisor_engine":   true,
				"core_exec_runner":         true,
				"core_readiness_gate":      true,
				"core_clash_version_probe": true,
				"core_build_approved":      true,
				"core_artifact_verifier":   true,
				"generation_artifacts":      true,
				"core_verified_exec_runner": true,
				"core_distribution":        false,
				"lifecycle_coordinator":    true,
				"core_lifecycle_api":       false,
				"proxy_inbound_model":      true,
				"mixed_inbound_probe":      true,
				"bounded_core_log_buffer":  true,
				"core_supervision":         false,
				"proxy_inbounds":           false,
				"routing_ir":               false,
				"cn_preset":                false,
				"subscriptions":            false,
				"tui":                      false,
			},
		})
	})
	return mux
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
