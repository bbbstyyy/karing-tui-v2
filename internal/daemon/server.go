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
	"strings"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
	"github.com/bbbstyyy/karing-tui-v2/internal/version"
)

var ErrAlreadyRunning = errors.New("daemon already running")

type Server struct {
	paths    runtimepath.Paths
	started  time.Time
	ruleSets *coreartifact.Store
}

func New(paths runtimepath.Paths) *Server {
	return &Server{paths: paths, started: time.Now().UTC()}
}

func (s *Server) Run(ctx context.Context) error {
	if err := s.paths.Ensure(); err != nil {
		return err
	}
	retentionPolicy, err := resolveStorageRetentionPolicy()
	if err != nil {
		return fmt.Errorf("configure storage retention: %w", err)
	}
	if err := prepareSocket(s.paths.Socket); err != nil {
		return err
	}
	ruleSets, err := coreartifact.NewStore(filepath.Join(s.paths.State, "core"))
	if err != nil {
		return fmt.Errorf("configure rule-set resource store: %w", err)
	}
	s.ruleSets = ruleSets

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

	store, err := storage.OpenWithRetention(ctx, s.paths.Database, retentionPolicy)
	if err != nil {
		return fmt.Errorf("open daemon state: %w", err)
	}
	defer store.Close()
	if _, err := store.RecoverInterrupted(ctx); err != nil {
		return fmt.Errorf("recover interrupted apply journal: %w", err)
	}
	if _, err := store.RecoverInterruptedProfileUpdates(ctx); err != nil {
		return fmt.Errorf("recover interrupted profile updates: %w", err)
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

	profileScheduler, err := buildProfileRefreshScheduler(store, runtime)
	if err != nil {
		return fmt.Errorf("configure profile refresh scheduler: %w", err)
	}
	profileErrCh := make(chan error, 1)
	go func() {
		profileErrCh <- profileScheduler.Run(daemonCtx)
	}()

	httpServer := newDaemonHTTPServer(s.handler(store, runtime))

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
		cause       error
		httpDone    bool
		coreDone    bool
		profileDone bool
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
	case err := <-profileErrCh:
		profileDone = true
		if ctx.Err() == nil {
			if err == nil {
				err = errors.New("profile refresh scheduler exited unexpectedly")
			}
			cause = fmt.Errorf("profile refresh scheduler: %w", err)
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
	if !profileDone {
		if err := waitError(profileErrCh, 12*time.Second); err != nil {
			cause = errors.Join(cause, fmt.Errorf("wait for profile refresh scheduler shutdown: %w", err))
		}
	}
	return cause
}

func newDaemonHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       65 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

func (s *Server) handler(store *storage.Store, runtime *serverRuntime) http.Handler {
	mux := http.NewServeMux()
	profileOperations := newProfileOperationGate(maxConcurrentProfileMetadataRefreshes)
	profileMetadataRefresh := registerProfileMetadataRoutes(mux, store, runtime, profileOperations)
	profileFullRefresh := registerProfileSourceRoutes(mux, store, runtime, profileOperations)
	registerProfileNodeRoutes(mux, store, profileOperations)
	registerProfileSnapshotPreviewRoutes(mux, store, profileOperations)
	registerProfileDeclarationStageRoutes(mux, store, profileOperations)
	var selectionCore currentSelectionCore
	if runtime != nil && runtime.CurrentSelectionReady() {
		selectionCore = runtime
	}
	selection, _ := NewCurrentSelectionCoordinator(store, selectionCore)
	routeExplain, _ := NewRouteExplainCoordinator(store)
	var observedConnections *ObservedConnectionsCoordinator
	if runtime != nil && runtime.ConnectionsReady() {
		observedConnections, _ = NewObservedConnectionsCoordinator(store, runtime, routeExplain)
	}
	var modeCore routingModeCore
	if runtime != nil && runtime.RoutingModeReady() {
		modeCore = runtime
	}
	routingMode, _ := NewRoutingModeCoordinator(store, modeCore)
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
		currentDeclaration, err := store.CurrentDeclaration(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiv1.ErrorResponse{Error: "read declaration state"})
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
			DeclarationRevision:       currentDeclaration.Revision,
			AppliedGenerationID:       snapshot.AppliedGenerationID,
			LastKnownGoodGenerationID: snapshot.LastKnownGoodGenerationID,
			RecoveryRequired:          snapshot.RecoveryRequired,
			CoreDesiredState:          string(snapshot.CoreDesiredState),
			RoutingMode:               string(snapshot.RoutingMode),
			PrivateDirect:             snapshot.PrivateDirect,
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
		declarationCompileRuntime := runtime != nil && runtime.DeclarationCompilerReady()
		declarationApplyRuntime := runtime != nil && runtime.DeclarationApplyReady()
		currentSelectionLive := runtime != nil && runtime.CurrentSelectionReady()
		connectionObservation := runtime != nil && runtime.ConnectionsReady()
		routingModeLive := runtime != nil && runtime.RoutingModeReady()
		profileSelectedFetch := false
		if runtime != nil {
			_, profileSelectedFetch = runtime.SelectedInbound()
		}
		writeJSON(w, http.StatusOK, apiv1.CapabilitiesResponse{
			APIVersion: apiv1.Version,
			Capabilities: map[string]bool{
				"daemon":                      true,
				"unix_socket_api":             true,
				"secure_runtime_paths":        true,
				"proxy_only_import_guard":     true,
				"sqlite_state":                true,
				"storage_retention":           true,
				"storage_retention_api":       true,
				"declaration_revisions":       true,
				"declaration_generation_link": true,
				"declaration_schema_v1":       true,
				"declaration_cn_preset":       true,
				"declaration_region_append":   true,
				"declaration_commit_api":      true,
				"declaration_compile_preview": declarationCompileRuntime,
				"declaration_apply_api":       declarationApplyRuntime,
				"apply_journal":               true,
				"apply_coordinator":           true,
				"managed_apply":               declarationApplyRuntime,
				"managed_apply_runtime":       managedApplyRuntime,
				"crash_recovery_state":        true,
				"crash_recovery_reconcile":    coreEnabled,
				"persisted_core_intent":       true,
				"core_supervisor_engine":      true,
				"core_exec_runner":            true,
				"core_parent_death_signal":    true,
				"core_readiness_gate":         true,
				"core_clash_version_probe":    true,
				"core_build_approved":         true,
				"core_artifact_verifier":      true,
				"generation_artifacts":        true,
				"staged_generation_gc":        true,
				"core_verified_exec_runner":   true,
				"generation_bound_runner":     true,
				"managed_core_adapter":        true,
				"operation_serialization":     true,
				"core_runtime_options":        true,
				"core_distribution":           false,
				"lifecycle_coordinator":       true,
				"core_lifecycle_api":          coreEnabled,
				"proxy_inbound_model":         true,
				"mixed_inbound_probe":         true,
				"routing_ir_model":            true,
				"routing_match_ast":           true,
				"routing_rule_lowerer":        true,
				"routing_entry_scoping":       true,
				"routing_layer_switches":      true,
				"routing_target_registry":     true,
				"route_explain_simulated":     true,
				"route_explain_observed":      false,
				"connection_observation":      connectionObservation,
				"routing_mode_intent":         true,
				"routing_mode_api":            true,
				"routing_mode_live":           routingModeLive,
				"private_direct_policy":       true,
				"private_direct_live":         routingModeLive,
				"routing_rule_set_closure":    true,
				"routing_rule_set_store":      s.ruleSets != nil,
				"rule_set_upload_api":         s.ruleSets != nil,
				"selection_group_model":       true,
				"selection_group_lowerer":     true,
				"current_selection_intent":    true,
				"current_selection_api":       true,
				"current_selection_live":      currentSelectionLive,
				"basic_node_model":            true,
				"basic_node_lowerer":          true,
				"native_config_emitter":       true,
				"generation_metadata_store":   true,
				"compiled_artifact_apply":     true,
				"dns_dependency_model":        true,
				"outbound_dns_lowerer":        true,
				"native_outbound_dns":         true,
				"direct_proxy_dns_lowerer":    true,
				"proxy_dns_route_binding":     true,
				"group_dns_lowerer":           true,
				"group_dns_route_binding":     true,
				"dns_fallback_lowerer":        true,
				"dns_runtime_paths_observed":  true,
				"profile_source_state":        true,
				"profile_source_api":          true,
				"profile_refresh_api":         profileFullRefresh,
				"profile_node_overlays":       true,
				"profile_node_overlay_api":    true,
				"profile_preview_api":         true,
				"profile_overlay_runtime":     true,
				"profile_node_filter_state":   true,
				"profile_node_filter":         false,
				"profile_refresh_fetch":       true,
				"profile_refresh_scheduler":   true,
				"profile_metadata_api":        true,
				"profile_metadata_refresh":    profileMetadataRefresh,
				"profile_fetch_selected":      profileSelectedFetch,
				"profile_fetch_specific_node": false,
				"bounded_core_log_buffer":     true,
				"core_supervision":            coreEnabled,
				"proxy_inbounds":              false,
				"routing_ir":                  false,
				"cn_preset_snapshot":          true,
				"cn_preset_resource_refs":     true,
				"cn_preset_resource_audit":    true,
				"cn_preset_offline_bundle":    false,
				"cn_preset_overrides":         true,
				"cn_preset_linux_lowerer":     true,
				"cn_preset_process_name":      true,
				"cn_preset_interleaving":      true,
				"region_append_model":         true,
				"region_append_lowerer":       true,
				"cn_preset":                   false,
				"subscriptions":               false,
				"tui":                         false,
			},
		})
	})
	mux.HandleFunc("GET /v1/routing/mode", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		state, err := routingMode.Get(ctx)
		if err != nil {
			writeRoutingModeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, routingModeResponse(state))
	})
	mux.HandleFunc("PUT /v1/routing/mode", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		var request apiv1.RoutingModeRequest
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "decode routing mode request: " + err.Error()})
			return
		}
		if err := requireJSONEOF(decoder); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "decode routing mode request: " + err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		if request.Mode == "" && request.PrivateDirect == nil {
			writeJSON(w, http.StatusUnprocessableEntity, apiv1.ErrorResponse{Error: "routing policy update is empty"})
			return
		}
		state, err := routingMode.SetPolicy(ctx, storage.RoutingMode(request.Mode), request.PrivateDirect)
		if err != nil {
			writeRoutingModeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, routingModeResponse(state))
	})
	mux.HandleFunc("GET /v1/connections", func(w http.ResponseWriter, r *http.Request) {
		if observedConnections == nil {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "connection observation is not configured"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		response, err := observedConnections.List(ctx)
		if err != nil {
			writeObservedConnectionsError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, response)
	})
	mux.HandleFunc("POST /v1/route/explain", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		decoder.DisallowUnknownFields()
		var request apiv1.RouteExplainRequest
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "decode route explain request: " + err.Error()})
			return
		}
		if err := requireJSONEOF(decoder); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "decode route explain request: " + err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		response, err := routeExplain.Explain(ctx, request)
		if err != nil {
			writeRouteExplainError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, response)
	})
	mux.HandleFunc("GET /v1/selection/current", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		state, err := selection.Get(ctx)
		if err != nil {
			writeCurrentSelectionError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, currentSelectionResponse(state))
	})
	mux.HandleFunc("PUT /v1/selection/current", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, storage.MaxSelectionTargetBytes+1024))
		decoder.DisallowUnknownFields()
		var request apiv1.CurrentSelectionRequest
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "decode current selection request: " + err.Error()})
			return
		}
		if err := requireJSONEOF(decoder); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "decode current selection request: " + err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		state, err := selection.Set(ctx, request.Target)
		if err != nil {
			writeCurrentSelectionError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, currentSelectionResponse(state))
	})
	mux.HandleFunc("GET /v1/storage/retention", func(w http.ResponseWriter, r *http.Request) {
		report, err := store.RetentionStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiv1.ErrorResponse{Error: "read storage retention status: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, storageRetentionResponse(report))
	})
	mux.HandleFunc("POST /v1/storage/prune", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		defer cancel()
		report, err := store.PruneRetention(ctx)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusGatewayTimeout
			}
			writeJSON(w, status, apiv1.ErrorResponse{Error: "prune storage retention: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, storageRetentionResponse(report))
	})
	mux.HandleFunc("PUT /v1/rule-sets/{sha256}", func(w http.ResponseWriter, r *http.Request) {
		if s.ruleSets == nil {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "rule-set resource store is not configured"})
			return
		}
		format := r.URL.Query().Get("format")
		if format == "" {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "rule-set format is required"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		path, size, err := s.ruleSets.PutRuleSet(ctx, r.Body, r.PathValue("sha256"), format)
		if err != nil {
			status := http.StatusBadRequest
			switch {
			case errors.Is(err, coreartifact.ErrRuleSetTooLarge):
				status = http.StatusRequestEntityTooLarge
			case errors.Is(err, coreartifact.ErrRuleSetImmutable):
				status = http.StatusConflict
			case errors.Is(err, context.DeadlineExceeded):
				status = http.StatusGatewayTimeout
			}
			writeJSON(w, status, apiv1.ErrorResponse{Error: err.Error()})
			return
		}
		extension := filepath.Ext(path)
		hash := strings.TrimSuffix(filepath.Base(path), extension)
		writeJSON(w, http.StatusCreated, apiv1.RuleSetUploadResponse{
			SHA256: hash,
			Format: format,
			Bytes:  size,
		})
	})
	mux.HandleFunc("GET /v1/declaration/current", func(w http.ResponseWriter, r *http.Request) {
		current, err := store.CurrentDeclaration(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiv1.ErrorResponse{Error: "read current declaration"})
			return
		}
		writeJSON(w, http.StatusOK, declarationResponse(current))
	})
	mux.HandleFunc("POST /v1/declaration", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, storage.MaxDeclarationBytes+4096)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request apiv1.DeclarationCommitRequest
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "decode declaration request: " + err.Error()})
			return
		}
		var validateErr error
		if s.ruleSets != nil {
			validateErr = declaration.ValidateV1WithResolver(r.Context(), request.Document, s.ruleSets)
		} else {
			validateErr = declaration.ValidateV1(request.Document)
		}
		if validateErr != nil {
			status := http.StatusBadRequest
			if errors.Is(validateErr, declaration.ErrRuleSetResourceUnavailable) {
				status = http.StatusUnprocessableEntity
			}
			writeJSON(w, status, apiv1.ErrorResponse{Error: validateErr.Error()})
			return
		}
		committed, err := store.CommitDeclaration(r.Context(), request.ExpectedRevision, request.Document, request.Source)
		if err != nil {
			status := http.StatusInternalServerError
			switch {
			case errors.Is(err, storage.ErrDeclarationRevisionConflict):
				status = http.StatusConflict
			case errors.Is(err, storage.ErrInvalidDeclaration),
				errors.Is(err, storage.ErrDeclarationTooLarge):
				status = http.StatusBadRequest
			}
			writeJSON(w, status, apiv1.ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, declarationResponse(committed))
	})
	mux.HandleFunc("POST /v1/declaration/compile", func(w http.ResponseWriter, r *http.Request) {
		if runtime == nil || !runtime.DeclarationCompilerReady() {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "declaration compiler runtime is not configured"})
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		var request apiv1.DeclarationCompileRequest
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "decode declaration compile request: " + err.Error()})
			return
		}
		if request.Revision == 0 {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "declaration revision must be positive"})
			return
		}

		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 20*time.Second)
		defer cancel()
		artifact, err := runtime.CompileDeclarationRevision(ctx, request.Revision)
		if err != nil {
			status := http.StatusBadRequest
			switch {
			case errors.Is(err, storage.ErrDeclarationNotFound):
				status = http.StatusNotFound
			case errors.Is(err, declaration.ErrRuleSetResourceMissing),
				errors.Is(err, declaration.ErrRuleSetResourceUnavailable):
				status = http.StatusUnprocessableEntity
			case errors.Is(err, context.DeadlineExceeded):
				status = http.StatusGatewayTimeout
			}
			writeJSON(w, status, apiv1.ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiv1.DeclarationCompileResponse{
			Revision:          artifact.Manifest.DeclarationRevision,
			DeclarationSHA256: artifact.Manifest.DeclarationSHA256,
			NativeSchemaID:    artifact.Manifest.SchemaID,
			ConfigSHA256:      artifact.Manifest.ConfigSHA256,
			InboundTags:       append([]string(nil), artifact.Manifest.InboundTags...),
			OutboundTags:      append([]string(nil), artifact.Manifest.OutboundTags...),
			DNSServerTags:     append([]string(nil), artifact.Manifest.DNSServerTags...),
			RouteEntryCount:   len(artifact.SourceMap),
			RuleSetCount:      len(artifact.Manifest.RuleSets),
		})
	})
	mux.HandleFunc("POST /v1/declaration/apply", func(w http.ResponseWriter, r *http.Request) {
		if runtime == nil || !runtime.DeclarationApplyReady() {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "declaration apply runtime is not configured"})
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		var request apiv1.DeclarationApplyRequest
		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "decode declaration apply request: " + err.Error()})
			return
		}
		if request.DeclarationRevision == 0 {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "declaration revision must be positive"})
			return
		}

		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 75*time.Second)
		defer cancel()
		attempt, artifact, err := runtime.ApplyDeclarationRevision(
			ctx,
			request.DeclarationRevision,
			request.ExpectedConfigRevision,
		)
		if err != nil {
			status := http.StatusInternalServerError
			switch {
			case errors.Is(err, storage.ErrDeclarationNotFound):
				status = http.StatusNotFound
			case errors.Is(err, storage.ErrRevisionConflict),
				errors.Is(err, storage.ErrRecoveryRequired),
				errors.Is(err, storage.ErrApplyInProgress),
				errors.Is(err, core.ErrCircuitOpen):
				status = http.StatusConflict
			case errors.Is(err, declaration.ErrInvalidDocument),
				errors.Is(err, declaration.ErrUnsupportedSchema),
				errors.Is(err, declaration.ErrRuleSetResourceMissing),
				errors.Is(err, declaration.ErrRuleSetResourceUnavailable):
				status = http.StatusUnprocessableEntity
			case errors.Is(err, storage.ErrGenerationStorageBudget):
				status = http.StatusInsufficientStorage
			case errors.Is(err, context.DeadlineExceeded):
				status = http.StatusGatewayTimeout
			}
			writeJSON(w, status, apiv1.ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiv1.DeclarationApplyResponse{
			DeclarationRevision:  artifact.Manifest.DeclarationRevision,
			DeclarationSHA256:    artifact.Manifest.DeclarationSHA256,
			NativeSchemaID:       artifact.Manifest.SchemaID,
			ConfigSHA256:         artifact.Manifest.ConfigSHA256,
			AttemptID:            attempt.ID,
			GenerationID:         attempt.GenerationID,
			BaseConfigRevision:   attempt.BaseRevision,
			TargetConfigRevision: attempt.TargetRevision,
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

func writeObservedConnectionsError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrConnectionObservationUnavailable):
		status = http.StatusConflict
	case errors.Is(err, ErrConnectionObservationBusy),
		errors.Is(err, ErrConnectionGenerationChanged):
		status = http.StatusConflict
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	}
	writeJSON(w, status, apiv1.ErrorResponse{Error: err.Error()})
}

func routingModeResponse(value RoutingModeState) apiv1.RoutingModeResponse {
	return apiv1.RoutingModeResponse{
		Mode:              string(value.Mode),
		PrivateDirect:     value.PrivateDirect,
		Applied:           value.Applied,
		LiveMode:          string(value.LiveMode),
		LivePrivateDirect: value.LivePrivateDirect,
	}
}

func writeRoutingModeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, storage.ErrInvalidRoutingMode):
		status = http.StatusUnprocessableEntity
	case errors.Is(err, ErrLiveRoutingModeUpdate):
		status = http.StatusBadGateway
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	}
	writeJSON(w, status, apiv1.ErrorResponse{Error: err.Error()})
}

func writeRouteExplainError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrRouteExplainInput):
		status = http.StatusBadRequest
	case errors.Is(err, ErrRouteExplainUnavailable):
		status = http.StatusConflict
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	}
	writeJSON(w, status, apiv1.ErrorResponse{Error: err.Error()})
}

func currentSelectionResponse(value CurrentSelectionState) apiv1.CurrentSelectionResponse {
	response := apiv1.CurrentSelectionResponse{
		Target:         value.Target,
		RuntimeTag:     value.RuntimeTag,
		Persisted:      value.Persisted,
		Applied:        value.Applied,
		LiveRuntimeTag: value.LiveRuntimeTag,
	}
	if !value.UpdatedAt.IsZero() {
		response.UpdatedAt = value.UpdatedAt.Format(time.RFC3339Nano)
	}
	return response
}

func writeCurrentSelectionError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrCurrentSelectionUnavailable):
		status = http.StatusConflict
	case errors.Is(err, ErrCurrentSelectionTarget),
		errors.Is(err, storage.ErrInvalidSelectionIntent):
		status = http.StatusUnprocessableEntity
	case errors.Is(err, ErrLiveSelectionUpdate):
		status = http.StatusBadGateway
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	}
	writeJSON(w, status, apiv1.ErrorResponse{Error: err.Error()})
}

func storageRetentionResponse(value storage.RetentionReport) apiv1.StorageRetentionResponse {
	return apiv1.StorageRetentionResponse{
		ConfirmedGenerations:     value.Policy.ConfirmedGenerations,
		MaxGenerationBytes:       value.Policy.MaxGenerationBytes,
		LiveGenerationCount:      value.LiveGenerationCount,
		LiveGenerationBytes:      value.LiveGenerationBytes,
		ProtectedGenerationCount: value.ProtectedGenerationCount,
		ActiveAttemptCount:       value.ActiveAttemptCount,
		ArchivedAttemptCount:     value.ArchivedAttemptCount,
		ArchivedThisRun:          value.ArchivedThisRun,
		PrunedGenerationCount:    value.PrunedGenerationCount,
		ReclaimedGenerationBytes: value.ReclaimedGenerationBytes,
		OverBudget:               value.OverBudget,
	}
}

func declarationResponse(value storage.DeclarationRevision) apiv1.DeclarationResponse {
	return apiv1.DeclarationResponse{
		Revision:       value.Revision,
		ParentRevision: value.ParentRevision,
		SHA256:         value.SHA256,
		Source:         value.Source,
		CreatedAt:      value.CreatedAt.Format(time.RFC3339Nano),
		Document:       append(json.RawMessage(nil), value.DocumentJSON...),
	}
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
