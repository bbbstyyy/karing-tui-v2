//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type daemonCoreRuntime interface {
	Run(context.Context) error
	WaitReady(context.Context) error
	Start(context.Context) error
	Stop(context.Context) error
	Snapshot() core.Snapshot
}

type managedCoreRuntime interface {
	daemonCoreRuntime
	Check(context.Context, Generation) error
	Activate(context.Context, Generation) error
	Verify(context.Context, Generation) error
	Rollback(context.Context, *Generation) error
	ReconcileRecovery(context.Context) error
}

type serverRuntime struct {
	core         daemonCoreRuntime
	lifecycle    *LifecycleCoordinator
	recovery     *RecoveryCoordinator
	apply        *ApplyCoordinator
	declarations *DeclarationCompileCoordinator
	gate         *OperationGate

	mu         sync.RWMutex
	restoreErr string
}

func buildServerRuntime(ctx context.Context, store *storage.Store, paths runtimepath.Paths) (*serverRuntime, <-chan error, context.CancelFunc, error) {
	options, err := resolveManagedCoreOptions(paths)
	if err != nil {
		return nil, nil, nil, err
	}
	if options == nil {
		return nil, nil, nil, nil
	}
	managed, err := NewManagedCore(store, *options)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compose managed core: %w", err)
	}
	controlAddress, err := netip.ParseAddrPort(strings.TrimPrefix(options.ControlEndpoint, "http://"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse managed core control endpoint: %w", err)
	}
	ruleSets, err := coreartifact.NewStore(options.StateRoot)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compose rule-set resource store: %w", err)
	}
	schemaCompiler, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       options.Inbounds,
		ControlAddress: controlAddress,
		ControlSecret:  options.ControlSecret,
		RuleSets:       ruleSets,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compose declaration compiler: %w", err)
	}
	declarations, err := NewDeclarationCompileCoordinator(store, schemaCompiler)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compose declaration compile coordinator: %w", err)
	}
	return startServerRuntimeWithDeclarations(ctx, store, managed, declarations)
}

func startServerRuntime(ctx context.Context, store *storage.Store, managed managedCoreRuntime) (*serverRuntime, <-chan error, context.CancelFunc, error) {
	return startServerRuntimeWithDeclarations(ctx, store, managed, nil)
}

func startServerRuntimeWithDeclarations(
	ctx context.Context,
	store *storage.Store,
	managed managedCoreRuntime,
	declarations *DeclarationCompileCoordinator,
) (*serverRuntime, <-chan error, context.CancelFunc, error) {
	if store == nil {
		return nil, nil, nil, errors.New("server runtime store is nil")
	}
	if managed == nil {
		return nil, nil, nil, errors.New("server runtime core is nil")
	}
	lifecycle, err := NewLifecycleCoordinator(store, managed)
	if err != nil {
		return nil, nil, nil, err
	}
	recovery, err := NewRecoveryCoordinator(store, managed)
	if err != nil {
		return nil, nil, nil, err
	}
	apply, err := NewApplyCoordinator(store, managed, DefaultApplyPolicy())
	if err != nil {
		return nil, nil, nil, err
	}

	coreCtx, coreCancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- managed.Run(coreCtx)
	}()

	readyCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	err = managed.WaitReady(readyCtx)
	cancel()
	if err != nil {
		coreCancel()
		select {
		case <-errCh:
		case <-time.After(time.Second):
		}
		return nil, nil, nil, fmt.Errorf("start core supervisor engine: %w", err)
	}

	runtime := &serverRuntime{
		core:         managed,
		lifecycle:    lifecycle,
		recovery:     recovery,
		apply:        apply,
		declarations: declarations,
		gate:         NewOperationGate(),
	}
	return runtime, errCh, coreCancel, nil
}

func (r *serverRuntime) Restore(ctx context.Context) {
	if r == nil {
		return
	}
	restoreCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	err := r.gate.Do(restoreCtx, "core-restore", func(operationCtx context.Context) error {
		recovered, err := r.recovery.Reconcile(operationCtx)
		if err != nil {
			return err
		}
		if recovered {
			return nil
		}
		return r.lifecycle.Restore(operationCtx)
	})
	r.mu.Lock()
	if err != nil {
		r.restoreErr = err.Error()
	} else {
		r.restoreErr = ""
	}
	r.mu.Unlock()
}

func (r *serverRuntime) RestoreError() string {
	if r == nil {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.restoreErr
}

func (r *serverRuntime) Snapshot() core.Snapshot {
	if r == nil || r.core == nil {
		return core.Snapshot{}
	}
	return r.core.Snapshot()
}

func (r *serverRuntime) CurrentSelectionReady() bool {
	if r == nil || r.core == nil {
		return false
	}
	_, canSelect := r.core.(interface {
		SelectCurrent(context.Context, string) error
	})
	_, canRead := r.core.(interface {
		CurrentSelection(context.Context) (string, error)
	})
	return canSelect && canRead
}

func (r *serverRuntime) SelectCurrent(ctx context.Context, outboundTag string) error {
	if !r.CurrentSelectionReady() {
		return errors.New("current selection control is not configured")
	}
	controller := r.core.(interface {
		SelectCurrent(context.Context, string) error
	})
	return r.gate.Do(ctx, "selection-set", func(operationCtx context.Context) error {
		return controller.SelectCurrent(operationCtx, outboundTag)
	})
}

func (r *serverRuntime) CurrentSelection(ctx context.Context) (string, error) {
	if !r.CurrentSelectionReady() {
		return "", errors.New("current selection control is not configured")
	}
	controller := r.core.(interface {
		CurrentSelection(context.Context) (string, error)
	})
	return controller.CurrentSelection(ctx)
}

func (r *serverRuntime) Start(ctx context.Context) error {
	if r == nil {
		return errors.New("core runtime is not configured")
	}
	return r.gate.Do(ctx, "core-start", r.lifecycle.Start)
}

func (r *serverRuntime) Stop(ctx context.Context) error {
	if r == nil {
		return errors.New("core runtime is not configured")
	}
	return r.gate.Do(ctx, "core-stop", r.lifecycle.Stop)
}

func (r *serverRuntime) ApplyNativeArtifact(
	ctx context.Context,
	expectedRevision uint64,
	artifact compiler.NativeConfigArtifact,
) (storage.Attempt, error) {
	if r == nil || r.apply == nil {
		return storage.Attempt{}, errors.New("managed apply runtime is not configured")
	}
	var attempt storage.Attempt
	err := r.gate.Do(ctx, "config-apply", func(operationCtx context.Context) error {
		var applyErr error
		attempt, applyErr = r.applyNativeArtifact(operationCtx, expectedRevision, artifact)
		return applyErr
	})
	return attempt, err
}

func (r *serverRuntime) applyNativeArtifact(
	ctx context.Context,
	expectedRevision uint64,
	artifact compiler.NativeConfigArtifact,
) (storage.Attempt, error) {
	if r == nil || r.apply == nil {
		return storage.Attempt{}, errors.New("managed apply runtime is not configured")
	}
	if err := artifact.ValidateDeclarationBinding(true); err != nil {
		return storage.Attempt{}, fmt.Errorf("validate declaration provenance: %w", err)
	}
	manifest, sourceMap, err := artifact.MetadataJSON()
	if err != nil {
		return storage.Attempt{}, fmt.Errorf("serialize compiled generation metadata: %w", err)
	}
	return r.apply.ApplyCompiled(ctx, expectedRevision, CompiledGenerationArtifacts{
		Config:    artifact.JSON,
		Manifest:  manifest,
		SourceMap: sourceMap,
	})
}

func (r *serverRuntime) ApplyCompiled(ctx context.Context, expectedRevision uint64, config []byte) (storage.Attempt, error) {
	if r == nil || r.apply == nil {
		return storage.Attempt{}, errors.New("managed apply runtime is not configured")
	}

	var attempt storage.Attempt
	err := r.gate.Do(ctx, "config-apply", func(operationCtx context.Context) error {
		var applyErr error
		attempt, applyErr = r.apply.Apply(operationCtx, expectedRevision, config)
		return applyErr
	})
	return attempt, err
}

func (r *serverRuntime) ManagedApplyReady() bool {
	return r != nil && r.apply != nil
}

func (r *serverRuntime) DeclarationCompilerReady() bool {
	return r != nil && r.declarations != nil
}

func (r *serverRuntime) DeclarationApplyReady() bool {
	return r != nil && r.declarations != nil && r.apply != nil
}

func (r *serverRuntime) ApplyDeclarationRevision(
	ctx context.Context,
	declarationRevision uint64,
	expectedConfigRevision uint64,
) (storage.Attempt, compiler.NativeConfigArtifact, error) {
	if r == nil || r.declarations == nil {
		return storage.Attempt{}, compiler.NativeConfigArtifact{}, errors.New("declaration compiler runtime is not configured")
	}
	if r.apply == nil {
		return storage.Attempt{}, compiler.NativeConfigArtifact{}, errors.New("managed apply runtime is not configured")
	}

	var (
		attempt  storage.Attempt
		artifact compiler.NativeConfigArtifact
	)
	err := r.gate.Do(ctx, "declaration-apply", func(operationCtx context.Context) error {
		var compileErr error
		artifact, compileErr = r.declarations.CompileRevision(operationCtx, declarationRevision)
		if compileErr != nil {
			return compileErr
		}
		var applyErr error
		attempt, applyErr = r.applyNativeArtifact(operationCtx, expectedConfigRevision, artifact)
		return applyErr
	})
	return attempt, artifact, err
}

func (r *serverRuntime) CompileDeclarationRevision(
	ctx context.Context,
	revision uint64,
) (compiler.NativeConfigArtifact, error) {
	if r == nil || r.declarations == nil {
		return compiler.NativeConfigArtifact{}, errors.New("declaration compiler runtime is not configured")
	}
	var artifact compiler.NativeConfigArtifact
	err := r.gate.Do(ctx, "declaration-compile", func(operationCtx context.Context) error {
		var compileErr error
		artifact, compileErr = r.declarations.CompileRevision(operationCtx, revision)
		return compileErr
	})
	return artifact, err
}

func (r *serverRuntime) ActiveOperation() OperationSnapshot {
	if r == nil {
		return OperationSnapshot{}
	}
	return r.gate.Snapshot()
}
