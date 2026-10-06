//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
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
}

type serverRuntime struct {
	core      daemonCoreRuntime
	lifecycle *LifecycleCoordinator
	apply     *ApplyCoordinator
	gate      *OperationGate

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
	return startServerRuntime(ctx, store, managed)
}

func startServerRuntime(ctx context.Context, store *storage.Store, managed managedCoreRuntime) (*serverRuntime, <-chan error, context.CancelFunc, error) {
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
		core:      managed,
		lifecycle: lifecycle,
		apply:     apply,
		gate:      NewOperationGate(),
	}
	return runtime, errCh, coreCancel, nil
}

func (r *serverRuntime) Restore(ctx context.Context) {
	if r == nil {
		return
	}
	restoreCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	err := r.gate.Do(restoreCtx, "core-restore", r.lifecycle.Restore)
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
	manifest, sourceMap, err := artifact.MetadataJSON()
	if err != nil {
		return storage.Attempt{}, fmt.Errorf("serialize compiled generation metadata: %w", err)
	}
	var attempt storage.Attempt
	err = r.gate.Do(ctx, "config-apply", func(operationCtx context.Context) error {
		var applyErr error
		attempt, applyErr = r.apply.ApplyCompiled(operationCtx, expectedRevision, CompiledGenerationArtifacts{
			Config:    artifact.JSON,
			Manifest:  manifest,
			SourceMap: sourceMap,
		})
		return applyErr
	})
	return attempt, err
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

func (r *serverRuntime) ActiveOperation() OperationSnapshot {
	if r == nil {
		return OperationSnapshot{}
	}
	return r.gate.Snapshot()
}
