//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

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

type serverRuntime struct {
	core      daemonCoreRuntime
	lifecycle *LifecycleCoordinator
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

func startServerRuntime(ctx context.Context, store lifecycleStore, managed daemonCoreRuntime) (*serverRuntime, <-chan error, context.CancelFunc, error) {
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

func (r *serverRuntime) ActiveOperation() OperationSnapshot {
	if r == nil {
		return OperationSnapshot{}
	}
	return r.gate.Snapshot()
}
