package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type lifecycleStore interface {
	Snapshot(context.Context) (storage.Snapshot, error)
	SetCoreDesiredState(context.Context, storage.CoreDesiredState) error
}

type coreController interface {
	Start(context.Context) error
	Stop(context.Context) error
}

type LifecycleCoordinator struct {
	store      lifecycleStore
	controller coreController
}

func NewLifecycleCoordinator(store lifecycleStore, controller coreController) (*LifecycleCoordinator, error) {
	if store == nil {
		return nil, errors.New("core lifecycle store is nil")
	}
	if controller == nil {
		return nil, errors.New("core lifecycle controller is nil")
	}
	return &LifecycleCoordinator{store: store, controller: controller}, nil
}

func (c *LifecycleCoordinator) Restore(ctx context.Context) error {
	snapshot, err := c.store.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("read persisted core lifecycle intent: %w", err)
	}
	if snapshot.RecoveryRequired {
		return storage.ErrRecoveryRequired
	}
	switch snapshot.CoreDesiredState {
	case storage.CoreDesiredStopped:
		return nil
	case storage.CoreDesiredRunning:
		if err := c.controller.Start(ctx); err != nil {
			return fmt.Errorf("restore requested core start: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", storage.ErrInvalidCoreDesiredState, snapshot.CoreDesiredState)
	}
}

func (c *LifecycleCoordinator) Start(ctx context.Context) error {
	snapshot, err := c.store.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("read state before core start: %w", err)
	}
	if snapshot.RecoveryRequired {
		return storage.ErrRecoveryRequired
	}

	if snapshot.CoreDesiredState != storage.CoreDesiredRunning {
		if err := c.store.SetCoreDesiredState(ctx, storage.CoreDesiredRunning); err != nil {
			return fmt.Errorf("persist core start intent: %w", err)
		}
	}
	if err := c.controller.Start(ctx); err != nil {
		return fmt.Errorf("start core supervisor: %w", err)
	}
	return nil
}

func (c *LifecycleCoordinator) Stop(ctx context.Context) error {
	if err := c.store.SetCoreDesiredState(ctx, storage.CoreDesiredStopped); err != nil {
		return fmt.Errorf("persist core stop intent: %w", err)
	}
	if err := c.controller.Stop(ctx); err != nil && !errors.Is(err, core.ErrNotRunning) {
		return fmt.Errorf("stop core supervisor: %w", err)
	}
	return nil
}
