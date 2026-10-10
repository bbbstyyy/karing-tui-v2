package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type recoveryStore interface {
	Snapshot(context.Context) (storage.Snapshot, error)
	ResolveRecovery(context.Context) error
}

type recoveryCore interface {
	ReconcileRecovery(context.Context) error
}

type RecoveryCoordinator struct {
	store recoveryStore
	core  recoveryCore
}

func NewRecoveryCoordinator(store recoveryStore, core recoveryCore) (*RecoveryCoordinator, error) {
	if store == nil {
		return nil, errors.New("recovery store is nil")
	}
	if core == nil {
		return nil, errors.New("recovery core is nil")
	}
	return &RecoveryCoordinator{store: store, core: core}, nil
}

func (c *RecoveryCoordinator) Reconcile(ctx context.Context) (bool, error) {
	snapshot, err := c.store.Snapshot(ctx)
	if err != nil {
		return false, fmt.Errorf("read state before recovery reconcile: %w", err)
	}
	if !snapshot.RecoveryRequired {
		return false, nil
	}

	if err := c.core.ReconcileRecovery(ctx); err != nil {
		return true, fmt.Errorf("reconcile interrupted apply against confirmed generation: %w", err)
	}
	if err := c.store.ResolveRecovery(ctx); err != nil {
		return true, fmt.Errorf("clear recovery-required state after reconcile: %w", err)
	}
	return true, nil
}
