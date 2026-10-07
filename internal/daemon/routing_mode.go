package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrLiveRoutingModeUpdate = errors.New("live routing mode update failed")

type routingModeStore interface {
	Snapshot(context.Context) (storage.Snapshot, error)
	SetRoutingMode(context.Context, storage.RoutingMode) error
}

type routingModeCore interface {
	Snapshot() core.Snapshot
	SetRoutingMode(context.Context, storage.RoutingMode) error
	CurrentRoutingMode(context.Context) (storage.RoutingMode, error)
}

type RoutingModeState struct {
	Mode     storage.RoutingMode
	Applied  bool
	LiveMode storage.RoutingMode
}

type RoutingModeCoordinator struct {
	store routingModeStore
	core  routingModeCore
}

func NewRoutingModeCoordinator(store routingModeStore, core routingModeCore) (*RoutingModeCoordinator, error) {
	if store == nil {
		return nil, errors.New("routing mode store is nil")
	}
	return &RoutingModeCoordinator{store: store, core: core}, nil
}

func (c *RoutingModeCoordinator) Get(ctx context.Context) (RoutingModeState, error) {
	snapshot, err := c.store.Snapshot(ctx)
	if err != nil {
		return RoutingModeState{}, err
	}
	state := RoutingModeState{Mode: snapshot.RoutingMode}
	if c.core == nil || c.core.Snapshot().State != core.StateRunning {
		return state, nil
	}
	live, err := c.core.CurrentRoutingMode(ctx)
	if err != nil {
		return state, fmt.Errorf("%w: read live mode: %v", ErrLiveRoutingModeUpdate, err)
	}
	state.LiveMode = live
	state.Applied = live == snapshot.RoutingMode
	return state, nil
}

func (c *RoutingModeCoordinator) Set(ctx context.Context, mode storage.RoutingMode) (RoutingModeState, error) {
	if err := mode.Validate(); err != nil {
		return RoutingModeState{}, err
	}
	if err := c.store.SetRoutingMode(ctx, mode); err != nil {
		return RoutingModeState{}, err
	}
	state := RoutingModeState{Mode: mode}
	if c.core == nil || c.core.Snapshot().State != core.StateRunning {
		return state, nil
	}
	if err := c.core.SetRoutingMode(ctx, mode); err != nil {
		return state, fmt.Errorf("%w: intent persisted but core update failed: %v", ErrLiveRoutingModeUpdate, err)
	}
	live, err := c.core.CurrentRoutingMode(ctx)
	if err != nil {
		return state, fmt.Errorf("%w: intent persisted but readback failed: %v", ErrLiveRoutingModeUpdate, err)
	}
	state.LiveMode = live
	state.Applied = live == mode
	if !state.Applied {
		return state, fmt.Errorf("%w: core readback is %q, want %q", ErrLiveRoutingModeUpdate, live, mode)
	}
	return state, nil
}

func routingModeCoreName(mode storage.RoutingMode) (string, error) {
	switch mode {
	case storage.RoutingModeRule:
		return "Rule", nil
	case storage.RoutingModeGlobal:
		return "Global", nil
	case storage.RoutingModeDirect:
		return "Direct", nil
	default:
		return "", mode.Validate()
	}
}

func routingModeFromCore(name string) (storage.RoutingMode, error) {
	switch name {
	case "Rule":
		return storage.RoutingModeRule, nil
	case "Global":
		return storage.RoutingModeGlobal, nil
	case "Direct":
		return storage.RoutingModeDirect, nil
	default:
		return "", fmt.Errorf("%w: core mode %q", storage.ErrInvalidRoutingMode, name)
	}
}
