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
	SetRoutingPolicy(context.Context, storage.RoutingMode, bool) error
}

type routingModeCore interface {
	Snapshot() core.Snapshot
	SetRoutingPolicy(context.Context, storage.RoutingMode, bool) error
	CurrentRoutingPolicy(context.Context) (storage.RoutingMode, bool, error)
}

type RoutingModeState struct {
	Mode              storage.RoutingMode
	PrivateDirect     bool
	Applied           bool
	LiveMode          storage.RoutingMode
	LivePrivateDirect *bool
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
	state := RoutingModeState{
		Mode:          snapshot.RoutingMode,
		PrivateDirect: snapshot.PrivateDirect,
	}
	if c.core == nil || c.core.Snapshot().State != core.StateRunning {
		return state, nil
	}
	liveMode, livePrivate, err := c.core.CurrentRoutingPolicy(ctx)
	if err != nil {
		return state, fmt.Errorf("%w: read live policy: %v", ErrLiveRoutingModeUpdate, err)
	}
	state.LiveMode = liveMode
	state.LivePrivateDirect = boolPtr(livePrivate)
	state.Applied = liveMode == snapshot.RoutingMode &&
		(snapshot.RoutingMode == storage.RoutingModeDirect || livePrivate == snapshot.PrivateDirect)
	return state, nil
}

func (c *RoutingModeCoordinator) Set(
	ctx context.Context,
	mode storage.RoutingMode,
) (RoutingModeState, error) {
	return c.SetPolicy(ctx, mode, nil)
}

func (c *RoutingModeCoordinator) SetPolicy(
	ctx context.Context,
	mode storage.RoutingMode,
	privateDirect *bool,
) (RoutingModeState, error) {
	snapshot, err := c.store.Snapshot(ctx)
	if err != nil {
		return RoutingModeState{}, err
	}
	if mode == "" {
		mode = snapshot.RoutingMode
	}
	if err := mode.Validate(); err != nil {
		return RoutingModeState{}, err
	}
	privateValue := snapshot.PrivateDirect
	if privateDirect != nil {
		privateValue = *privateDirect
	}
	if err := c.store.SetRoutingPolicy(ctx, mode, privateValue); err != nil {
		return RoutingModeState{}, err
	}
	state := RoutingModeState{Mode: mode, PrivateDirect: privateValue}
	if c.core == nil || c.core.Snapshot().State != core.StateRunning {
		return state, nil
	}
	if err := c.core.SetRoutingPolicy(ctx, mode, privateValue); err != nil {
		return state, fmt.Errorf("%w: intent persisted but core update failed: %v", ErrLiveRoutingModeUpdate, err)
	}
	liveMode, livePrivate, err := c.core.CurrentRoutingPolicy(ctx)
	if err != nil {
		return state, fmt.Errorf("%w: intent persisted but readback failed: %v", ErrLiveRoutingModeUpdate, err)
	}
	state.LiveMode = liveMode
	state.LivePrivateDirect = boolPtr(livePrivate)
	state.Applied = liveMode == mode && (mode == storage.RoutingModeDirect || livePrivate == privateValue)
	if !state.Applied {
		return state, fmt.Errorf(
			"%w: core readback is mode=%q private_direct=%t, want mode=%q private_direct=%t",
			ErrLiveRoutingModeUpdate,
			liveMode,
			livePrivate,
			mode,
			privateValue,
		)
	}
	return state, nil
}

func routingModeCoreName(mode storage.RoutingMode, privateDirect bool) (string, error) {
	switch mode {
	case storage.RoutingModeRule:
		if privateDirect {
			return "Rule", nil
		}
		return "RuleNoPrivate", nil
	case storage.RoutingModeGlobal:
		if privateDirect {
			return "Global", nil
		}
		return "GlobalNoPrivate", nil
	case storage.RoutingModeDirect:
		return "Direct", nil
	default:
		return "", mode.Validate()
	}
}

func routingModeFromCore(name string) (storage.RoutingMode, bool, error) {
	switch name {
	case "Rule":
		return storage.RoutingModeRule, true, nil
	case "RuleNoPrivate":
		return storage.RoutingModeRule, false, nil
	case "Global":
		return storage.RoutingModeGlobal, true, nil
	case "GlobalNoPrivate":
		return storage.RoutingModeGlobal, false, nil
	case "Direct":
		return storage.RoutingModeDirect, false, nil
	default:
		return "", false, fmt.Errorf("%w: core mode %q", storage.ErrInvalidRoutingMode, name)
	}
}

func boolPtr(value bool) *bool {
	return &value
}
