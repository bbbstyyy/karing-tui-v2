package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var (
	ErrCurrentSelectionUnavailable = errors.New("current selection is unavailable")
	ErrCurrentSelectionTarget      = errors.New("invalid current selection target")
	ErrLiveSelectionUpdate         = errors.New("live current selection update failed")
)

type currentSelectionStore interface {
	CurrentDeclaration(context.Context) (storage.DeclarationRevision, error)
	CurrentSelectionIntent(context.Context) (storage.SelectionIntent, bool, error)
	SetCurrentSelectionIntent(context.Context, []byte) (storage.SelectionIntent, error)
}

type currentSelectionCore interface {
	Snapshot() core.Snapshot
	SelectCurrent(context.Context, string) error
	CurrentSelection(context.Context) (string, error)
}

type CurrentSelectionState struct {
	Target         domain.TargetRef
	RuntimeTag     string
	Persisted      bool
	UpdatedAt      time.Time
	Applied        bool
	LiveRuntimeTag string
}

type CurrentSelectionCoordinator struct {
	store currentSelectionStore
	core  currentSelectionCore
}

func NewCurrentSelectionCoordinator(
	store currentSelectionStore,
	core currentSelectionCore,
) (*CurrentSelectionCoordinator, error) {
	if store == nil {
		return nil, errors.New("current selection store is nil")
	}
	return &CurrentSelectionCoordinator{store: store, core: core}, nil
}

func (c *CurrentSelectionCoordinator) Get(ctx context.Context) (CurrentSelectionState, error) {
	current, err := c.store.CurrentDeclaration(ctx)
	if err != nil {
		return CurrentSelectionState{}, err
	}
	if current.Revision == 0 || len(current.DocumentJSON) == 0 {
		return CurrentSelectionState{}, ErrCurrentSelectionUnavailable
	}

	intent, persisted, err := c.store.CurrentSelectionIntent(ctx)
	if err != nil {
		return CurrentSelectionState{}, err
	}
	var target domain.TargetRef
	var updatedAt time.Time
	if persisted {
		target, err = decodeSelectionTarget(intent.TargetJSON)
		if err != nil {
			return CurrentSelectionState{}, err
		}
		updatedAt = intent.UpdatedAt
	} else {
		model, parseErr := declaration.ParseV1(current.DocumentJSON)
		if parseErr != nil {
			return CurrentSelectionState{}, parseErr
		}
		target = model.Selection.Current.Default
	}

	runtimeTag, err := declaration.CurrentSelectionRuntimeTag(current.DocumentJSON, target)
	if err != nil {
		return CurrentSelectionState{}, fmt.Errorf("%w: %v", ErrCurrentSelectionTarget, err)
	}
	state := CurrentSelectionState{
		Target:     target,
		RuntimeTag: runtimeTag,
		Persisted:  persisted,
		UpdatedAt:  updatedAt,
	}
	if c.core == nil || c.core.Snapshot().State != core.StateRunning {
		return state, nil
	}
	live, err := c.core.CurrentSelection(ctx)
	if err != nil {
		return state, fmt.Errorf("%w: read live selector: %v", ErrLiveSelectionUpdate, err)
	}
	state.LiveRuntimeTag = live
	state.Applied = live == runtimeTag
	return state, nil
}

func (c *CurrentSelectionCoordinator) Set(
	ctx context.Context,
	target domain.TargetRef,
) (CurrentSelectionState, error) {
	current, err := c.store.CurrentDeclaration(ctx)
	if err != nil {
		return CurrentSelectionState{}, err
	}
	if current.Revision == 0 || len(current.DocumentJSON) == 0 {
		return CurrentSelectionState{}, ErrCurrentSelectionUnavailable
	}
	runtimeTag, err := declaration.CurrentSelectionRuntimeTag(current.DocumentJSON, target)
	if err != nil {
		return CurrentSelectionState{}, fmt.Errorf("%w: %v", ErrCurrentSelectionTarget, err)
	}
	encoded, err := json.Marshal(target)
	if err != nil {
		return CurrentSelectionState{}, fmt.Errorf("%w: encode target: %v", ErrCurrentSelectionTarget, err)
	}
	intent, err := c.store.SetCurrentSelectionIntent(ctx, encoded)
	if err != nil {
		return CurrentSelectionState{}, err
	}
	state := CurrentSelectionState{
		Target:     target,
		RuntimeTag: runtimeTag,
		Persisted:  true,
		UpdatedAt:  intent.UpdatedAt,
	}
	if c.core == nil || c.core.Snapshot().State != core.StateRunning {
		return state, nil
	}
	if err := c.core.SelectCurrent(ctx, runtimeTag); err != nil {
		return state, fmt.Errorf("%w: intent persisted but selector update failed: %v", ErrLiveSelectionUpdate, err)
	}
	live, err := c.core.CurrentSelection(ctx)
	if err != nil {
		return state, fmt.Errorf("%w: intent persisted but selector readback failed: %v", ErrLiveSelectionUpdate, err)
	}
	state.LiveRuntimeTag = live
	state.Applied = live == runtimeTag
	if !state.Applied {
		return state, fmt.Errorf("%w: selector readback is %q, want %q", ErrLiveSelectionUpdate, live, runtimeTag)
	}
	return state, nil
}

func decodeSelectionTarget(content []byte) (domain.TargetRef, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var target domain.TargetRef
	if err := decoder.Decode(&target); err != nil {
		return domain.TargetRef{}, fmt.Errorf("%w: decode persisted target: %v", ErrCurrentSelectionTarget, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, context.Canceled) {
		if err == nil {
			return domain.TargetRef{}, fmt.Errorf("%w: persisted target has multiple JSON values", ErrCurrentSelectionTarget)
		}
		if !errors.Is(err, io.EOF) {
			return domain.TargetRef{}, fmt.Errorf("%w: decode persisted target: %v", ErrCurrentSelectionTarget, err)
		}
	}
	return target, nil
}
