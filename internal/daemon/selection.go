package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
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
	Snapshot(context.Context) (storage.Snapshot, error)
	GenerationArtifacts(context.Context, int64) (storage.GenerationArtifacts, error)
	Declaration(context.Context, uint64) (storage.DeclarationRevision, error)
	CurrentDeclaration(context.Context) (storage.DeclarationRevision, error)
	CurrentSelectionIntent(context.Context) (storage.SelectionIntent, bool, error)
	SetCurrentSelectionIntent(context.Context, []byte) (storage.SelectionIntent, error)
	SetCurrentSelectionIntentChecked(context.Context, []byte, storage.SelectionPrecondition) (storage.SelectionIntent, error)
}

type currentSelectionCore interface {
	Snapshot() core.Snapshot
	SelectCurrent(context.Context, string) error
	CurrentSelection(context.Context) (string, error)
}

type CurrentSelectionState struct {
	Target              domain.TargetRef
	RuntimeTag          string
	Persisted           bool
	UpdatedAt           time.Time
	Applied             bool
	LiveRuntimeTag      string
	SelectionRevision   uint64
	ConfigRevision      uint64
	AppliedGenerationID *int64
	DeclarationRevision uint64
	DeclarationSHA256   string
}

type CurrentSelectionCoordinator struct {
	store currentSelectionStore
	core  currentSelectionCore
	mu    sync.Mutex // Serialize legacy and checked writes through live readback.
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
	snapshot, err := c.store.Snapshot(ctx)
	if err != nil {
		return CurrentSelectionState{}, err
	}
	current, err := c.selectionDeclarationForSnapshot(ctx, snapshot)
	if err != nil {
		return CurrentSelectionState{}, err
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
		Target:              target,
		RuntimeTag:          runtimeTag,
		Persisted:           persisted,
		UpdatedAt:           updatedAt,
		SelectionRevision:   intent.Revision,
		ConfigRevision:      snapshot.Revision,
		AppliedGenerationID: snapshot.AppliedGenerationID,
		DeclarationRevision: current.Revision,
		DeclarationSHA256:   current.SHA256,
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
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot, err := c.store.Snapshot(ctx)
	if err != nil {
		return CurrentSelectionState{}, err
	}
	current, err := c.selectionDeclarationForSnapshot(ctx, snapshot)
	if err != nil {
		return CurrentSelectionState{}, err
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
		Target:              target,
		RuntimeTag:          runtimeTag,
		Persisted:           true,
		UpdatedAt:           intent.UpdatedAt,
		SelectionRevision:   intent.Revision,
		ConfigRevision:      snapshot.Revision,
		AppliedGenerationID: snapshot.AppliedGenerationID,
		DeclarationRevision: current.Revision,
		DeclarationSHA256:   current.SHA256,
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

func (c *CurrentSelectionCoordinator) selectionDeclaration(ctx context.Context) (storage.DeclarationRevision, error) {
	snapshot, err := c.store.Snapshot(ctx)
	if err != nil {
		return storage.DeclarationRevision{}, fmt.Errorf("read applied generation for current selection: %w", err)
	}
	return c.selectionDeclarationForSnapshot(ctx, snapshot)
}

func (c *CurrentSelectionCoordinator) selectionDeclarationForSnapshot(
	ctx context.Context, snapshot storage.Snapshot,
) (storage.DeclarationRevision, error) {
	if snapshot.AppliedGenerationID == nil {
		current, err := c.store.CurrentDeclaration(ctx)
		if err != nil {
			return storage.DeclarationRevision{}, err
		}
		if current.Revision == 0 || len(current.DocumentJSON) == 0 {
			return storage.DeclarationRevision{}, ErrCurrentSelectionUnavailable
		}
		return current, nil
	}

	artifacts, err := c.store.GenerationArtifacts(ctx, *snapshot.AppliedGenerationID)
	if err != nil {
		return storage.DeclarationRevision{}, fmt.Errorf("read applied generation provenance for current selection: %w", err)
	}
	if len(artifacts.ManifestJSON) == 0 || artifacts.ManifestSHA256 == "" {
		return storage.DeclarationRevision{}, fmt.Errorf(
			"%w: applied generation %d has no declaration provenance",
			ErrCurrentSelectionUnavailable,
			*snapshot.AppliedGenerationID,
		)
	}
	manifestSum := sha256.Sum256(artifacts.ManifestJSON)
	if hex.EncodeToString(manifestSum[:]) != artifacts.ManifestSHA256 {
		return storage.DeclarationRevision{}, fmt.Errorf(
			"%w: applied generation %d manifest hash mismatch",
			ErrCurrentSelectionUnavailable,
			*snapshot.AppliedGenerationID,
		)
	}
	var manifest compiler.NativeManifest
	if err := json.Unmarshal(artifacts.ManifestJSON, &manifest); err != nil {
		return storage.DeclarationRevision{}, fmt.Errorf(
			"%w: decode applied generation %d manifest: %v",
			ErrCurrentSelectionUnavailable,
			*snapshot.AppliedGenerationID,
			err,
		)
	}
	if manifest.DeclarationRevision == 0 || manifest.DeclarationSHA256 == "" {
		return storage.DeclarationRevision{}, fmt.Errorf(
			"%w: applied generation %d has no declaration binding",
			ErrCurrentSelectionUnavailable,
			*snapshot.AppliedGenerationID,
		)
	}
	stored, err := c.store.Declaration(ctx, manifest.DeclarationRevision)
	if err != nil {
		return storage.DeclarationRevision{}, fmt.Errorf(
			"%w: load applied declaration revision %d: %v",
			ErrCurrentSelectionUnavailable,
			manifest.DeclarationRevision,
			err,
		)
	}
	if stored.SHA256 != manifest.DeclarationSHA256 {
		return storage.DeclarationRevision{}, fmt.Errorf(
			"%w: applied declaration revision %d hash mismatch",
			ErrCurrentSelectionUnavailable,
			manifest.DeclarationRevision,
		)
	}
	if len(stored.DocumentJSON) == 0 {
		return storage.DeclarationRevision{}, fmt.Errorf(
			"%w: applied declaration revision %d is empty",
			ErrCurrentSelectionUnavailable,
			stored.Revision,
		)
	}
	return stored, nil
}

func decodeSelectionTarget(content []byte) (domain.TargetRef, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var target domain.TargetRef
	if err := decoder.Decode(&target); err != nil {
		return domain.TargetRef{}, fmt.Errorf("%w: decode persisted target: %v", ErrCurrentSelectionTarget, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return domain.TargetRef{}, fmt.Errorf("%w: persisted target has multiple JSON values", ErrCurrentSelectionTarget)
		}
		return domain.TargetRef{}, fmt.Errorf("%w: decode persisted target: %v", ErrCurrentSelectionTarget, err)
	}
	return target, nil
}
