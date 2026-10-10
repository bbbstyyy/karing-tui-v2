package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrCurrentSelectionConflict = errors.New("current selection binding changed; reload before retrying")

// CheckedSelectionExpectation is the complete, immutable binding returned by
// GET /v1/selection/current. All fields must match, including the revision of
// the current selection and the declaration SHA of the applied generation.
type CheckedSelectionExpectation struct {
	SelectionRevision   uint64
	ConfigRevision      uint64
	AppliedGenerationID *int64
	DeclarationRevision uint64
	DeclarationSHA256   string
}

// SetChecked validates membership against the declaration bound to the exact
// applied generation and commits a single optimistic SQLite CAS. A failed
// write cannot change durable intent or issue a live selector call.
//
// Selection I/O is NOT in the SQLite write transaction. If the live core
// operation fails after commit, the intent remains durable and callers must
// GET again rather than retrying the stale precondition.
func (c *CurrentSelectionCoordinator) SetChecked(
	ctx context.Context, target domain.TargetRef, expected CheckedSelectionExpectation,
) (CurrentSelectionState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot, err := c.store.Snapshot(ctx)
	if err != nil {
		return CurrentSelectionState{}, err
	}
	if snapshot.RecoveryRequired || snapshot.ActiveAttemptID != nil {
		return CurrentSelectionState{}, ErrCurrentSelectionUnavailable
	}
	if snapshot.Revision != expected.ConfigRevision ||
		!sameGenerationID(snapshot.AppliedGenerationID, expected.AppliedGenerationID) {
		return CurrentSelectionState{}, ErrCurrentSelectionConflict
	}
	current, err := c.selectionDeclarationForSnapshot(ctx, snapshot)
	if err != nil {
		return CurrentSelectionState{}, err
	}
	if current.Revision != expected.DeclarationRevision ||
		current.SHA256 != expected.DeclarationSHA256 ||
		current.Revision == 0 || current.SHA256 == "" {
		return CurrentSelectionState{}, ErrCurrentSelectionConflict
	}
	tag, err := declaration.CurrentSelectionRuntimeTag(current.DocumentJSON, target)
	if err != nil {
		return CurrentSelectionState{}, fmt.Errorf("%w: checked target is not a declared member", ErrCurrentSelectionTarget)
	}
	if c.core != nil && c.core.Snapshot().State == core.StateRunning &&
		snapshot.AppliedGenerationID == nil {
		// A running core with no known applied generation cannot be safely
		// given a selector derived from the pending declaration.
		return CurrentSelectionState{}, ErrCurrentSelectionUnavailable
	}
	encoded, err := json.Marshal(target)
	if err != nil {
		return CurrentSelectionState{}, fmt.Errorf("%w: encode target", ErrCurrentSelectionTarget)
	}
	intent, err := c.store.SetCurrentSelectionIntentChecked(ctx, encoded, storage.SelectionPrecondition{
		Revision: expected.SelectionRevision, ConfigRevision: expected.ConfigRevision,
		AppliedGenerationID: expected.AppliedGenerationID,
		DeclarationRevision: expected.DeclarationRevision,
	})
	if err != nil {
		return CurrentSelectionState{}, err
	}
	state := CurrentSelectionState{
		Target: target, RuntimeTag: tag, Persisted: true,
		UpdatedAt: intent.UpdatedAt, SelectionRevision: intent.Revision,
		ConfigRevision: snapshot.Revision, AppliedGenerationID: snapshot.AppliedGenerationID,
		DeclarationRevision: current.Revision, DeclarationSHA256: current.SHA256,
	}
	if c.core == nil || c.core.Snapshot().State != core.StateRunning {
		return state, nil
	}
	if err := c.core.SelectCurrent(ctx, tag); err != nil {
		return state, fmt.Errorf("%w: intent persisted but live update failed", ErrLiveSelectionUpdate)
	}
	live, err := c.core.CurrentSelection(ctx)
	if err != nil {
		return state, fmt.Errorf("%w: intent persisted but live readback failed", ErrLiveSelectionUpdate)
	}
	state.LiveRuntimeTag = live
	state.Applied = live == tag
	if !state.Applied {
		return state, fmt.Errorf("%w: intent persisted but live readback differs", ErrLiveSelectionUpdate)
	}
	return state, nil
}
