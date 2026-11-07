package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// An apply can have reached durable commit even if the subsequent readback is
// unavailable. Never advertise success or retry/roll back speculatively.
var ErrCheckedApplyReadbackUncertain = errors.New("checked apply durable readback uncertain")

type checkedApplyReadbackStore interface {
	Snapshot(context.Context) (storage.Snapshot, error)
	Attempt(context.Context, int64) (storage.Attempt, error)
	GenerationArtifacts(context.Context, int64) (storage.GenerationArtifacts, error)
}

// verifyCheckedApplyReadback binds the success receipt to committed daemon
// state, the terminal journal entry and the exact persisted generation bytes.
// This is a non-mutating verification after Check -> Activate -> Verify ->
// CommitApplied. It is NOT a substitute for live Core verification, which the
// apply coordinator must have completed before returning.
func verifyCheckedApplyReadback(
	ctx context.Context,
	store checkedApplyReadbackStore,
	receipt apiv1.CheckedApplyReceipt,
	attempt storage.Attempt,
) error {
	if store == nil || attempt.ID <= 0 || attempt.GenerationID <= 0 ||
		attempt.BaseRevision != receipt.ExpectedConfigRevision ||
		attempt.TargetRevision != receipt.ExpectedConfigRevision+1 ||
		attempt.ConfigSHA256 != receipt.NativeConfigSHA256 {
		return ErrCheckedApplyReadbackUncertain
	}
	state, err := store.Snapshot(ctx)
	if err != nil || state.Revision != attempt.TargetRevision ||
		state.AppliedGenerationID == nil || *state.AppliedGenerationID != attempt.GenerationID ||
		state.LastKnownGoodGenerationID == nil || *state.LastKnownGoodGenerationID != attempt.GenerationID ||
		state.RecoveryRequired || state.ActiveAttemptID != nil {
		return ErrCheckedApplyReadbackUncertain
	}
	record, err := store.Attempt(ctx, attempt.ID)
	if err != nil || record.Phase != storage.PhaseCommitted ||
		record.ID != attempt.ID || record.GenerationID != attempt.GenerationID ||
		record.BaseRevision != attempt.BaseRevision || record.TargetRevision != attempt.TargetRevision ||
		record.ConfigSHA256 != receipt.NativeConfigSHA256 {
		return ErrCheckedApplyReadbackUncertain
	}
	artifacts, err := store.GenerationArtifacts(ctx, attempt.GenerationID)
	if err != nil ||
		!checkedApplySHA256Matches(artifacts.ConfigJSON, artifacts.ConfigSHA256) ||
		artifacts.ConfigSHA256 != receipt.NativeConfigSHA256 ||
		!checkedApplySHA256Matches(artifacts.ManifestJSON, artifacts.ManifestSHA256) ||
		!checkedApplySHA256Matches(artifacts.SourceMapJSON, artifacts.SourceMapSHA256) {
		return ErrCheckedApplyReadbackUncertain
	}
	var manifest struct {
		DeclarationRevision uint64 `json:"declaration_revision"`
		DeclarationSHA256   string `json:"declaration_sha256"`
		ConfigSHA256        string `json:"config_sha256"`
	}
	if err := json.Unmarshal(artifacts.ManifestJSON, &manifest); err != nil ||
		manifest.DeclarationRevision != receipt.DeclarationRevision ||
		manifest.DeclarationSHA256 != receipt.DeclarationSHA256 ||
		manifest.ConfigSHA256 != receipt.NativeConfigSHA256 {
		return ErrCheckedApplyReadbackUncertain
	}
	return nil
}

func checkedApplySHA256Matches(content []byte, expected string) bool {
	if len(content) == 0 || !validRouteEditSHA(expected) {
		return false
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]) == expected
}
