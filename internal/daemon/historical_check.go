package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var (
	ErrHistoricalCheckUnavailable = errors.New("historical generation core-check unavailable")
	ErrHistoricalCheckRejected    = errors.New("historical generation is not compatible with current runtime")
	ErrHistoricalCheckChanged     = errors.New("historical generation check binding changed")
)

// HistoricalCheckEvidence is deliberately private to the daemon package.
// A successful core Check is NOT a restore receipt or durable resource lease.
type HistoricalCheckEvidence struct {
	SourceGenerationID int64
	CoreChecked        bool
	Applied            bool
	RestoreReady       bool
}

// historicalIsolatedChecker is intentionally NOT part of the normal apply
// interface. Only explicitly supporting runtimes may check rebound native
// JSON; a missing adapter rejects the dry-run before core I/O.
type historicalIsolatedChecker interface {
	CheckIsolated(context.Context, Generation, string, string) error
}

// CheckHistoricalGeneration performs an internal, non-activating dry run.
// There is intentionally no HTTP, CLI, capability, or TUI route to invoke it.
// The operation gate prevents another daemon core transition while checking.
// Concurrent DB writers are rejected by storage CAS and follow-up reads.
func (r *serverRuntime) CheckHistoricalGeneration(
	ctx context.Context, store *storage.Store, stateRoot string, sourceID int64,
) (HistoricalCheckEvidence, error) {
	if r == nil || r.apply == nil || r.apply.core == nil ||
		r.declarations == nil || r.gate == nil || store == nil || sourceID <= 0 {
		return HistoricalCheckEvidence{}, ErrHistoricalCheckUnavailable
	}
	var result HistoricalCheckEvidence
	err := r.gate.Do(ctx, "historical-generation-check", func(inner context.Context) error {
		var runErr error
		result, runErr = r.checkHistoricalGeneration(inner, store, stateRoot, sourceID)
		return runErr
	})
	return result, err
}

func (r *serverRuntime) checkHistoricalGeneration(
	ctx context.Context, store *storage.Store, stateRoot string, sourceID int64,
) (evidence HistoricalCheckEvidence, err error) {
	// Never use the read-only report as a capability. All state binding and
	// retained provenance are checked again at the atomic prepare boundary.
	audit, err := recoveryAudit(ctx, store, stateRoot)
	if err != nil {
		return evidence, ErrHistoricalCheckChanged
	}
	var historical *apiv1.RecoveryGenerationAudit
	for i := range audit.Generations {
		if audit.Generations[i].GenerationID == sourceID {
			historical = &audit.Generations[i]
			break
		}
	}
	if historical == nil || historical.Applied ||
		historical.Status != "stored_integrity_verified_only" ||
		historical.PreflightStatus != recoveryPreflightConsistentOnly ||
		!historical.StoredIntegrityVerified || !historical.RuleSetResourcesVerified ||
		historical.RestoreReady || audit.RestoreSupported ||
		audit.ActiveApply || audit.RecoveryRequired {
		return evidence, ErrHistoricalCheckRejected
	}

	before, err := store.Snapshot(ctx)
	if err != nil || before.AppliedGenerationID == nil ||
		before.LastKnownGoodGenerationID == nil ||
		*before.AppliedGenerationID == sourceID ||
		before.RecoveryRequired || before.ActiveAttemptID != nil {
		return evidence, ErrHistoricalCheckChanged
	}
	intent, persisted, err := store.CurrentSelectionIntent(ctx)
	if err != nil {
		return evidence, ErrHistoricalCheckUnavailable
	}
	head, err := store.CurrentDeclaration(ctx)
	if err != nil || head.Revision == 0 || !validRouteEditSHA(head.SHA256) ||
		!auditDigest(head.DocumentJSON, head.SHA256, storage.MaxDeclarationBytes) {
		return evidence, ErrHistoricalCheckUnavailable
	}

	// Protect both potential fallback references. A core-check failure is
	// harmless, but no future activation may be planned when its fallback
	// configurations or local rule resources have already disappeared.
	budget := maxRecoveryAuditRuleBytes
	fallbackArtifacts := make([]historicalStoredArtifact, 0, 2)
	seenFallback := make(map[int64]bool, 2)
	for _, id := range []int64{*before.AppliedGenerationID, *before.LastKnownGoodGenerationID} {
		if seenFallback[id] {
			continue
		}
		seenFallback[id] = true
		current := inspectRetainedGeneration(ctx, store, stateRoot,
			apiv1.RecoveryGenerationAudit{GenerationID: id, PayloadRetained: true},
			before, intent, persisted, &budget)
		if current.Status != "stored_integrity_verified_only" ||
			current.PreflightStatus != recoveryPreflightConsistentOnly {
			return evidence, ErrHistoricalCheckRejected
		}
		fallback, readErr := store.GenerationArtifacts(ctx, id)
		if readErr != nil {
			return evidence, ErrHistoricalCheckChanged
		}
		fallbackArtifacts = append(fallbackArtifacts, historicalStoredArtifact{id: id, artifacts: fallback})
	}

	source, err := store.GenerationArtifacts(ctx, sourceID)
	if err != nil {
		return evidence, ErrHistoricalCheckChanged
	}
	var historicalManifest compiler.NativeManifest
	if json.Unmarshal(source.ManifestJSON, &historicalManifest) != nil ||
		historicalManifest.SchemaID != compiler.NativeSchemaID ||
		historicalManifest.ValidateDeclarationBinding(true) != nil {
		return evidence, ErrHistoricalCheckRejected
	}

	// The current compiler and control-plane parameters must generate the
	// same exact historical bytes, including manifest and source-map.
	// Never replay a stored native JSON with a stale control secret, DNS
	// graph or core schema simply because its original SHA still matches.
	recompiled, err := r.declarations.CompileRevision(ctx, historicalManifest.DeclarationRevision)
	if err != nil || recompiled.ValidateDeclarationBinding(true) != nil {
		return evidence, ErrHistoricalCheckRejected
	}
	manifestJSON, sourceMapJSON, err := recompiled.MetadataJSON()
	if err != nil || !bytes.Equal(recompiled.JSON, source.ConfigJSON) ||
		!bytes.Equal(manifestJSON, source.ManifestJSON) ||
		!bytes.Equal(sourceMapJSON, source.SourceMapJSON) ||
		recompiled.SHA256 != source.ConfigSHA256 {
		return evidence, ErrHistoricalCheckRejected
	}

	// Keep the historical and both fallback resource inodes open across
	// candidate preparation and core Check. This detects path replacements
	// and in-place corruption that a before/after path-only hash can miss.
	originals := append([]historicalStoredArtifact{{id: sourceID, artifacts: source}}, fallbackArtifacts...)
	pins, err := pinHistoricalRuleSets(ctx, stateRoot, originals)
	if err != nil {
		return evidence, ErrHistoricalCheckRejected
	}
	defer func() {
		if closeErr := pins.Close(); closeErr != nil {
			err = errors.Join(err, ErrHistoricalCheckUnavailable)
			evidence = HistoricalCheckEvidence{}
		}
	}()
	if !historicalPayloadsUnchanged(ctx, store, originals) || pins.Reverify(ctx) != nil {
		return evidence, ErrHistoricalCheckChanged
	}

	// Materialize a bounded independent copy of the entire target + fallback
	// rule closure before Check. It is an ephemeral safety prerequisite,
	// deliberately NOT a re-bound runtime config or an activation lease.
	isolated, isolateErr := coreartifact.StagePinnedRuleSetSnapshot(ctx,
		filepath.Join(stateRoot, "core"), pins.files)
	if isolateErr != nil {
		return evidence, ErrHistoricalCheckRejected
	}
	defer func() {
		if closeErr := isolated.Close(); closeErr != nil {
			err = errors.Join(err, ErrHistoricalCheckUnavailable)
			evidence = HistoricalCheckEvidence{}
		}
	}()
	if isolated.Verify(ctx) != nil || pins.Reverify(ctx) != nil {
		return evidence, ErrHistoricalCheckChanged
	}

	precondition := storage.HistoricalRestorePrecondition{
		SourceGenerationID:                sourceID,
		SourceConfigSHA256:                source.ConfigSHA256,
		SourceManifestSHA256:              source.ManifestSHA256,
		SourceMapSHA256:                   source.SourceMapSHA256,
		ExpectedConfigRevision:            before.Revision,
		ExpectedAppliedGenerationID:       *before.AppliedGenerationID,
		ExpectedLastKnownGoodGenerationID: *before.LastKnownGoodGenerationID,
		ExpectedDeclarationRevision:       head.Revision,
		ExpectedDeclarationSHA256:         head.SHA256,
		ExpectedSelectionRevision:         intent.Revision,
		ExpectedRoutingMode:               before.RoutingMode,
		ExpectedPrivateDirect:             before.PrivateDirect,
		ExpectedCoreDesiredState:          before.CoreDesiredState,
	}
	attempt, sealed, err := store.PrepareHistoricalRestore(ctx, precondition)
	if err != nil {
		return evidence, fmt.Errorf("%w: atomic historical candidate prepare rejected", ErrHistoricalCheckChanged)
	}
	// Always release the active journal slot, even on client cancellation,
	// failed validation or core-check timeout. No activation is ever issued.
	// Cleanup errors are reported and must never be silently ignored.
	defer func() {
		cleanupErr := r.apply.abortPrepared(ctx, attempt.ID, storage.HistoricalCheckAbortReason)
		if cleanupErr == nil {
			// Do not let a successful dry-run silently consume generations quota.
			// Reclamation is a SECOND detached, bounded storage transaction that
			// archives only this directly-aborted historical candidate.
			cleanupErr = r.apply.cleanupStateStep(ctx, func(cleanupCtx context.Context) error {
				return store.ReclaimAbortedHistoricalCheck(cleanupCtx, attempt.ID)
			})
		}
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("%w: prepared candidate cleanup failed: %v",
				ErrHistoricalCheckUnavailable, cleanupErr))
			evidence = HistoricalCheckEvidence{}
		}
	}()

	if !bytes.Equal(sealed.ConfigJSON, recompiled.JSON) ||
		!bytes.Equal(sealed.ManifestJSON, manifestJSON) ||
		!bytes.Equal(sealed.SourceMapJSON, sourceMapJSON) ||
		!historicalCheckStillBound(ctx, store, precondition, attempt.ID) ||
		!historicalPayloadsUnchanged(ctx, store, originals) ||
		pins.Reverify(ctx) != nil || isolated.Verify(ctx) != nil {
		return evidence, ErrHistoricalCheckChanged
	}

	// Core Check never sees the original shared rule-set paths when this
	// generation references rule sets. Its temporary native JSON is staged
	// inside the SAME locked snapshot, under a different SHA, and is never
	// stored as a generation or bound to the running proxy.
	candidate := Generation{ID: attempt.GenerationID,
		Config: append([]byte(nil), sealed.ConfigJSON...), SHA256: attempt.ConfigSHA256}
	var check func(context.Context) error
	if len(historicalManifest.RuleSets) != 0 {
		runner, supported := r.apply.core.(historicalIsolatedChecker)
		if !supported {
			return evidence, ErrHistoricalCheckUnavailable
		}
		rebound, rebindErr := rebindHistoricalCheckJSON(ctx, sealed.ConfigJSON, historicalManifest, isolated)
		if rebindErr != nil {
			return evidence, ErrHistoricalCheckRejected
		}
		configPath, isolatedSHA, stageErr := isolated.StageNativeCheckConfig(ctx, rebound)
		if stageErr != nil || isolated.Verify(ctx) != nil {
			return evidence, ErrHistoricalCheckRejected
		}
		check = func(checkCtx context.Context) error {
			return runner.CheckIsolated(checkCtx, candidate, configPath, isolatedSHA)
		}
	} else {
		// No local rule sets means there are no paths to rewrite; continue
		// using the original strictly bound generation Check interface.
		check = func(checkCtx context.Context) error {
			return r.apply.core.Check(checkCtx, candidate)
		}
	}
	if err := r.apply.withTimeout(ctx, r.apply.policy.CheckTimeout, check); err != nil {
		return evidence, fmt.Errorf("%w: core rejected historical candidate", ErrHistoricalCheckRejected)
	}
	// Re-read original SQLite payloads and all pinned source/fallback file
	// descriptors AFTER core Check, not only the target's pathname.
	if !historicalCheckStillBound(ctx, store, precondition, attempt.ID) ||
		!historicalPayloadsUnchanged(ctx, store, originals) ||
		pins.Reverify(ctx) != nil || isolated.Verify(ctx) != nil {
		return evidence, ErrHistoricalCheckChanged
	}

	return HistoricalCheckEvidence{
		SourceGenerationID: sourceID,
		CoreChecked:        true,
		Applied:            false, RestoreReady: false,
	}, nil
}

func historicalCheckStillBound(
	ctx context.Context, store *storage.Store,
	expected storage.HistoricalRestorePrecondition, activeAttemptID int64,
) bool {
	snapshot, err := store.Snapshot(ctx)
	if err != nil || snapshot.Revision != expected.ExpectedConfigRevision ||
		snapshot.AppliedGenerationID == nil ||
		*snapshot.AppliedGenerationID != expected.ExpectedAppliedGenerationID ||
		snapshot.LastKnownGoodGenerationID == nil ||
		*snapshot.LastKnownGoodGenerationID != expected.ExpectedLastKnownGoodGenerationID ||
		snapshot.ActiveAttemptID == nil || *snapshot.ActiveAttemptID != activeAttemptID ||
		snapshot.RecoveryRequired ||
		snapshot.RoutingMode != expected.ExpectedRoutingMode ||
		snapshot.PrivateDirect != expected.ExpectedPrivateDirect ||
		snapshot.CoreDesiredState != expected.ExpectedCoreDesiredState {
		return false
	}
	intent, _, err := store.CurrentSelectionIntent(ctx)
	if err != nil || intent.Revision != expected.ExpectedSelectionRevision {
		return false
	}
	head, err := store.CurrentDeclaration(ctx)
	return err == nil && head.Revision == expected.ExpectedDeclarationRevision &&
		head.SHA256 == expected.ExpectedDeclarationSHA256 &&
		auditDigest(head.DocumentJSON, head.SHA256, storage.MaxDeclarationBytes)
}
