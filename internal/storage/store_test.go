package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyLifecycleKeepsRevisionOnRollback(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)
	defer store.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database permissions = %04o, want 0600", got)
	}

	initial, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Revision != 0 || initial.AppliedGenerationID != nil || initial.RecoveryRequired || initial.CoreDesiredState != CoreDesiredStopped {
		t.Fatalf("unexpected initial snapshot: %+v", initial)
	}

	first, err := store.PrepareApply(ctx, 0, []byte(`{"inbounds":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if first.TargetRevision != 1 || first.Phase != PhasePrepared {
		t.Fatalf("unexpected first attempt: %+v", first)
	}

	if _, err := store.PrepareApply(ctx, 0, []byte(`{"inbounds":[]}`)); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("second concurrent prepare error = %v, want ErrApplyInProgress", err)
	}
	if err := store.BeginActivation(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitApplied(ctx, first.ID, true); err != nil {
		t.Fatal(err)
	}

	afterFirst, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterFirst.Revision != 1 || afterFirst.AppliedGenerationID == nil || *afterFirst.AppliedGenerationID != first.GenerationID {
		t.Fatalf("unexpected snapshot after commit: %+v", afterFirst)
	}
	if afterFirst.LastKnownGoodGenerationID == nil || *afterFirst.LastKnownGoodGenerationID != first.GenerationID {
		t.Fatalf("last known good not promoted: %+v", afterFirst)
	}

	config, hash, err := store.GenerationConfig(ctx, first.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if string(config) != `{"inbounds":[]}` || hash != first.ConfigSHA256 {
		t.Fatalf("unexpected generation payload/hash: %q %q", config, hash)
	}

	if _, err := store.PrepareApply(ctx, 0, []byte(`{"outbounds":[]}`)); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale revision error = %v, want ErrRevisionConflict", err)
	}

	second, err := store.PrepareApply(ctx, 1, []byte(`{"outbounds":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginRollback(ctx, second.ID, "health check failed"); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRollback(ctx, second.ID); err != nil {
		t.Fatal(err)
	}

	afterRollback, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterRollback.Revision != 1 || afterRollback.AppliedGenerationID == nil || *afterRollback.AppliedGenerationID != first.GenerationID {
		t.Fatalf("rollback changed applied state: %+v", afterRollback)
	}
	journal, err := store.Attempt(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != PhaseRolledBack || journal.Error != "health check failed" {
		t.Fatalf("unexpected rollback journal: %+v", journal)
	}
}

func TestRecoverInterruptedActivationRequiresReconcile(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)

	first, err := store.PrepareApply(ctx, 0, []byte(`{"first":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitApplied(ctx, first.ID, true); err != nil {
		t.Fatal(err)
	}

	second, err := store.PrepareApply(ctx, 1, []byte(`{"second":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	recovery, err := reopened.RecoverInterrupted(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !recovery.NeedsReconcile || len(recovery.InterruptedAttemptIDs) != 1 || recovery.InterruptedAttemptIDs[0] != second.ID {
		t.Fatalf("unexpected recovery result: %+v", recovery)
	}

	snapshot, err := reopened.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || !snapshot.RecoveryRequired || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != first.GenerationID {
		t.Fatalf("unexpected recovered snapshot: %+v", snapshot)
	}
	if _, err := reopened.PrepareApply(ctx, 1, []byte(`{"blocked":true}`)); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("prepare during recovery error = %v, want ErrRecoveryRequired", err)
	}

	if err := reopened.ResolveRecovery(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.PrepareApply(ctx, 1, []byte(`{"after_recovery":true}`)); err != nil {
		t.Fatalf("prepare after recovery: %v", err)
	}
}

func TestRecoverPreparedAttemptDoesNotRequireCoreReconcile(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)
	attempt, err := store.PrepareApply(ctx, 0, []byte(`{"prepared":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovery, err := reopened.RecoverInterrupted(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if recovery.NeedsReconcile || len(recovery.InterruptedAttemptIDs) != 1 || recovery.InterruptedAttemptIDs[0] != attempt.ID {
		t.Fatalf("unexpected prepared recovery: %+v", recovery)
	}
	snapshot, err := reopened.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RecoveryRequired {
		t.Fatalf("prepared-only interruption should not require core reconcile: %+v", snapshot)
	}
}

func TestCoreDesiredStatePersistsWithoutChangingRevision(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)

	initial, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if initial.CoreDesiredState != CoreDesiredStopped || initial.Revision != 0 {
		t.Fatalf("unexpected initial desired state: %+v", initial)
	}
	if err := store.SetCoreDesiredState(ctx, CoreDesiredRunning); err != nil {
		t.Fatal(err)
	}
	running, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if running.CoreDesiredState != CoreDesiredRunning || running.Revision != 0 {
		t.Fatalf("desired state update changed config revision or failed: %+v", running)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := reopened.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.CoreDesiredState != CoreDesiredRunning || persisted.Revision != 0 {
		t.Fatalf("desired state did not persist across reopen: %+v", persisted)
	}
	if err := reopened.SetCoreDesiredState(ctx, CoreDesiredStopped); err != nil {
		t.Fatal(err)
	}
	stopped, err := reopened.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.CoreDesiredState != CoreDesiredStopped || stopped.Revision != 0 {
		t.Fatalf("explicit stop intent was not persisted independently: %+v", stopped)
	}
	if err := reopened.SetCoreDesiredState(ctx, CoreDesiredState("invalid")); !errors.Is(err, ErrInvalidCoreDesiredState) {
		t.Fatalf("invalid desired state error = %v, want ErrInvalidCoreDesiredState", err)
	}
}

func TestInvalidTransitionIsRejected(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	attempt, err := store.PrepareApply(ctx, 0, []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, attempt.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid transition error = %v, want ErrInvalidTransition", err)
	}
}

func newTestStore(t *testing.T, ctx context.Context) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}

func TestPrepareApplyWithMetadataPersistsImmutableGenerationArtifacts(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	config := []byte(`{"inbounds":[],"route":{"rules":[]}}`)
	manifest := []byte(`{"schema_id":"test-schema","resources":[{"ref":"acl:test","sha256":"abc"}]}`)
	sourceMap := []byte(`[{"rule_index":0,"layer":"final","group_id":"FINAL"}]`)

	attempt, err := store.PrepareApplyWithMetadata(ctx, 0, config, manifest, sourceMap)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.GenerationArtifacts(ctx, attempt.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if string(artifacts.ConfigJSON) != string(config) ||
		string(artifacts.ManifestJSON) != string(manifest) ||
		string(artifacts.SourceMapJSON) != string(sourceMap) {
		t.Fatalf("generation artifacts changed: %+v", artifacts)
	}
	if artifacts.ConfigSHA256 != sha256String(config) ||
		artifacts.ManifestSHA256 != sha256String(manifest) ||
		artifacts.SourceMapSHA256 != sha256String(sourceMap) {
		t.Fatalf("unexpected generation artifact hashes: %+v", artifacts)
	}
	if attempt.ConfigSHA256 != artifacts.ConfigSHA256 {
		t.Fatalf("attempt config hash = %q, artifacts hash = %q", attempt.ConfigSHA256, artifacts.ConfigSHA256)
	}

	artifacts.ConfigJSON[0] = 'x'
	artifacts.ManifestJSON[0] = 'x'
	artifacts.SourceMapJSON[0] = 'x'
	again, err := store.GenerationArtifacts(ctx, attempt.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.ConfigJSON) != string(config) ||
		string(again.ManifestJSON) != string(manifest) ||
		string(again.SourceMapJSON) != string(sourceMap) {
		t.Fatal("caller mutation changed persisted generation artifacts")
	}

	legacyConfig, legacyHash, err := store.GenerationConfig(ctx, attempt.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if string(legacyConfig) != string(config) || legacyHash != sha256String(config) {
		t.Fatalf("GenerationConfig compatibility changed: %q %q", legacyConfig, legacyHash)
	}
}

func TestPrepareApplyLegacyGenerationHasNoMetadata(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	attempt, err := store.PrepareApply(ctx, 0, []byte(`{"legacy":true}`))
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.GenerationArtifacts(ctx, attempt.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts.ManifestJSON) != 0 || artifacts.ManifestSHA256 != "" ||
		len(artifacts.SourceMapJSON) != 0 || artifacts.SourceMapSHA256 != "" {
		t.Fatalf("legacy generation unexpectedly has metadata: %+v", artifacts)
	}
}

func TestPrepareApplyWithMetadataRejectsInvalidOrOversizedMetadata(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	config := []byte(`{"valid":true}`)
	validManifest := []byte(`{"manifest":true}`)
	validSourceMap := []byte(`[]`)

	cases := []struct {
		name      string
		manifest  []byte
		sourceMap []byte
		want      error
	}{
		{name: "empty manifest", sourceMap: validSourceMap, want: ErrInvalidGenerationMetadata},
		{name: "invalid manifest", manifest: []byte("{"), sourceMap: validSourceMap, want: ErrInvalidGenerationMetadata},
		{name: "empty source map", manifest: validManifest, want: ErrInvalidGenerationMetadata},
		{name: "invalid source map", manifest: validManifest, sourceMap: []byte("["), want: ErrInvalidGenerationMetadata},
		{name: "oversized manifest", manifest: []byte(`"` + strings.Repeat("m", MaxGenerationMetadataBytes) + `"`), sourceMap: validSourceMap, want: ErrGenerationMetadataTooLarge},
		{name: "oversized source map", manifest: validManifest, sourceMap: []byte(`"` + strings.Repeat("s", MaxGenerationMetadataBytes) + `"`), want: ErrGenerationMetadataTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.PrepareApplyWithMetadata(ctx, 0, config, tc.manifest, tc.sourceMap); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			snapshot, err := store.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.ActiveAttemptID != nil || snapshot.Revision != 0 {
				t.Fatalf("invalid metadata changed durable state: %+v", snapshot)
			}
		})
	}
}

func TestSchemaV3ReopenPreservesLegacyGeneration(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)

	attempt, err := store.PrepareApply(ctx, 0, []byte(`{"before_migration_fixture":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	artifacts, err := reopened.GenerationArtifacts(ctx, attempt.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if string(artifacts.ConfigJSON) != `{"before_migration_fixture":true}` {
		t.Fatalf("generation config changed after reopen: %q", artifacts.ConfigJSON)
	}
	if len(artifacts.ManifestJSON) != 0 || len(artifacts.SourceMapJSON) != 0 {
		t.Fatalf("legacy generation gained metadata after migration: %+v", artifacts)
	}
}

func sha256String(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
