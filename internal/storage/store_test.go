package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestReadOnlyDatabaseRejectsApplyWithoutChangingConfirmedState(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	baseline, err := store.PrepareApply(ctx, 0, []byte(`{"generation":"baseline"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, baseline.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, baseline.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitApplied(ctx, baseline.ID, true); err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.ExecContext(ctx, "PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	defer store.db.ExecContext(context.Background(), "PRAGMA query_only = OFF")

	if _, err := store.PrepareApply(ctx, 1, []byte(`{"generation":"must-not-persist"}`)); err == nil {
		t.Fatal("read-only database unexpectedly accepted a new apply")
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 ||
		snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != baseline.GenerationID ||
		snapshot.LastKnownGoodGenerationID == nil || *snapshot.LastKnownGoodGenerationID != baseline.GenerationID ||
		snapshot.ActiveAttemptID != nil ||
		snapshot.RecoveryRequired {
		t.Fatalf("read-only apply failure changed confirmed state: %+v", snapshot)
	}
	config, hash, err := store.GenerationConfig(ctx, baseline.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if string(config) != `{"generation":"baseline"}` || hash != baseline.ConfigSHA256 {
		t.Fatalf("read-only failure changed baseline generation: config=%q hash=%q", config, hash)
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

func TestSchemaV3MigratesRealV2DatabaseWithoutChangingState(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	config := []byte(`{"v2":true}`)
	hash := sha256String(config)
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE generations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
			target_revision INTEGER NOT NULL CHECK(target_revision = base_revision + 1),
			config_json BLOB NOT NULL,
			config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE daemon_state (
			singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
			config_revision INTEGER NOT NULL DEFAULT 0 CHECK(config_revision >= 0),
			applied_generation_id INTEGER REFERENCES generations(id) ON DELETE RESTRICT,
			last_known_good_generation_id INTEGER REFERENCES generations(id) ON DELETE RESTRICT,
			recovery_required INTEGER NOT NULL DEFAULT 0 CHECK(recovery_required IN (0, 1)),
			core_desired_state TEXT NOT NULL DEFAULT 'stopped'
				CHECK(core_desired_state IN ('stopped', 'running'))
		)`,
		`CREATE TABLE apply_journal (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE RESTRICT,
			previous_generation_id INTEGER REFERENCES generations(id) ON DELETE RESTRICT,
			base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
			target_revision INTEGER NOT NULL CHECK(target_revision = base_revision + 1),
			phase TEXT NOT NULL CHECK(phase IN ('prepared', 'activating', 'verifying', 'rolling_back', 'committed', 'rolled_back', 'failed', 'interrupted')),
			active_slot INTEGER CHECK(active_slot IS NULL OR active_slot = 1),
			error TEXT NOT NULL DEFAULT '',
			started_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE UNIQUE INDEX apply_journal_one_active ON apply_journal(active_slot) WHERE active_slot IS NOT NULL`,
		`CREATE INDEX apply_journal_generation ON apply_journal(generation_id)`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			_ = db.Close()
			t.Fatalf("create v2 fixture: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?), (2, ?)`, now, now); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	result, err := db.ExecContext(ctx, `
		INSERT INTO generations(base_revision, target_revision, config_json, config_sha256, created_at)
		VALUES(0, 1, ?, ?, ?)
	`, config, hash, now)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	generationID, err := result.LastInsertId()
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO daemon_state(
			singleton,
			config_revision,
			applied_generation_id,
			last_known_good_generation_id,
			recovery_required,
			core_desired_state
		)
		VALUES(1, 1, ?, ?, 0, 'running')
	`, generationID, generationID); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO apply_journal(
			generation_id,
			previous_generation_id,
			base_revision,
			target_revision,
			phase,
			active_slot,
			error,
			started_at,
			updated_at
		)
		VALUES(?, NULL, 0, 1, 'committed', NULL, '', ?, ?)
	`, generationID, now, now); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 ||
		snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != generationID ||
		snapshot.LastKnownGoodGenerationID == nil || *snapshot.LastKnownGoodGenerationID != generationID ||
		snapshot.RecoveryRequired ||
		snapshot.CoreDesiredState != CoreDesiredRunning ||
		snapshot.ActiveAttemptID != nil {
		t.Fatalf("v2 state changed during v3 migration: %+v", snapshot)
	}

	artifacts, err := store.GenerationArtifacts(ctx, generationID)
	if err != nil {
		t.Fatal(err)
	}
	if string(artifacts.ConfigJSON) != string(config) || artifacts.ConfigSHA256 != hash {
		t.Fatalf("v2 generation changed during migration: %+v", artifacts)
	}
	if len(artifacts.ManifestJSON) != 0 || artifacts.ManifestSHA256 != "" ||
		len(artifacts.SourceMapJSON) != 0 || artifacts.SourceMapSHA256 != "" {
		t.Fatalf("v2 generation gained fabricated metadata: %+v", artifacts)
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
