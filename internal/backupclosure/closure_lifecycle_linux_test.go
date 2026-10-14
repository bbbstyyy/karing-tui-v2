//go:build linux

package backupclosure

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

)

// Do not produce an encrypted archive which would capture an in-flight apply
// or a daemon still requiring post-crash operator reconciliation. Both gates
// must examine the copied SQLite image without mutating authoritative state.
func TestBuildClosureRefusesUnstableApplyLifecycle(t *testing.T) {
	for _, state := range []string{"active_apply", "recovery_required"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			id := f.commit(t, true)
			ctx := context.Background()
			switch state {
			case "active_apply":
				artifacts, err := f.store.GenerationArtifacts(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.store.PrepareApplyWithMetadata(ctx, f.configRevision,
					artifacts.ConfigJSON, artifacts.ManifestJSON,
					artifacts.SourceMapJSON)
				if err != nil {
					t.Fatal(err)
				}
			case "recovery_required":
				db, err := sql.Open("sqlite", f.store.Path())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.ExecContext(ctx,
					"UPDATE daemon_state SET recovery_required=1 WHERE singleton=1"); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before, err := f.store.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			closure, err := Build(ctx, f.store, f.stateRoot, f.parent)
			if closure != nil || !errors.Is(err, ErrUnsafeClosure) {
				t.Fatalf("unstable %s state generated archive closure: %v %v", state, closure, err)
			}
			requireNoBackupScopes(t, f)
			after, err := f.store.Snapshot(ctx)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("backup inspection altered live apply lifecycle: %+v -> %+v %v", before, after, err)
			}
		})
	}
}

func TestAuthenticatedArchiveRejectsUnstableLifecycleDespiteValidMAC(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	ctx := context.Background()
	closure, err := Build(ctx, f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	parent := testSealedDir(t, f)
	original := filepath.Join(parent, "stable-original.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(ctx, original, key); err != nil {
		t.Fatal(err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		sql  string
	}{
		{"active_apply", "UPDATE apply_journal SET phase='prepared', active_slot=1 WHERE phase='committed'"},
		{"recovery_required", "UPDATE daemon_state SET recovery_required=1 WHERE singleton=1"},
		{"config_revision_drift", "UPDATE daemon_state SET config_revision=config_revision+1 WHERE singleton=1"},
		{"missing_last_known_good", "UPDATE daemon_state SET last_known_good_generation_id=NULL WHERE singleton=1"},
		{"applied_not_committed", "UPDATE apply_journal SET phase='failed' WHERE phase='committed'"},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := filepath.Join(parent, test.name+".ktbackup")
			tamperAndResealArchive(t, original, destination, key, func(data []byte) []byte {
				return mutateInMemorySQLite(t, data, test.sql)
			})
			if _, err := VerifyInertArchive(ctx, destination, key); err != nil {
				t.Fatalf("crypto fixture must pass: %v", err)
			}
			report, err := PreflightInertArchive(ctx, destination, key, nil)
			if !errors.Is(err, ErrUnsafeSealedArchive) ||
				!reflect.DeepEqual(report, InertArchivePreflight{}) {
				t.Fatalf("invalid lifecycle accepted by authenticated reader: %+v %v", report, err)
			}
		})
	}
}

// Retention legitimately moves terminal committed attempts to apply_history;
// archive inspection must not mistake this compaction for an uncommitted core.
func TestArchiveLifecycleAcceptsCompactedCommittedHistory(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	ctx := context.Background()
	if _, err := f.store.PruneRetention(ctx); err != nil {
		t.Fatal(err)
	}
	refs, _, err := f.store.ConfirmedGenerationRefs(ctx, 4)
	if err != nil || len(refs) != 1 || !refs[0].PayloadRetained {
		t.Fatalf("fixture lost compacted committed evidence: %+v %v", refs, err)
	}
	closure, err := Build(ctx, f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatalf("committed history compaction rejected: %v", err)
	}
	defer closure.Close()
	parent := testSealedDir(t, f)
	destination := filepath.Join(parent, "compacted.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(ctx, destination, key); err != nil {
		t.Fatal(err)
	}
	report, err := PreflightInertArchive(ctx, destination, key, nil)
	if err != nil || !report.SchemaCatalogVerified || !report.SQLiteLogicalVerified ||
		report.RestoreSupported || report.RestoreReady {
		t.Fatalf("compacted committed history failed authenticated inspection: %+v %v", report, err)
	}
}

// Retained empty history is valid for inspection, but never a usable restore.
func TestArchiveLifecycleAcceptsEmptyInitialDatabaseWithoutRestore(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	closure, err := Build(ctx, f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	parent := testSealedDir(t, f)
	destination := filepath.Join(parent, "empty-history.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(ctx, destination, key); err != nil {
		t.Fatal(err)
	}
	report, err := PreflightInertArchive(ctx, destination, key, nil)
	if err != nil || !report.SchemaCatalogVerified || !report.SQLiteLogicalVerified ||
		report.GenerationCount != 0 || report.RestoreSupported || report.RestoreReady {
		t.Fatalf("empty immutable state acquired restore authority: %+v %v", report, err)
	}
}
