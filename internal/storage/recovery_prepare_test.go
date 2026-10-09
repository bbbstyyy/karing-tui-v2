package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func historicalRestoreFixture(t *testing.T) (*Store, HistoricalRestorePrecondition, Attempt, Attempt) {
	t.Helper()
	ctx := context.Background()
	store := openRetentionTestStore(t, ctx, RetentionPolicy{
		ConfirmedGenerations: 2, MaxGenerationBytes: 1 << 20,
	})
	t.Cleanup(func() { store.Close() })
	head, err := store.CommitDeclaration(ctx, 0, []byte(`{"schema_version":1,"source":"fixture"}`), "test:history")
	if err != nil {
		t.Fatal(err)
	}
	commit := func(rev uint64, label string) Attempt {
		t.Helper()
		native := []byte(fmt.Sprintf(`{"generation":%q}`, label))
		manifest := []byte(fmt.Sprintf(
			`{"schema_id":"test","config_sha256":%q,"declaration_revision":%d,"declaration_sha256":%q}`,
			sha256String(native), head.Revision, head.SHA256))
		attempt, err := store.PrepareApplyWithMetadata(ctx, rev, native, manifest, []byte(`[]`))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.BeginActivation(ctx, attempt.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.BeginVerification(ctx, attempt.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.CommitApplied(ctx, attempt.ID, true); err != nil {
			t.Fatal(err)
		}
		return attempt
	}
	first := commit(0, "original")
	second := commit(1, "replacement")
	if _, err := store.SetCurrentSelectionIntent(ctx, []byte(`{"kind":"specific_node","profile_id":"fixture","node_id":"one"}`)); err != nil {
		t.Fatal(err)
	}
	source, err := store.GenerationArtifacts(ctx, first.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	selection, _, err := store.CurrentSelectionIntent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := HistoricalRestorePrecondition{
		SourceGenerationID:                first.GenerationID,
		SourceConfigSHA256:                source.ConfigSHA256,
		SourceManifestSHA256:              source.ManifestSHA256,
		SourceMapSHA256:                   source.SourceMapSHA256,
		ExpectedConfigRevision:            2,
		ExpectedAppliedGenerationID:       second.GenerationID,
		ExpectedLastKnownGoodGenerationID: second.GenerationID,
		ExpectedDeclarationRevision:       head.Revision,
		ExpectedDeclarationSHA256:         head.SHA256,
		ExpectedSelectionRevision:         selection.Revision,
		ExpectedRoutingMode:               RoutingModeRule,
		ExpectedPrivateDirect:             false,
		ExpectedCoreDesiredState:          CoreDesiredStopped,
	}
	return store, p, first, second
}

func TestHistoricalRestorePrepareCopiesCommittedPayloadWithoutActivating(t *testing.T) {
	store, p, first, second := historicalRestoreFixture(t)
	ctx := context.Background()
	// Archived success must be accepted while its immutable payload exists.
	if _, err := store.PruneRetention(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	attempt, copied, err := store.PrepareHistoricalRestore(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.Phase != PhasePrepared || attempt.GenerationID == first.GenerationID ||
		attempt.GenerationID == second.GenerationID ||
		attempt.TargetRevision != 3 || attempt.BaseRevision != 2 ||
		attempt.PreviousGenerationID == nil || *attempt.PreviousGenerationID != second.GenerationID {
		t.Fatalf("candidate did not keep protected rollback reference: %+v", attempt)
	}
	original, err := store.GenerationArtifacts(ctx, first.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := store.GenerationArtifacts(ctx, attempt.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original.ConfigJSON, copied.ConfigJSON) ||
		!bytes.Equal(original.ManifestJSON, staged.ManifestJSON) ||
		!bytes.Equal(original.SourceMapJSON, staged.SourceMapJSON) ||
		original.ConfigSHA256 != staged.ConfigSHA256 {
		t.Fatal("historical config and metadata were not copied exactly")
	}
	var origin sql.NullInt64
	if err := store.db.QueryRowContext(ctx, `SELECT restore_origin_generation_id
		FROM generations WHERE id = ?`, attempt.GenerationID).Scan(&origin); err != nil {
		t.Fatal(err)
	}
	if !origin.Valid || origin.Int64 != first.GenerationID {
		t.Fatalf("candidate lost historical origin: %+v", origin)
	}
	after, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision ||
		after.AppliedGenerationID == nil || *after.AppliedGenerationID != second.GenerationID ||
		after.LastKnownGoodGenerationID == nil || *after.LastKnownGoodGenerationID != second.GenerationID ||
		after.ActiveAttemptID == nil || *after.ActiveAttemptID != attempt.ID {
		t.Fatalf("prepare changed confirmed active state: %+v", after)
	}
	refs, _, err := store.ConfirmedGenerationRefs(ctx, 12)
	if err != nil || len(refs) != 2 {
		t.Fatalf("unverified restore candidate leaked into success history: %+v err=%v", refs, err)
	}
	if _, _, err := store.PrepareHistoricalRestore(ctx, p); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("double restore prepare error=%v, want active apply conflict", err)
	}
	if err := store.AbortPrepared(ctx, attempt.ID, "test cancelled"); err != nil {
		t.Fatal(err)
	}
	final, err := store.Snapshot(ctx)
	if err != nil || final.ActiveAttemptID != nil || final.Revision != 2 {
		t.Fatalf("cancel left active prepared state: %+v err=%v", final, err)
	}
}

func TestHistoricalRestorePrepareRejectsAllStaleBindingsWithoutMutation(t *testing.T) {
	cases := []struct {
		name   string
		change func(context.Context, *Store, *HistoricalRestorePrecondition) error
		want   error
	}{
		{"config revision", func(_ context.Context, _ *Store, p *HistoricalRestorePrecondition) error {
			p.ExpectedConfigRevision++
			return nil
		}, ErrHistoricalRestoreChanged},
		{"applied generation", func(_ context.Context, _ *Store, p *HistoricalRestorePrecondition) error {
			p.ExpectedAppliedGenerationID++
			return nil
		}, ErrHistoricalRestoreChanged},
		{"last-known-good generation", func(_ context.Context, _ *Store, p *HistoricalRestorePrecondition) error {
			p.ExpectedLastKnownGoodGenerationID++
			return nil
		}, ErrHistoricalRestoreChanged},
		{"declaration revision", func(_ context.Context, _ *Store, p *HistoricalRestorePrecondition) error {
			p.ExpectedDeclarationRevision++
			return nil
		}, ErrHistoricalRestoreChanged},
		{"declaration SHA", func(_ context.Context, _ *Store, p *HistoricalRestorePrecondition) error {
			p.ExpectedDeclarationSHA256 = strings.Repeat("a", 64)
			return nil
		}, ErrHistoricalRestoreChanged},
		{"selection revision", func(_ context.Context, _ *Store, p *HistoricalRestorePrecondition) error {
			p.ExpectedSelectionRevision++
			return nil
		}, ErrHistoricalRestoreChanged},
		{"live selection update", func(ctx context.Context, s *Store, _ *HistoricalRestorePrecondition) error {
			_, err := s.SetCurrentSelectionIntent(ctx, []byte(`{"kind":"specific_node","profile_id":"fixture","node_id":"two"}`))
			return err
		}, ErrHistoricalRestoreChanged},
		{"routing mode", func(ctx context.Context, s *Store, _ *HistoricalRestorePrecondition) error {
			return s.SetRoutingMode(ctx, RoutingModeDirect)
		}, ErrHistoricalRestoreChanged},
		{"private direct", func(ctx context.Context, s *Store, _ *HistoricalRestorePrecondition) error {
			return s.SetRoutingPolicy(ctx, RoutingModeRule, true)
		}, ErrHistoricalRestoreChanged},
		{"desired state", func(ctx context.Context, s *Store, _ *HistoricalRestorePrecondition) error {
			return s.SetCoreDesiredState(ctx, CoreDesiredRunning)
		}, ErrHistoricalRestoreChanged},
		{"source digest changed", func(_ context.Context, _ *Store, p *HistoricalRestorePrecondition) error {
			p.SourceConfigSHA256 = strings.Repeat("a", 64)
			return nil
		}, ErrHistoricalRestoreUnavailable},
		{"bad digest format", func(_ context.Context, _ *Store, p *HistoricalRestorePrecondition) error {
			p.SourceManifestSHA256 = "invalid"
			return nil
		}, ErrHistoricalRestoreRejected},
		{"recovery required", func(ctx context.Context, s *Store, _ *HistoricalRestorePrecondition) error {
			_, err := s.db.ExecContext(ctx, `UPDATE daemon_state SET recovery_required = 1 WHERE singleton = 1`)
			return err
		}, ErrRecoveryRequired},
		{"active apply", func(ctx context.Context, s *Store, p *HistoricalRestorePrecondition) error {
			_, err := s.PrepareApply(ctx, p.ExpectedConfigRevision, []byte(`{"pending":true}`))
			return err
		}, ErrApplyInProgress},
		{"corrupt source metadata", func(ctx context.Context, s *Store, p *HistoricalRestorePrecondition) error {
			_, err := s.db.ExecContext(ctx, `UPDATE generations SET manifest_sha256 = ? WHERE id = ?`,
				strings.Repeat("b", 64), p.SourceGenerationID)
			return err
		}, ErrHistoricalRestoreUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, p, _, _ := historicalRestoreFixture(t)
			ctx := context.Background()
			if err := tc.change(ctx, store, &p); err != nil {
				t.Fatal(err)
			}
			var beforeCount int
			if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM generations`).Scan(&beforeCount); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.PrepareHistoricalRestore(ctx, p); !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			var afterCount int
			if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM generations`).Scan(&afterCount); err != nil {
				t.Fatal(err)
			}
			if afterCount != beforeCount {
				t.Fatalf("refused restore inserted generations: before=%d after=%d", beforeCount, afterCount)
			}
		})
	}
}

func TestHistoricalRestorePrepareRejectsPrunedAndUnconfirmedSources(t *testing.T) {
	t.Run("pruned", func(t *testing.T) {
		store, p, first, _ := historicalRestoreFixture(t)
		ctx := context.Background()
		native := []byte(`{"generation":"third"}`)
		manifest := []byte(fmt.Sprintf(
			`{"schema_id":"test","config_sha256":%q,"declaration_revision":%d,"declaration_sha256":%q}`,
			sha256String(native), p.ExpectedDeclarationRevision, p.ExpectedDeclarationSHA256))
		third, err := store.PrepareApplyWithMetadata(ctx, 2, native, manifest, []byte(`[]`))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.BeginActivation(ctx, third.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.BeginVerification(ctx, third.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.CommitApplied(ctx, third.ID, true); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PruneRetention(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.GenerationConfig(ctx, first.GenerationID); err == nil {
			t.Fatal("old source was not pruned by retention fixture")
		}
		p.ExpectedConfigRevision = 3
		p.ExpectedAppliedGenerationID = third.GenerationID
		p.ExpectedLastKnownGoodGenerationID = third.GenerationID
		if _, _, err := store.PrepareHistoricalRestore(ctx, p); !errors.Is(err, ErrHistoricalRestoreUnavailable) {
			t.Fatalf("pruned historical source: %v", err)
		}
	})
	t.Run("unconfirmed", func(t *testing.T) {
		store, p, _, _ := historicalRestoreFixture(t)
		ctx := context.Background()
		native := []byte(`{"generation":"unverified"}`)
		manifest := []byte(fmt.Sprintf(
			`{"schema_id":"test","config_sha256":%q,"declaration_revision":%d,"declaration_sha256":%q}`,
			sha256String(native), p.ExpectedDeclarationRevision, p.ExpectedDeclarationSHA256))
		candidate, err := store.PrepareApplyWithMetadata(ctx, 2, native, manifest, []byte(`[]`))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.AbortPrepared(ctx, candidate.ID, "unverified"); err != nil {
			t.Fatal(err)
		}
		artifacts, err := store.GenerationArtifacts(ctx, candidate.GenerationID)
		if err != nil {
			t.Fatal(err)
		}
		p.SourceGenerationID = candidate.GenerationID
		p.SourceConfigSHA256 = artifacts.ConfigSHA256
		p.SourceManifestSHA256 = artifacts.ManifestSHA256
		p.SourceMapSHA256 = artifacts.SourceMapSHA256
		if _, _, err := store.PrepareHistoricalRestore(ctx, p); !errors.Is(err, ErrHistoricalRestoreUnavailable) {
			t.Fatalf("unconfirmed historical candidate: %v", err)
		}
	})
}

func TestHistoricalRestorePrepareBudgetAndArchivedHashAreFailClosed(t *testing.T) {
	store, p, _, _ := historicalRestoreFixture(t)
	ctx := context.Background()
	if _, err := store.PruneRetention(ctx); err != nil {
		t.Fatal(err)
	}
	// Corrupted archived history cannot claim success merely because its
	// retained generation bytes still hash correctly.
	if _, err := store.db.ExecContext(ctx, `UPDATE apply_history SET config_sha256 = ?
		WHERE generation_id = ?`, strings.Repeat("c", 64), p.SourceGenerationID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.PrepareHistoricalRestore(ctx, p); !errors.Is(err, ErrHistoricalRestoreUnavailable) {
		t.Fatalf("bad archived provenance passed: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE apply_history SET config_sha256 = ?
		WHERE generation_id = ?`, p.SourceConfigSHA256, p.SourceGenerationID); err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.GenerationArtifacts(ctx, p.SourceGenerationID)
	if err != nil {
		t.Fatal(err)
	}
	store.retention.MaxGenerationBytes, err = generationBytesTxForTest(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	store.retention.MaxGenerationBytes += int64(len(artifacts.ConfigJSON) + len(artifacts.ManifestJSON) + len(artifacts.SourceMapJSON) - 1)
	var countBefore int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM generations`).Scan(&countBefore); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.PrepareHistoricalRestore(ctx, p); !errors.Is(err, ErrGenerationStorageBudget) {
		t.Fatalf("quota bypass: %v", err)
	}
	var countAfter int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM generations`).Scan(&countAfter); err != nil {
		t.Fatal(err)
	}
	if countAfter != countBefore {
		t.Fatal("out-of-quota restore mutated historical payloads")
	}
}

func generationBytesTxForTest(ctx context.Context, store *Store) (int64, error) {
	var retained int64
	err := store.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(
		length(config_json) + COALESCE(length(manifest_json),0) + COALESCE(length(source_map_json),0)
	),0) FROM generations`).Scan(&retained)
	return retained, err
}

func TestHistoricalRestorePreconditionCannotBeForgedWithInvalidFields(t *testing.T) {
	_, p, _, _ := historicalRestoreFixture(t)
	raw, err := json.Marshal(p)
	if err != nil || len(raw) == 0 {
		t.Fatal(err)
	}
	p.ExpectedConfigRevision = 0
	if err := p.validate(); !errors.Is(err, ErrHistoricalRestoreRejected) {
		t.Fatalf("zero expected revision accepted: %v", err)
	}
}
