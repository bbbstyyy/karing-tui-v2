package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func newCommittedInertFenceFixture(t *testing.T) (*Store, InertRestoreFence) {
	t.Helper()
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	t.Cleanup(func() { _ = store.Close() })
	decl, err := store.CommitDeclaration(ctx, 0,
		[]byte(`{"schema_version":1,"source":"inert-restore-fence"}`),
		"test:restore-fence")
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"inbounds":[],"route":{"rules":[]}}`)
	manifest := []byte(fmt.Sprintf(
		`{"schema_id":"test","config_sha256":%q,"declaration_revision":%d,"declaration_sha256":%q}`,
		sha256String(config), decl.Revision, decl.SHA256))
	attempt, err := store.PrepareApplyWithMetadata(
		ctx, 0, config, manifest, []byte(`[]`))
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
	if _, err := store.SetCurrentSelectionIntent(ctx,
		[]byte(`{"kind":"specific_node","profile_id":"stable","node_id":"one"}`)); err != nil {
		t.Fatal(err)
	}
	fence, err := store.ReadInertRestoreFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return store, fence
}

func TestReadInertRestoreFenceBindsCommittedStateWithoutMutations(t *testing.T) {
	store, expected := newCommittedInertFenceFixture(t)
	before, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found, err := store.ReadInertRestoreFence(context.Background())
	if err != nil || expected != found ||
		found.ConfigRevision != 1 || found.AppliedGenerationID <= 0 ||
		found.LastKnownGoodGenerationID != found.AppliedGenerationID ||
		found.DeclarationRevision != 1 || found.SelectionRevision != 1 ||
		len(found.SelectionSHA256) != 64 ||
		found.RoutingMode != RoutingModeRule ||
		found.CoreDesiredState != CoreDesiredStopped {
		t.Fatalf("invalid committed-state fence: %+v %v", found, err)
	}
	if err := store.RecheckInertRestoreFence(context.Background(), expected); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"inbounds", "node_id", "specific_node", "stable"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("fence disclosed private content: %s", secret)
		}
	}
	after, err := store.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("read-only fence changed live state: %+v -> %+v: %v", before, after, err)
	}
}

func TestInertRestoreFenceDetectsStaleCASBindings(t *testing.T) {
	testCases := []struct {
		name string
		update func(context.Context, *Store) error
	}{
		{"selection", func(ctx context.Context, s *Store) error {
			_, err := s.SetCurrentSelectionIntent(ctx,
				[]byte(`{"kind":"specific_node","profile_id":"stable","node_id":"two"}`))
			return err
		}},
		{"declaration", func(ctx context.Context, s *Store) error {
			_, err := s.CommitDeclaration(ctx, 1,
				[]byte(`{"schema_version":1,"source":"modified"}`), "test:restore-fence")
			return err
		}},
		{"desired_core", func(ctx context.Context, s *Store) error {
			return s.SetCoreDesiredState(ctx, CoreDesiredRunning)
		}},
		{"routing_mode", func(ctx context.Context, s *Store) error {
			_, err := s.db.ExecContext(ctx,
				"UPDATE daemon_state SET routing_mode = 'global' WHERE singleton = 1")
			return err
		}},
		{"config_revision", func(ctx context.Context, s *Store) error {
			_, err := s.db.ExecContext(ctx,
				"UPDATE daemon_state SET config_revision = config_revision + 1 WHERE singleton = 1")
			return err
		}},
		{"applied_hash", func(ctx context.Context, s *Store) error {
			_, err := s.db.ExecContext(ctx,
				"UPDATE generations SET config_sha256 = ? WHERE id = (SELECT applied_generation_id FROM daemon_state)",
				strings.Repeat("a", 64))
			return err
		}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store, fence := newCommittedInertFenceFixture(t)
			ctx := context.Background()
			if err := tc.update(ctx, store); err != nil {
				t.Fatal(err)
			}
			err := store.RecheckInertRestoreFence(ctx, fence)
			if !errors.Is(err, ErrInertRestoreFenceChanged) &&
				!errors.Is(err, ErrInertRestoreFenceUnavailable) {
				t.Fatalf("stale/invalid binding escaped fence: %v", err)
			}
		})
	}
}

func TestInertRestoreFenceRefusesUnsafeLiveState(t *testing.T) {
	for _, tc := range []struct{
		name string
		change func(context.Context, *Store) error
	}{
		{"active_apply", func(ctx context.Context, s *Store) error {
			_, err := s.PrepareApply(ctx, 1, []byte(`{"inbounds":[]}`))
			return err
		}},
		{"recovery_required", func(ctx context.Context, s *Store) error {
			_, err := s.db.ExecContext(ctx,
				"UPDATE daemon_state SET recovery_required = 1 WHERE singleton = 1")
			return err
		}},
		{"corrupt_declaration", func(ctx context.Context, s *Store) error {
			_, err := s.db.ExecContext(ctx,
				"UPDATE declaration_revisions SET document_json = ? WHERE revision = 1",
				[]byte(`{"malformed":true}`))
			return err
		}},
		{"invalid_selection", func(ctx context.Context, s *Store) error {
			_, err := s.db.ExecContext(ctx,
				"UPDATE selection_state SET current_target_json = ? WHERE singleton = 1",
				[]byte("invalid-json"))
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := newCommittedInertFenceFixture(t)
			ctx := context.Background()
			if err := tc.change(ctx, store); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ReadInertRestoreFence(ctx); !errors.Is(err, ErrInertRestoreFenceUnavailable) {
				t.Fatalf("invalid live state accepted: %v", err)
			}
		})
	}
}
