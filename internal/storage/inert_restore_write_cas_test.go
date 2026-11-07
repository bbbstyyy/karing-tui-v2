package storage

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// No prepared journal, applied state, or LKG may change when a write-intent
// CAS succeeds, fails, is cancelled, or rolls back an injected error.
func TestInertRestoreWriteCASChecksAndRollsBackWithoutPersisting(t *testing.T) {
	s, expected := newCommittedInertFenceFixture(t)
	ctx := context.Background()
	before, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckInertRestoreWriteCAS(ctx, expected); err != nil {
		t.Fatalf("write-intent precondition refused current fence: %v", err)
	}
	if err := s.CheckInertRestoreWriteCAS(ctx, expected); err != nil {
		t.Fatalf("initial CAS did not release the writer lease: %v", err)
	}
	after, err := s.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) ||
		after.ActiveAttemptID != nil {
		t.Fatalf("inert CAS mutated committed live state: before=%+v after=%+v err=%v", before, after, err)
	}
	refs, _, err := s.ConfirmedGenerationRefs(ctx, 12)
	if err != nil || len(refs) != 1 {
		t.Fatalf("inert CAS inserted a journal row or changed history: %+v %v", refs, err)
	}
	if err := s.checkInertRestoreWriteCAS(ctx, expected, func() error {
		return errors.New("fault-injected rollback")
	}); !errors.Is(err, ErrInertRestoreWriteCASUnavailable) {
		t.Fatalf("fault was not converted to refusal: %v", err)
	}
	// Even after a failed probe, a valid real writer still works.
	if _, err := s.SetCurrentSelectionIntent(ctx,
		[]byte(`{"kind":"specific_node","profile_id":"stable","node_id":"still-writable"}`)); err != nil {
		t.Fatalf("probe held a stale SQLite write lock: %v", err)
	}
	if err := s.CheckInertRestoreWriteCAS(ctx, expected); !errors.Is(err, ErrInertRestoreFenceChanged) {
		t.Fatalf("selection change did not invalidate write CAS: %v", err)
	}
}

func TestInertRestoreWriteCASRejectsAllStaleOrInvalidBindings(t *testing.T) {
	cases := []struct {
		name   string
		change func(context.Context, *Store) error
		want   error
	}{
		{"selection_revision", func(ctx context.Context, s *Store) error {
			_, err := s.SetCurrentSelectionIntent(ctx,
				[]byte(`{"kind":"specific_node","profile_id":"stable","node_id":"second"}`))
			return err
		}, ErrInertRestoreFenceChanged},
		{"selection_digest_without_revision", func(ctx context.Context, s *Store) error {
			_, err := s.db.ExecContext(ctx,
				"UPDATE selection_state SET current_target_json = ? WHERE singleton = 1",
				[]byte(`{"kind":"specific_node","profile_id":"stable","node_id":"hidden-change"}`))
			return err
		}, ErrInertRestoreFenceChanged},
		{"declaration", func(ctx context.Context, s *Store) error {
			_, err := s.CommitDeclaration(ctx, 1, []byte(`{"schema_version":1,"changed":true}`),
				"test:restore-fence")
			return err
		}, ErrInertRestoreFenceChanged},
		{"core_desired", func(ctx context.Context, s *Store) error {
			return s.SetCoreDesiredState(ctx, CoreDesiredRunning)
		}, ErrInertRestoreFenceChanged},
		{"routing_mode", func(ctx context.Context, s *Store) error {
			_, err := s.db.ExecContext(ctx,
				"UPDATE daemon_state SET routing_mode='global' WHERE singleton=1")
			return err
		}, ErrInertRestoreFenceChanged},
		{"applied_blob", func(ctx context.Context, s *Store) error {
			_, err := s.db.ExecContext(ctx,
				"UPDATE generations SET config_sha256=? WHERE id=(SELECT applied_generation_id FROM daemon_state)",
				strings.Repeat("a", 64))
			return err
		}, ErrInertRestoreWriteCASUnavailable},
		{"recovery_required", func(ctx context.Context, s *Store) error {
			_, err := s.db.ExecContext(ctx,
				"UPDATE daemon_state SET recovery_required=1 WHERE singleton=1")
			return err
		}, ErrInertRestoreFenceChanged},
		{"active_apply", func(ctx context.Context, s *Store) error {
			_, err := s.PrepareApply(ctx, 1, []byte(`{"inbounds":[]}`))
			return err
		}, ErrInertRestoreFenceChanged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, expected := newCommittedInertFenceFixture(t)
			ctx := context.Background()
			if err := tc.change(ctx, s); err != nil {
				t.Fatal(err)
			}
			before, err := s.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.CheckInertRestoreWriteCAS(ctx, expected); !errors.Is(err, tc.want) {
				t.Fatalf("stale write CAS result=%v, want %v", err, tc.want)
			}
			after, err := s.Snapshot(ctx)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("refused CAS changed live state: before=%+v after=%+v err=%v", before, after, err)
			}
		})
	}
}

func TestInertRestoreWriteCASRefusesForgedFenceAndCancel(t *testing.T) {
	s, fence := newCommittedInertFenceFixture(t)
	ctx := context.Background()
	for _, scenario := range []string{"zero_config", "invalid_hash", "overflow_revision", "invalid_mode"} {
		bad := fence
		switch scenario {
		case "zero_config":
			bad.ConfigRevision = 0
		case "invalid_hash":
			bad.SelectionSHA256 = strings.Repeat("g", 64)
		case "overflow_revision":
			bad.DeclarationRevision = ^uint64(0)
		case "invalid_mode":
			bad.RoutingMode = RoutingMode("unrecognized")
		}
		if err := s.CheckInertRestoreWriteCAS(ctx, bad); !errors.Is(err, ErrInertRestoreWriteCASUnavailable) {
			t.Fatalf("forged %s got %v", scenario, err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.CheckInertRestoreWriteCAS(canceled, fence); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled precondition succeeded: %v", err)
	}
	running, stop := context.WithCancel(context.Background())
	defer stop()
	if err := s.checkInertRestoreWriteCAS(running, fence, func() error {
		stop()
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-transaction cancel did not fail closed: %v", err)
	}
	if err := s.CheckInertRestoreWriteCAS(context.Background(), fence); err != nil {
		t.Fatalf("cancel left a hidden write transaction behind: %v", err)
	}
}

func TestInertRestoreWriteCASBlocksParallelWriterUntilRollback(t *testing.T) {
	s, fence := newCommittedInertFenceFixture(t)
	ctx := context.Background()
	other, err := Open(ctx, s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	// A short busy timeout makes the conflict deterministic without
	// requiring external clocks or a long test delay.
	if _, err := other.db.ExecContext(ctx, "PRAGMA busy_timeout = 100"); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.checkInertRestoreWriteCAS(ctx, fence, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("SQLite writer reservation was not acquired")
	}
	// Open's second connection must not be able to commit a competing
	// selection update while the guarded no-change UPDATE holds the lock.
	conflictCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	_, competingErr := other.SetCurrentSelectionIntent(conflictCtx,
		[]byte(`{"kind":"specific_node","profile_id":"stable","node_id":"contending"}`))
	cancel()
	close(release)
	if competingErr == nil {
		t.Fatal("competing writer committed during exclusive CAS transaction")
	}
	if err := <-done; err != nil {
		t.Fatalf("rollback failed to release SQLite writer reservation: %v", err)
	}
	if _, err := other.SetCurrentSelectionIntent(ctx,
		[]byte(`{"kind":"specific_node","profile_id":"stable","node_id":"after-lock"}`)); err != nil {
		t.Fatalf("writer stayed blocked after rollback: %v", err)
	}
	if err := s.CheckInertRestoreWriteCAS(ctx, fence); !errors.Is(err, ErrInertRestoreFenceChanged) {
		t.Fatalf("post-lock mutation was not detected: %v", err)
	}
}
