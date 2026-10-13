//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestInertRestoreWriteBoundaryNonMutatingCAS(t *testing.T) {
	f, candidate, key := createInertDryRunFixture(t)
	ctx := context.Background()
	initial, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dryRun, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckInertRestoreWriteBoundary(ctx, f.store, candidate, key, dryRun); err != nil {
		t.Fatalf("atomically checked write-intent fence refused valid candidate: %v", err)
	}
	if dryRun.RestoreReady || dryRun.RestoreSupported {
		t.Fatal("write precondition generated restore permission")
	}
	final, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(initial, final) ||
		final.ActiveAttemptID != nil || final.RecoveryRequired {
		t.Fatalf("write-intent check modified running state: %+v -> %+v %v", initial, final, err)
	}
	refs, _, err := f.store.ConfirmedGenerationRefs(ctx, 12)
	if err != nil || len(refs) != 1 {
		t.Fatalf("write precondition changed successful history: %+v %v", refs, err)
	}
}

func TestInertRestoreWriteBoundaryClosesBetweenReadAndSQLCheck(t *testing.T) {
	for _, change := range []string{"selection", "declaration"} {
		t.Run(change, func(t *testing.T) {
			f, candidate, key := createInertDryRunFixture(t)
			ctx := context.Background()
			dryRun, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
			if err != nil {
				t.Fatal(err)
			}
			err = checkInertRestoreWriteBoundary(
				ctx, f.store, candidate, key, dryRun, func() error {
					if change == "selection" {
						_, err := f.store.SetCurrentSelectionIntent(ctx,
							[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"late"}`))
						return err
					}
					_, err := f.store.CommitDeclaration(ctx, f.declarationRevision,
						[]byte(`{"version":1,"changed":"late"}`),
						"test:backup-closure")
					return err
				},
			)
			if !errors.Is(err, ErrInertRestoreDryRunChanged) {
				t.Fatalf("live writer passed post-recheck SQLite CAS: %v", err)
			}
			if snapshot, err := f.store.Snapshot(ctx); err != nil ||
				snapshot.ActiveAttemptID != nil || snapshot.RecoveryRequired ||
				snapshot.Revision != f.configRevision {
				t.Fatalf("inert write boundary started actual apply: %+v %v", snapshot, err)
			}
		})
	}
}

func TestInertRestoreWriteBoundaryRejectsFaultAndStaleReport(t *testing.T) {
	f, candidate, key := createInertDryRunFixture(t)
	ctx := context.Background()
	dryRun, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkInertRestoreWriteBoundary(ctx, f.store, candidate, key, dryRun,
		func() error { return errors.New("simulated disk/core boundary failure") },
	); !errors.Is(err, ErrInertRestoreDryRunRejected) {
		t.Fatalf("injected phase failure accepted: %v", err)
	}
	if err := CheckInertRestoreWriteBoundary(ctx, f.store, candidate, key, dryRun); err != nil {
		t.Fatalf("refused phase left SQL transaction blocked: %v", err)
	}
	tampered := dryRun
	tampered.RestoreReady = true
	if err := CheckInertRestoreWriteBoundary(ctx, f.store, candidate, key, tampered);
		!errors.Is(err, ErrInertRestoreDryRunRejected) {
		t.Fatalf("forged restore permission accepted: %v", err)
	}
	tampered = dryRun
	tampered.Baseline.SelectionSHA256 = "not-a-hash"
	if err := CheckInertRestoreWriteBoundary(ctx, f.store, candidate, key, tampered);
		!errors.Is(err, ErrInertRestoreDryRunChanged) &&
			!errors.Is(err, ErrInertRestoreDryRunRejected) {
		t.Fatalf("forged CAS baseline accepted: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := CheckInertRestoreWriteBoundary(canceled, f.store, candidate, key, dryRun);
		!errors.Is(err, context.Canceled) {
		t.Fatalf("cancel did not abort guarded write fence: %v", err)
	}
	if _, err := f.store.SetCurrentSelectionIntent(ctx,
		[]byte(`{"kind":"specific_node","profile_id":"stable","node_id":"works-after-rollback"}`)); err != nil {
		t.Fatalf("refused CAS blocked normal selection update: %v", err)
	}
}

func TestInertRestoreWriteBoundaryRefusesUnsafeLiveAndCandidate(t *testing.T) {
	f, candidate, key := createInertDryRunFixture(t)
	ctx := context.Background()
	evidence, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PrepareApply(ctx, f.configRevision, []byte(`{"inbounds":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := CheckInertRestoreWriteBoundary(ctx, f.store, candidate, key, evidence);
		!errors.Is(err, ErrInertRestoreDryRunRejected) {
		t.Fatalf("active apply state accepted: %v", err)
	}
}

