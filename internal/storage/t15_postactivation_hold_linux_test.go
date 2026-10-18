//go:build linux

package storage

import (
	"bytes"
	"context"
	"os"
	"testing"
)

// These are real Go Store v18 journal transitions on a disposable temporary
// SQLite DB, not Core activation or a guest reboot. A synthetic host witness
// must never make postactivation recovery eligible for safe prepared replay.
func TestGuestAuditPostActivationInterruptionRequiresReconciliation(t *testing.T) {
	for _, stage := range []string{"activating", "verifying", "rolling_back"} {
		t.Run(stage, func(t *testing.T) {
			g := newGuestBridge(t)
			pendingID := g.seedRealV18(t, true)
			ctx := context.Background()
			db, err := Open(ctx, g.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			base, err := db.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.BeginActivation(ctx, pendingID); err != nil {
				t.Fatal(err)
			}
			if stage != "activating" {
				if err := db.BeginVerification(ctx, pendingID); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "rolling_back" {
				if err := db.BeginRollback(ctx, pendingID, "isolated test rollback"); err != nil {
					t.Fatal(err)
				}
			}
			attempt, err := db.Attempt(ctx, pendingID)
			if err != nil || string(attempt.Phase) != stage {
				t.Fatalf("fixture did not persist requested phase: %+v %v", attempt, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			sha := g.capture(t)
			g.syntheticStopObservation(t)
			g.run(t, "verify", sha, false)
			g.run(t, "reconcile-verify", sha, false)

			db, err = Open(ctx, g.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			recovery, err := db.RecoverInterrupted(ctx)
			if err != nil || !recovery.NeedsReconcile ||
				len(recovery.InterruptedAttemptIDs) != 1 ||
				recovery.InterruptedAttemptIDs[0] != pendingID {
				t.Fatalf("postactivation interruption not held: %+v %v", recovery, err)
			}
			after, err := db.Snapshot(ctx)
			if err != nil || !after.RecoveryRequired || after.ActiveAttemptID != nil ||
				after.Revision != base.Revision ||
				after.AppliedGenerationID == nil || base.AppliedGenerationID == nil ||
				*after.AppliedGenerationID != *base.AppliedGenerationID ||
				after.LastKnownGoodGenerationID == nil || base.LastKnownGoodGenerationID == nil ||
				*after.LastKnownGoodGenerationID != *base.LastKnownGoodGenerationID ||
				after.CoreDesiredState != CoreDesiredStopped {
				t.Fatalf("postactivation recovery altered confirmed state: %+v %+v %v", base, after, err)
			}
			finished, err := db.Attempt(ctx, pendingID)
			if err != nil || finished.Phase != PhaseInterrupted ||
				finished.GenerationID != attempt.GenerationID ||
				finished.ConfigSHA256 != attempt.ConfigSHA256 {
				t.Fatalf("interrupted candidate identity changed: %+v -> %+v %v", attempt, finished, err)
			}
			again, err := db.RecoverInterrupted(ctx)
			if err != nil || again.NeedsReconcile || len(again.InterruptedAttemptIDs) != 0 {
				t.Fatalf("idempotent replay unexpectedly changed journal: %+v %v", again, err)
			}
			afterAgain, err := db.Snapshot(ctx)
			if err != nil || !afterAgain.RecoveryRequired {
				t.Fatalf("second replay cleared the mandatory hold: %+v %v", afterAgain, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			beforeAudit, err := os.ReadFile(g.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			g.run(t, "verify", sha, false)
			g.run(t, "reconcile-verify", sha, false)
			afterAudit, err := os.ReadFile(g.dbPath)
			if err != nil || !bytes.Equal(beforeAudit, afterAudit) {
				t.Fatalf("negative Python replay changed real guest SQLite file: %v", err)
			}
			db, err = Open(ctx, g.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			reopened, err := db.Snapshot(ctx)
			if err != nil || !reopened.RecoveryRequired ||
				reopened.Revision != base.Revision ||
				reopened.ActiveAttemptID != nil {
				t.Fatalf("reopen incorrectly cleared unresolved postactivation: %+v %v", reopened, err)
			}
		})
	}
}

func TestGuestAuditFailedRollbackRetainsManualHold(t *testing.T) {
	g := newGuestBridge(t)
	pendingID := g.seedRealV18(t, true)
	ctx := context.Background()
	db, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := db.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.BeginActivation(ctx, pendingID); err != nil {
		t.Fatal(err)
	}
	if err := db.BeginRollback(ctx, pendingID, "isolated test failure"); err != nil {
		t.Fatal(err)
	}
	if err := db.FailRollback(ctx, pendingID, "isolated test rollback failure"); err != nil {
		t.Fatal(err)
	}
	held, err := db.Snapshot(ctx)
	if err != nil || !held.RecoveryRequired || held.ActiveAttemptID != nil ||
		held.Revision != initial.Revision ||
		held.AppliedGenerationID == nil || initial.AppliedGenerationID == nil ||
		*held.AppliedGenerationID != *initial.AppliedGenerationID {
		t.Fatalf("failed rollback did not retain applied generation and recovery hold: %+v %v", held, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	sha := g.capture(t)
	g.syntheticStopObservation(t)
	g.run(t, "verify", sha, false)
	g.run(t, "reconcile-verify", sha, false)
	db, err = Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := db.RecoverInterrupted(ctx)
	if err != nil || replayed.NeedsReconcile || len(replayed.InterruptedAttemptIDs) != 0 {
		t.Fatalf("inactive failed-rollback journal was treated as a new safe apply: %+v %v", replayed, err)
	}
	snapshot, err := db.Snapshot(ctx)
	if err != nil || !snapshot.RecoveryRequired ||
		snapshot.AppliedGenerationID == nil || initial.AppliedGenerationID == nil ||
		*snapshot.AppliedGenerationID != *initial.AppliedGenerationID {
		t.Fatalf("inactive failed-rollback hold incorrectly cleared: %+v %v", snapshot, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", sha, false)
	g.run(t, "reconcile-verify", sha, false)
}
