package coreartifact

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func recoveryScopeFixture(t *testing.T) (*RuleSetSnapshot, *RuleSetPin, string) {
	t.Helper()
	source, hash, _ := pinnedRuleSetFixture(t)
	pin, err := PinRuleSet(source, hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pin.Close() })
	root := filepath.Join(t.TempDir(), "core")
	scope, err := StagePinnedRuleSetSnapshot(context.Background(), root, []*RuleSetPin{pin})
	if err != nil {
		t.Fatal(err)
	}
	return scope, pin, root
}

func simulateSnapshotCrash(t *testing.T, scope *RuleSetSnapshot) {
	t.Helper()
	if scope == nil || scope.lock == nil {
		t.Fatal("snapshot is not locked")
	}
	// Releasing the open directory descriptor simulates the kernel dropping
	// a process lifetime flock after SIGKILL or power interruption.
	if err := scope.lock.Close(); err != nil {
		t.Fatal(err)
	}
	scope.lock = nil
}

func TestRuleSetSnapshotRecoverySkipsActiveAndReclaimsAbandonedScope(t *testing.T) {
	scope, _, root := recoveryScopeFixture(t)
	extraLock, err := lockSnapshotDirectory(scope.dir)
	if !errors.Is(err, ErrRuleSetSnapshotActive) || extraLock != nil {
		t.Fatalf("an independent descriptor could take a live scope lock: %v", err)
	}
	report, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), root)
	if err != nil || report.Active != 1 || report.Reclaimed != 0 {
		t.Fatalf("live scope was touched: %+v err=%v", report, err)
	}
	if err := scope.Verify(context.Background()); err != nil {
		t.Fatalf("reclaimer altered live scope: %v", err)
	}
	path := scope.dir
	simulateSnapshotCrash(t, scope)
	report, err = ReclaimOrphanedRuleSetSnapshots(context.Background(), root)
	if err != nil || report.Active != 0 || report.Reclaimed != 1 {
		t.Fatalf("abandoned scope was not reclaimed: %+v err=%v", report, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan path was not removed: %v", err)
	}
	if report, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), root); err != nil ||
		report.Reclaimed != 0 {
		t.Fatalf("reclaim was not idempotent: %+v err=%v", report, err)
	}
}

func TestRuleSetSnapshotRecoveryAllowsPartialPrivateCopyAfterCrash(t *testing.T) {
	scope, pin, root := recoveryScopeFixture(t)
	copyPath, ok := scope.FileFor(pin.path)
	if !ok {
		t.Fatal("missing isolated copy")
	}
	// A crash during io.Copy leaves a 0600 partial file instead of 0400.
	if err := os.Chmod(copyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	simulateSnapshotCrash(t, scope)
	report, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), root)
	if err != nil || report.Reclaimed != 1 {
		t.Fatalf("partial 0600 copy blocked crash recovery: %+v err=%v", report, err)
	}
	if _, err := os.Lstat(copyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial copy survived recovery: %v", err)
	}
}

func TestRuleSetSnapshotRecoveryNeverDeletesUnknownOrReplacedEntries(t *testing.T) {
	for _, mutation := range []struct {
		name string
		do   func(t *testing.T, scope *RuleSetSnapshot, pin *RuleSetPin)
	}{
		{"unknown-file", func(t *testing.T, scope *RuleSetSnapshot, _ *RuleSetPin) {
			if err := os.WriteFile(filepath.Join(scope.dir, "unknown"), []byte("leave"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-file", func(t *testing.T, scope *RuleSetSnapshot, _ *RuleSetPin) {
			if err := os.Symlink(filepath.Join(t.TempDir(), "outside"),
				filepath.Join(scope.dir, "link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"world-readable", func(t *testing.T, scope *RuleSetSnapshot, pin *RuleSetPin) {
			copyPath, _ := scope.FileFor(pin.path)
			if err := os.Chmod(copyPath, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"replaced-file", func(t *testing.T, scope *RuleSetSnapshot, pin *RuleSetPin) {
			copyPath, _ := scope.FileFor(pin.path)
			if err := os.Rename(copyPath, copyPath+".moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(copyPath, []byte("not the file originally owned"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			scope, pin, root := recoveryScopeFixture(t)
			originalDir := scope.dir
			mutation.do(t, scope, pin)
			simulateSnapshotCrash(t, scope)
			report, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), root)
			if !errors.Is(err, ErrUnsafeRuleSetSnapshot) || report.Reclaimed != 0 {
				t.Fatalf("unsafe scope was deleted: %+v err=%v", report, err)
			}
			if _, err := os.Lstat(originalDir); err != nil {
				t.Fatalf("unsafe scope was removed: %v", err)
			}
		})
	}
}

func TestRuleSetSnapshotRecoveryRefusesSymlinkScopeAndUnsafeParent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "core")
	if err := os.MkdirAll(filepath.Join(root, "historical-check-snapshots"), 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "historical-check-snapshots")
	outside := t.TempDir()
	badScope := filepath.Join(parent, ".check-SYMLINK")
	if err := os.Symlink(outside, badScope); err != nil {
		t.Fatal(err)
	}
	if _, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), root); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("symlinked scope accepted: %v", err)
	}
	if _, err := os.Lstat(badScope); err != nil {
		t.Fatalf("symlinked scope unexpectedly deleted: %v", err)
	}
	if err := os.Remove(badScope); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), root); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("group-readable snapshot parent accepted: %v", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), root); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("symlinked snapshot parent accepted: %v", err)
	}
}

func TestRuleSetSnapshotRecoveryIsBoundedAndCancellationSafe(t *testing.T) {
	root := filepath.Join(t.TempDir(), "core")
	parent := filepath.Join(root, "historical-check-snapshots")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReclaimOrphanedRuleSetSnapshots(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled recovery ignored cancellation: %v", err)
	}
	for i := 0; i <= MaxRuleSetSnapshotRecoveryScopes; i++ {
		path := filepath.Join(parent, fmt.Sprintf(".check-%06d", i))
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	report, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), root)
	if !errors.Is(err, ErrUnsafeRuleSetSnapshot) || report.Reclaimed != 0 {
		t.Fatalf("unbounded directory scan performed deletions: %+v err=%v", report, err)
	}
	first := filepath.Join(parent, ".check-000000")
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("bounded scan modified first scope: %v", err)
	}
	if _, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), "relative"); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("relative root accepted: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if report, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), missing); err != nil || report.Reclaimed != 0 {
		t.Fatalf("missing root should be read-only no-op: %+v err=%v", report, err)
	}
}

func TestRuleSetSnapshotStageReclaimsPriorCrashButNotOtherLiveScope(t *testing.T) {
	live, pin, root := recoveryScopeFixture(t)
	defer live.Close()
	crashed, err := StagePinnedRuleSetSnapshot(context.Background(), root, []*RuleSetPin{pin})
	if err != nil {
		t.Fatal(err)
	}
	crashedDir := crashed.dir
	simulateSnapshotCrash(t, crashed)
	next, err := StagePinnedRuleSetSnapshot(context.Background(), root, []*RuleSetPin{pin})
	if err != nil {
		t.Fatalf("new check failed to clean previous orphan: %v", err)
	}
	defer next.Close()
	if _, err := os.Lstat(crashedDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("next check leaked previous orphan: %v", err)
	}
	if err := live.Verify(context.Background()); err != nil {
		t.Fatalf("new check removed concurrently live snapshot: %v", err)
	}
	if err := next.Verify(context.Background()); err != nil {
		t.Fatalf("new snapshot was invalid after scavenging: %v", err)
	}
}

func TestRuleSetSnapshotParentLockPreventsCreationRecoveryRace(t *testing.T) {
	live, pin, root := recoveryScopeFixture(t)
	defer live.Close()
	parent := filepath.Join(root, "historical-check-snapshots")
	parentLock, err := lockSnapshotDirectory(parent)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, err := ReclaimOrphanedRuleSetSnapshots(ctx, root); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("recovery ignored a busy parent lock: %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel2()
	if _, err := StagePinnedRuleSetSnapshot(ctx2, root, []*RuleSetPin{pin}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("creation ignored a busy parent lock: %v", err)
	}
	if err := parentLock.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := StagePinnedRuleSetSnapshot(context.Background(), root, []*RuleSetPin{pin})
	if err != nil {
		t.Fatalf("released parent lock prevented new snapshot: %v", err)
	}
	defer next.Close()
	if err := live.Verify(context.Background()); err != nil {
		t.Fatalf("parent lock contention destroyed a live scope: %v", err)
	}
	if next.dir == live.dir || next.lock == nil {
		t.Fatal("new scope did not receive its own exclusive directory lock")
	}
}
