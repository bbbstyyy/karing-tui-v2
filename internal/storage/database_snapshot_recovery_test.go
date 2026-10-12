package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func createOrphanDatabaseSnapshot(t *testing.T, parent, suffix string, content []byte) string {
	t.Helper()
	scope := filepath.Join(parent, ".sqlite-snapshot-v2-"+suffix)
	if err := os.Mkdir(scope, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(scope, 0o700); err != nil {
		t.Fatal(err)
	}
	if content != nil {
		if err := os.WriteFile(filepath.Join(scope, "state.db"), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return scope
}

func TestDatabaseSnapshotReclaimsAbandonedScopesBeforeNextCopy(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()
	parent := privateSnapshotTestDir(t)
	orphan := createOrphanDatabaseSnapshot(t, parent, "crash1234", []byte("partial sqlite data"))
	snapshot, err := store.CreateDatabaseSnapshot(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned scope was not reclaimed before copy: %v", err)
	}
	report, err := ReclaimOrphanedDatabaseSnapshots(ctx, parent)
	if err != nil || report.Active != 1 || report.Reclaimed != 0 {
		t.Fatalf("actively held snapshot was reclaimed: %+v err=%v", report, err)
	}
	if _, err := os.Lstat(snapshot.Path); err != nil {
		t.Fatalf("active copy was damaged: %v", err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	report, err = ReclaimOrphanedDatabaseSnapshots(ctx, parent)
	if err != nil || report.Active != 0 || report.Reclaimed != 0 {
		t.Fatalf("clean close left orphaned scope: %+v err=%v", report, err)
	}
}

func TestDatabaseSnapshotCrashProcessReleasesFlock(t *testing.T) {
	if os.Getenv("KARING_SNAPSHOT_CRASH_CHILD") == "yes" {
		// The helper intentionally exits without closing its scope lock.
		parent := os.Getenv("KARING_SNAPSHOT_PARENT")
		dir := filepath.Join(parent, ".sqlite-snapshot-v2-crashchild")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		lock, err := lockDatabaseSnapshotDirectory(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "state.db"), []byte("aborted VACUUM"), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = lock
		os.Exit(0)
	}
	ctx := context.Background()
	parent := privateSnapshotTestDir(t)
	command := exec.Command(os.Args[0], "-test.run=^TestDatabaseSnapshotCrashProcessReleasesFlock$")
	command.Env = append(os.Environ(), "KARING_SNAPSHOT_CRASH_CHILD=yes", "KARING_SNAPSHOT_PARENT="+parent)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("crashed subprocess setup: %v (%s)", err, output)
	}
	report, err := ReclaimOrphanedDatabaseSnapshots(ctx, parent)
	if err != nil || report.Reclaimed != 1 || report.Active != 0 {
		t.Fatalf("orphaned child scope was not reclaimed: %+v err=%v", report, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("crashed child secret files still present: %+v err=%v", entries, err)
	}
}

func TestDatabaseSnapshotCrossProcessActiveLockIsNotReclaimed(t *testing.T) {
	if os.Getenv("KARING_SNAPSHOT_ACTIVE_CHILD") == "yes" {
		report, err := ReclaimOrphanedDatabaseSnapshots(context.Background(), os.Getenv("KARING_SNAPSHOT_PARENT"))
		if err != nil || report.Active != 1 || report.Reclaimed != 0 {
			t.Fatalf("active cross-process scope: %+v err=%v", report, err)
		}
		return
	}
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()
	parent := privateSnapshotTestDir(t)
	snapshot, err := store.CreateDatabaseSnapshot(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestDatabaseSnapshotCrossProcessActiveLockIsNotReclaimed$")
	command.Env = append(os.Environ(), "KARING_SNAPSHOT_ACTIVE_CHILD=yes", "KARING_SNAPSHOT_PARENT="+parent)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("child must skip active snapshot: %v (%s)", err, output)
	}
	if err := snapshot.verifyFile(); err != nil {
		t.Fatalf("cross-process recovery mutated active file: %v", err)
	}
}

func TestDatabaseSnapshotConcurrentScopeCreationNeverLeavesUnlockedWindow(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()
	parent := privateSnapshotTestDir(t)
	var wg sync.WaitGroup
	type result struct {
		snapshot *DatabaseSnapshot
		err      error
	}
	ch := make(chan result, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := store.CreateDatabaseSnapshot(ctx, parent)
			ch <- result{snapshot: s, err: err}
		}()
	}
	wg.Wait()
	close(ch)
	var snapshots []*DatabaseSnapshot
	for got := range ch {
		if got.err != nil {
			t.Fatalf("concurrent copy failed: %v", got.err)
		}
		snapshots = append(snapshots, got.snapshot)
	}
	defer func() {
		for _, snapshot := range snapshots {
			_ = snapshot.Close()
		}
	}()
	if len(snapshots) != 2 || snapshots[0].Path == snapshots[1].Path {
		t.Fatalf("copies reused a directory: %v", snapshots)
	}
	report, err := ReclaimOrphanedDatabaseSnapshots(ctx, parent)
	if err != nil || report.Active != 2 || report.Reclaimed != 0 {
		t.Fatalf("concurrently active copies unexpectedly reclaimed: %+v err=%v", report, err)
	}
}

func TestDatabaseSnapshotRecoveryParentLockIsContextBounded(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()
	parent := privateSnapshotTestDir(t)
	held, err := lockDatabaseSnapshotDirectory(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	bounded, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	if _, err := store.CreateDatabaseSnapshot(bounded, parent); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("creator bypassed parent lock: %v", err)
	}
	if _, err := ReclaimOrphanedDatabaseSnapshots(bounded, parent); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("scavenger bypassed held parent lock: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("created an unlocked scope while parent busy: %+v %v", entries, err)
	}
}

func TestDatabaseSnapshotRecoveryRefusesForeignAndUnsafeContents(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*testing.T, string, string)
	}{
		{"extra_file", func(t *testing.T, _, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "unrelated"), []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink_file", func(t *testing.T, parent, dir string) {
			if err := os.Symlink(filepath.Join(parent, "victim"), filepath.Join(dir, "state.db")); err != nil {
				t.Fatal(err)
			}
		}},
		{"public_file", func(t *testing.T, _, dir string) {
			file := filepath.Join(dir, "state.db")
			if err := os.WriteFile(file, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlinked_file", func(t *testing.T, parent, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "state.db"), []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(dir, "state.db"), filepath.Join(t.TempDir(), "outside")); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized_file", func(t *testing.T, _, dir string) {
			file := filepath.Join(dir, "state.db")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(file, MaxDatabaseSnapshotBytes+1); err != nil {
				t.Fatal(err)
			}
		}},
		{"nested_directory", func(t *testing.T, _, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := privateSnapshotTestDir(t)
			dir := createOrphanDatabaseSnapshot(t, parent, "unsafe123", nil)
			tc.alter(t, parent, dir)
			if _, err := ReclaimOrphanedDatabaseSnapshots(context.Background(), parent); !errors.Is(err, ErrUnsafeDatabaseSnapshot) {
				t.Fatalf("unsafe orphan accepted: %v", err)
			}
			if _, err := os.Lstat(dir); err != nil {
				t.Fatalf("unsafe scope was deleted: %v", err)
			}
		})
	}
}

func TestDatabaseSnapshotRecoveryRefusesSymlinkedAndUnboundedParents(t *testing.T) {
	parent := privateSnapshotTestDir(t)
	link := filepath.Join(privateSnapshotTestDir(t), "redirect")
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReclaimOrphanedDatabaseSnapshots(context.Background(), link); !errors.Is(err, ErrUnsafeDatabaseSnapshot) {
		t.Fatalf("symlink parent passed recovery: %v", err)
	}
	for i := 0; i <= MaxDatabaseSnapshotRecoveryScopes; i++ {
		createOrphanDatabaseSnapshot(t, parent, fmt.Sprintf("prefix%03d", i), nil)
	}
	if _, err := ReclaimOrphanedDatabaseSnapshots(context.Background(), parent); !errors.Is(err, ErrUnsafeDatabaseSnapshot) {
		t.Fatalf("over-budget scope scan was accepted: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != MaxDatabaseSnapshotRecoveryScopes+1 {
		t.Fatal("over-budget recovery deleted arbitrary scopes")
	}
	missing := filepath.Join(privateSnapshotTestDir(t), "not-created")
	report, err := ReclaimOrphanedDatabaseSnapshots(context.Background(), missing)
	if err != nil || report.Reclaimed != 0 || report.Active != 0 {
		t.Fatalf("missing recovery parent should be no-op: %+v err=%v", report, err)
	}
}

func TestDatabaseSnapshotLegacyUnleasedScopeNeverReclaimed(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()
	parent := privateSnapshotTestDir(t)
	// Earlier M4 snapshots used this unversioned name WITHOUT flock.
	// They may belong to an active older process and are never scavenged.
	legacy := filepath.Join(parent, ".sqlite-snapshot-legacy123")
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(legacy, "state.db")
	if err := os.WriteFile(secret, []byte("legacy-possibly-active"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReclaimOrphanedDatabaseSnapshots(ctx, parent); !errors.Is(err, ErrUnsafeDatabaseSnapshot) {
		t.Fatalf("legacy unleased scope was accepted by new scavenger: %v", err)
	}
	if _, err := store.CreateDatabaseSnapshot(ctx, parent); !errors.Is(err, ErrUnsafeDatabaseSnapshot) {
		t.Fatalf("new snapshot ignored unleased legacy scope: %v", err)
	}
	content, err := os.ReadFile(secret)
	if err != nil || string(content) != "legacy-possibly-active" {
		t.Fatal("legacy scope was damaged")
	}
}
