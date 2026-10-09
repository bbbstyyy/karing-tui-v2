package coreartifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRuleSetSnapshotCopiesDistinctInodesAndCleansUp(t *testing.T) {
	root := filepath.Join(t.TempDir(), "core")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	var pins []*RuleSetPin
	var origins []string
	for _, data := range [][]byte{
		[]byte(`{"version":4,"rules":[{"domain":["source.example"]}]}`),
		[]byte(`{"version":4,"rules":[{"domain":["fallback.example"]}]}`),
	} {
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		path, _, err := store.PutRuleSet(context.Background(), bytes.NewReader(data), hash, "source")
		if err != nil {
			t.Fatal(err)
		}
		pin, err := PinRuleSet(path, hash)
		if err != nil {
			t.Fatal(err)
		}
		pins = append(pins, pin)
		origins = append(origins, path)
		t.Cleanup(func() { _ = pin.Close() })
	}
	snapshot, err := StagePinnedRuleSetSnapshot(context.Background(), root, pins)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, source := range origins {
		copyPath, exists := snapshot.FileFor(source)
		if !exists {
			t.Fatalf("missing snapshot for %s", source)
		}
		sourceInfo, err := os.Lstat(source)
		if err != nil {
			t.Fatal(err)
		}
		copyInfo, err := os.Lstat(copyPath)
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(sourceInfo, copyInfo) ||
			copyInfo.Mode().Perm() != 0o400 ||
			filepath.Dir(copyPath) != snapshot.dir {
			t.Fatalf("snapshot is not an independent private read-only copy: %+v", copyInfo)
		}
	}
	// The old copy is independently readable even after the shared original
	// pathname has been replaced with same bytes on a new inode.
	originalData, err := os.ReadFile(origins[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(origins[0], origins[0]+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(origins[0], originalData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Verify(context.Background()); err != nil {
		t.Fatalf("isolated copy was invalidated by a shared-path swap: %v", err)
	}
	if err := pins[0].Reverify(context.Background()); !errors.Is(err, ErrUnsafeRuleSetPath) {
		t.Fatalf("original descriptor failed to detect same-byte inode swap: %v", err)
	}
	path := snapshot.dir
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot directory leaked after Close: %v", err)
	}
	if _, ok := snapshot.FileFor(origins[0]); ok {
		t.Fatal("closed snapshot exposed stale path")
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuleSetSnapshotRejectsChangedSourceAndCanceledWorkWithoutLeaks(t *testing.T) {
	source, hash, _ := pinnedRuleSetFixture(t)
	pin, err := PinRuleSet(source, hash)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	root := filepath.Join(t.TempDir(), "core")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StagePinnedRuleSetSnapshot(ctx, root, []*RuleSetPin{pin}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled snapshot unexpectedly published: %v", err)
	}
	if err := os.WriteFile(source, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StagePinnedRuleSetSnapshot(context.Background(), root, []*RuleSetPin{pin}); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("stale pinned original was copied: %v", err)
	}
	parent := filepath.Join(root, "historical-check-snapshots")
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("failed snapshot left files: entries=%v err=%v", entries, err)
	}
}

func TestRuleSetSnapshotDetectsCopyTamperingAndRefusesUnsafeCleanup(t *testing.T) {
	source, hash, _ := pinnedRuleSetFixture(t)
	pin, err := PinRuleSet(source, hash)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	root := filepath.Join(t.TempDir(), "core")
	snapshot, err := StagePinnedRuleSetSnapshot(context.Background(), root, []*RuleSetPin{pin})
	if err != nil {
		t.Fatal(err)
	}
	copyPath, ok := snapshot.FileFor(source)
	if !ok {
		t.Fatal("missing isolated copy")
	}
	if err := os.Chmod(copyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Verify(context.Background()); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("mutated isolated copy still verified: %v", err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatalf("cleanup should remove the same owned inode even when corrupt: %v", err)
	}

	second, err := StagePinnedRuleSetSnapshot(context.Background(), root, []*RuleSetPin{pin})
	if err != nil {
		t.Fatal(err)
	}
	secondPath, _ := second.FileFor(source)
	if err := os.Rename(secondPath, secondPath+".swapped"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte("attacker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("cleanup followed replaced copy: %v", err)
	}
	if data, err := os.ReadFile(secondPath); err != nil || string(data) != "attacker" {
		t.Fatalf("unsafe cleanup modified unexpected file: content=%q err=%v", data, err)
	}
	// Test-directory cleanup is permitted here; the production cleaner must
	// never recursively follow or delete an unrecognized replacement.
}

func TestRuleSetSnapshotRejectsInvalidInputsAndSupportsEmptyClosure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "core")
	empty, err := StagePinnedRuleSetSnapshot(context.Background(), root, nil)
	if err != nil || empty == nil || empty.Verify(context.Background()) != nil ||
		empty.Close() != nil {
		t.Fatalf("empty closure was not a no-op: snapshot=%+v err=%v", empty, err)
	}
	pinPath, hash, _ := pinnedRuleSetFixture(t)
	pin, err := PinRuleSet(pinPath, hash)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if _, err := StagePinnedRuleSetSnapshot(context.Background(), "relative", []*RuleSetPin{pin}); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("relative snapshot root allowed: %v", err)
	}
	many := make([]*RuleSetPin, MaxRuleSetSnapshotFiles+1)
	for i := range many {
		many[i] = pin
	}
	if _, err := StagePinnedRuleSetSnapshot(context.Background(), root, many); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("unbounded descriptor list accepted: %v", err)
	}
	dup, err := StagePinnedRuleSetSnapshot(context.Background(), root, []*RuleSetPin{pin, pin})
	if err != nil {
		t.Fatal(err)
	}
	if len(dup.files) != 1 {
		t.Fatalf("duplicate identical resource not deduplicated: %d", len(dup.files))
	}
	if err := dup.Close(); err != nil {
		t.Fatal(err)
	}
}


func TestRuleSetSnapshotFailureAfterFirstCopyReclaimsPartialScope(t *testing.T) {
	root := filepath.Join(t.TempDir(), "core")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	var pins []*RuleSetPin
	for _, text := range []string{"source-one", "source-two"} {
		data := []byte(text)
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		path, _, err := store.PutRuleSet(context.Background(), bytes.NewReader(data), hash, "binary")
		if err != nil {
			t.Fatal(err)
		}
		pin, err := PinRuleSet(path, hash)
		if err != nil {
			t.Fatal(err)
		}
		pins = append(pins, pin)
		t.Cleanup(func() { _ = pin.Close() })
	}
	// First pin is healthy, but second source changes after pinning.
	// Partial copying must never leave a positive-looking directory behind.
	if err := os.WriteFile(pins[1].path, []byte("altered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StagePinnedRuleSetSnapshot(context.Background(), root, pins); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("partial source change was not rejected: %v", err)
	}
	dirs, err := os.ReadDir(filepath.Join(root, "historical-check-snapshots"))
	if err != nil || len(dirs) != 0 {
		t.Fatalf("partially copied historical rules leaked: entries=%v err=%v", dirs, err)
	}
}

func TestRuleSetSnapshotRejectsUnexpectedEntriesWithoutDeletingThem(t *testing.T) {
	source, hash, _ := pinnedRuleSetFixture(t)
	pin, err := PinRuleSet(source, hash)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	snapshot, err := StagePinnedRuleSetSnapshot(context.Background(),
		filepath.Join(t.TempDir(), "core"), []*RuleSetPin{pin})
	if err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(snapshot.dir, "unknown")
	if err := os.WriteFile(extra, []byte("do not delete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Verify(context.Background()); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("unexpected extra entry accepted: %v", err)
	}
	if err := snapshot.Close(); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("unexpected extra entry was recursively cleaned: %v", err)
	}
	if content, err := os.ReadFile(extra); err != nil || string(content) != "do not delete" {
		t.Fatalf("cleanup touched unrecognized file: %q err=%v", content, err)
	}
}
