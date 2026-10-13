//go:build linux

package coreartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fakeCorePinFixture(t *testing.T) (*CorePin, string, []byte) {
	t.Helper()
	content := []byte("#!/bin/sh\necho controlled test core\n")
	root := t.TempDir()
	path := filepath.Join(root, "core")
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(content)
	p, err := pinCoreExpected(context.Background(), path, hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	p.arch = "amd64" // unit-only fixture; production uses runtime.GOARCH
	t.Cleanup(func() { _ = p.Close() })
	return p, path, content
}

func TestApprovedCorePinRefusesSyntheticCore(t *testing.T) {
	_, path, _ := fakeCorePinFixture(t)
	if pin, err := PinApprovedCore(context.Background(), path); pin != nil || !errors.Is(err, ErrCorePinChanged) {
		t.Fatalf("unapproved fixture admitted: %+v err=%v", pin, err)
	}
}

func TestCoreCopyIsIndependentAndNeverExecutable(t *testing.T) {
	pin, original, payload := fakeCorePinFixture(t)
	root := filepath.Join(t.TempDir(), "private-core")
	snap, err := StagePinnedRuleSetSnapshotWithCore(context.Background(), root, nil, pin)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	copyPath, ok := snap.CoreFile()
	if !ok || copyPath == "" {
		t.Fatal("missing snapshot core")
	}
	src, err := os.Lstat(original)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := os.Lstat(copyPath)
	if err != nil || os.SameFile(src, dst) || dst.Mode().Perm() != 0o400 {
		t.Fatalf("private core not independent / non-executable: %v %v", dst, err)
	}
	if err := snap.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Same-byte pathname replacement must not change the existing copy,
	// and MUST invalidate the original held descriptor.
	displaced := original + ".old"
	if err := os.Rename(original, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(original, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pin.Reverify(context.Background()); !errors.Is(err, ErrCorePinChanged) {
		t.Fatalf("same-content inode replacement not detected: %v", err)
	}
	if err := snap.Verify(context.Background()); err != nil {
		t.Fatalf("independent copy changed with original: %v", err)
	}
	if err := snap.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(copyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ephemeral core was not removed: %v", err)
	}
}

func TestCoreCopyTamperingFailsClosed(t *testing.T) {
	pin, _, _ := fakeCorePinFixture(t)
	snap, err := StagePinnedRuleSetSnapshotWithCore(context.Background(), filepath.Join(t.TempDir(), "core"), nil, pin)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	copyPath, ok := snap.CoreFile()
	if !ok {
		t.Fatal("missing core copy")
	}
	if err := os.Chmod(copyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("mutated core"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snap.Verify(context.Background()); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("mutated copy verified: %v", err)
	}
}

func TestCorePinRejectsSymlinksHardlinksPermissionsAndOversize(t *testing.T) {
	pin, path, _ := fakeCorePinFixture(t)
	hardlink := filepath.Join(t.TempDir(), "hardlink")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if err := pin.Reverify(context.Background()); !errors.Is(err, ErrUnsafeArtifact) {
		t.Fatalf("hardlinked source accepted: %v", err)
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if p, err := pinCoreExpected(context.Background(), link, pin.expected); p != nil || !errors.Is(err, ErrUnsafeArtifact) {
		t.Fatalf("symlink admitted: %v", err)
	}
	if err := os.Chmod(path, 0o722); err != nil {
		t.Fatal(err)
	}
	if err := pin.Reverify(context.Background()); !errors.Is(err, ErrUnsafeArtifact) {
		t.Fatalf("world writable source admitted: %v", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, MaxPinnedCoreBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := pin.Reverify(context.Background()); !errors.Is(err, ErrUnsafeArtifact) {
		t.Fatalf("oversized source admitted: %v", err)
	}
}

func TestOrphanScavengerRecognizesOnlyBoundedCoreCopy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "core")
	parent := filepath.Join(root, "historical-check-snapshots")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	pin, _, data := fakeCorePinFixture(t)
	orphan := filepath.Join(parent, ".check-copiedcore")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(orphan, "core-"+pin.expected+".bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), root)
	if err != nil || report.Reclaimed != 1 || report.Active != 0 {
		t.Fatalf("bounded orphan core was not removed: %+v err=%v", report, err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphan persisted")
	}
	unsafe := filepath.Join(parent, ".check-unsafecore")
	if err := os.Mkdir(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unsafe, "core-UNKNOWN.bin"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReclaimOrphanedRuleSetSnapshots(context.Background(), root); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("unexpected executable name accepted: %v", err)
	}
	if _, err := os.Lstat(unsafe); err != nil {
		t.Fatalf("unsafe orphan erased: %v", err)
	}
}

func TestCoreCopyCancellationAndNilPin(t *testing.T) {
	coreRoot := filepath.Join(t.TempDir(), "core")
	if _, err := StagePinnedRuleSetSnapshotWithCore(context.Background(), coreRoot, nil, nil); !errors.Is(err, ErrUnsafeRuleSetSnapshot) {
		t.Fatalf("nil approved core admitted: %v", err)
	}
	pin, _, _ := fakeCorePinFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StagePinnedRuleSetSnapshotWithCore(ctx, coreRoot, nil, pin); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled core copy admitted: %v", err)
	}
}
