//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func stageTargetCustodyFixture(t *testing.T) (root, source, parent string, key [32]byte, ciphertext []byte) {
	t.Helper()
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closure.Close() })
	source = filepath.Join(testSealedDir(t, f), "stage-target-custody-source.ktbackup")
	key = testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	ciphertext, err = os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	return f.stateRoot, source, newInertCandidateParent(t, f.stateRoot), key, ciphertext
}

func singleStageCandidateScope(t *testing.T, parent string) string {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		t.Fatalf("expected one encrypted candidate scope: entries=%v err=%v", entries, err)
	}
	return filepath.Join(parent, entries[0].Name())
}

// The source and candidate both contain completely valid identical sealed
// ciphertext. A replacement file inode in the ORIGINAL locked candidate
// directory must never become Stage's final HMAC source, nor be unlinked
// during failed-Stage cleanup.
func TestStageFinalPreflightAndCleanupRejectForeignSameContentTarget(t *testing.T) {
	root, source, candidateParent, key, ciphertext := stageTargetCustodyFixture(t)
	alternate := filepath.Join(root, "foreign-stage-final-cipher.ktbackup")
	moved := filepath.Join(root, "original-stage-final-cipher.ktbackup")
	sentinel := filepath.Join(root, "foreign-stage-sentinel")
	if err := os.WriteFile(alternate, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	foreignInfo, err := os.Lstat(alternate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	var scope string
	var originalInfo os.FileInfo
	injected := false
	var mutationErr error
	candidate, stageErr := stageInertRestoreCandidate(
		context.Background(), source, candidateParent, key,
		func(stage string) bool {
			if stage != "candidate_revalidation" {
				return true
			}
			injected = true
			scopeEntries, err := os.ReadDir(candidateParent)
			if err != nil || len(scopeEntries) != 1 || !scopeEntries[0].IsDir() {
				mutationErr = ErrUnsafeInertRestoreCandidate
				return true
			}
			scope = filepath.Join(candidateParent, scopeEntries[0].Name())
			archive := filepath.Join(scope, inertRestoreCipherName)
			originalInfo, mutationErr = os.Lstat(archive)
			if mutationErr != nil {
				return true
			}
			if mutationErr = os.Rename(archive, moved); mutationErr != nil {
				return true
			}
			mutationErr = os.Rename(alternate, archive)
			return true
		})
	if candidate != nil {
		_ = candidate.Close()
	}
	if !injected || mutationErr != nil || candidate != nil ||
		!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Stage accepted or deleted same-content replacement: injected=%t mutation=%v result=%v err=%v",
			injected, mutationErr, candidate, stageErr)
	}
	if scope == "" {
		t.Fatal("injected candidate scope was not recorded")
	}
	current := filepath.Join(scope, inertRestoreCipherName)
	currentInfo, err := os.Lstat(current)
	if err != nil || !os.SameFile(foreignInfo, currentInfo) ||
		os.SameFile(originalInfo, currentInfo) {
		t.Fatalf("failed Stage deleted or replaced foreign ciphertext inode: %v", err)
	}
	retained, err := os.Lstat(moved)
	if err != nil || !os.SameFile(originalInfo, retained) {
		t.Fatalf("failed Stage deleted its original target: %v", err)
	}
	for _, path := range []string{source, current, moved} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, ciphertext) {
			t.Fatalf("Stage modified valid encrypted ciphertext at %q: %v", filepath.Base(path), err)
		}
	}
	sentinelBytes, err := os.ReadFile(sentinel)
	if err != nil || string(sentinelBytes) != "untouched" {
		t.Fatalf("foreign sentinel was modified: %v", err)
	}
	// The substituted archive itself is well-formed and authenticated.
	// Rejecting it is due to Stage target inode custody, not hash mismatch.
	independent, err := PreflightInertArchive(context.Background(), current, key, nil)
	if err != nil || !independent.SQLiteLogicalVerified ||
		independent.RestoreReady || independent.RestoreSupported {
		t.Fatalf("foreign ciphertext was not a valid archive: %+v %v", independent, err)
	}
}

// Before O_EXCL creates Stage's first ciphertext inode, ANY same-name file
// in the otherwise empty scope belongs to someone else, even if its bytes
// and owner/mode would satisfy a normal candidate inspection.
func TestStageCleanupDoesNotUnlinkFilePlacedBeforeTargetOpen(t *testing.T) {
	root, source, candidateParent, key, ciphertext := stageTargetCustodyFixture(t)
	_ = root
	var foreignScope string
	injected := false
	var mutationErr error
	candidate, stageErr := stageInertRestoreCandidate(
		context.Background(), source, candidateParent, key,
		func(stage string) bool {
			if stage != "cipher_before_openat" {
				return true
			}
			injected = true
			scopeEntries, err := os.ReadDir(candidateParent)
			if err != nil || len(scopeEntries) != 1 || !scopeEntries[0].IsDir() {
				mutationErr = ErrUnsafeInertRestoreCandidate
				return true
			}
			foreignScope = filepath.Join(candidateParent, scopeEntries[0].Name())
			mutationErr = os.WriteFile(
				filepath.Join(foreignScope, inertRestoreCipherName), ciphertext, 0o600)
			return true // Let production O_EXCL reject the foreign file.
		})
	if candidate != nil {
		_ = candidate.Close()
	}
	if !injected || mutationErr != nil || candidate != nil ||
		!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Stage failed to refuse existing foreign target: injected=%t mutation=%v err=%v",
			injected, mutationErr, stageErr)
	}
	if foreignScope == "" {
		t.Fatal("foreign candidate path not captured")
	}
	got, err := os.ReadFile(filepath.Join(foreignScope, inertRestoreCipherName))
	if err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatalf("failed Stage unlinked a foreign file it never created: %v", err)
	}
	// A foreign scope cannot be removed just because Stage's creation failed.
	if info, err := os.Stat(foreignScope); err != nil || !info.IsDir() {
		t.Fatalf("failed Stage unlinked foreign candidate scope: %v", err)
	}
}

// Failed Stage can still clean up exactly the owned partial ciphertext it
// created and the now-empty scope. This preserves ordinary fail-closed
// behavior without reverting to deleting unknown same-name file inodes.
func TestStageCleanupReclaimsOwnedPartialCiphertextAfterOpen(t *testing.T) {
	_, source, candidateParent, key, _ := stageTargetCustodyFixture(t)
	injected := false
	candidate, stageErr := stageInertRestoreCandidate(
		context.Background(), source, candidateParent, key,
		func(stage string) bool {
			if stage == "cipher_target_fd_opened" {
				injected = true
				return false
			}
			return true
		})
	if candidate != nil {
		_ = candidate.Close()
	}
	if !injected || candidate != nil ||
		!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Stage unexpectedly accepted partial target: injected=%t err=%v",
			injected, stageErr)
	}
	if entries, err := os.ReadDir(candidateParent); err != nil || len(entries) != 0 {
		t.Fatalf("owned partial ciphertext or scope leaked: entries=%v err=%v", entries, err)
	}
}

// Healthy encrypted Stage/Verify/Reopen is unchanged; successful Stage
// holds the write-only O_EXCL target fd through final full preflight and
// closes it when custody is handed off as an inert candidate.
func TestStageTargetRetainedFileHealthyLifecycle(t *testing.T) {
	_, source, candidateParent, key, ciphertext := stageTargetCustodyFixture(t)
	candidate, err := StageInertRestoreCandidate(context.Background(), source, candidateParent, key)
	if err != nil {
		t.Fatalf("healthy Stage refused retained target: %v", err)
	}
	defer candidate.Close()
	if report, err := candidate.Verify(context.Background(), key); err != nil ||
		!report.SQLiteLogicalVerified || report.RestoreReady || report.RestoreSupported {
		t.Fatalf("healthy retained candidate failed full Verify: %+v %v", report, err)
	}
	got, err := os.ReadFile(candidate.archive)
	if err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatalf("healthy Stage target ciphertext changed: %v", err)
	}
	directory := candidate.Directory()
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := ReopenInertRestoreCandidate(context.Background(), directory, key)
	if err != nil {
		t.Fatalf("healthy candidate Reopen refused: %v", err)
	}
	defer reopened.Close()
	if report, err := reopened.Verify(context.Background(), key); err != nil ||
		!report.SQLiteLogicalVerified || report.RestoreReady || report.RestoreSupported {
		t.Fatalf("healthy candidate Verify after Reopen refused: %+v %v", report, err)
	}
}
