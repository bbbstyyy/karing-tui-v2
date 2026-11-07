//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func hasInertPhase(phases []string, expected string) bool {
	for _, phase := range phases {
		if phase == expected {
			return true
		}
	}
	return false
}

func singleCreatedScopeAtParent(parent string) (string, error) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return "", err
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return "", ErrUnsafeInertRestoreCandidate
	}
	return filepath.Join(parent, entries[0].Name()), nil
}

// After creation fstatat captures the original (dev, ino) pair, another
// private 0700 directory can have the SAME name, mode and owner. Opening it
// must not create a receipt for an inode that our mkdirat did not verify.
func TestScopeCreationRefusesPrivateDirectorySwapAfterInodeReceipt(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	parentLock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer parentLock.Close()
	var injected bool
	var originalPath, replacedPath string
	var mutationErr error
	var phases []string
	path, created, createErr := createInertScopeAtLeasedParentProbed(
		parentLock, parent, func(phase string) bool {
			phases = append(phases, phase)
			if phase != "scope_created_inode_receipt" {
				return true
			}
			injected = true
			var pathErr error
			replacedPath, pathErr = singleCreatedScopeAtParent(parent)
			if pathErr != nil {
				mutationErr = pathErr
				return true
			}
			originalPath = filepath.Join(parent, "original-created-inode")
			mutationErr = os.Rename(replacedPath, originalPath)
			if mutationErr != nil {
				return true
			}
			mutationErr = os.Mkdir(replacedPath, 0o700)
			if mutationErr != nil {
				return true
			}
			mutationErr = os.WriteFile(
				filepath.Join(replacedPath, "foreign-sentinel"), []byte("keep"), 0o600)
			return true
		})
	if !injected || mutationErr != nil || createErr == nil ||
		!errors.Is(createErr, ErrUnsafeInertRestoreCandidate) ||
		path != "" || created != nil || !hasInertPhase(phases, "scope_created_inode_changed") {
		t.Fatalf("created scope adopted same-name foreign inode: injected=%t mutation=%v err=%v receipt=%v phases=%v",
			injected, mutationErr, createErr, created, phases)
	}
	original, err := os.Lstat(originalPath)
	if err != nil || !original.IsDir() || original.Mode().Perm() != 0o700 {
		t.Fatalf("original created scope modified: %v", err)
	}
	replacement, err := os.Lstat(replacedPath)
	if err != nil || !replacement.IsDir() || replacement.Mode().Perm() != 0o700 ||
		os.SameFile(original, replacement) {
		t.Fatalf("foreign private replacement modified or reused same inode: %v", err)
	}
	foreignBytes, err := os.ReadFile(filepath.Join(replacedPath, "foreign-sentinel"))
	if err != nil || string(foreignBytes) != "keep" {
		t.Fatalf("foreign sentinel changed: %v", err)
	}
	if !sameInertCandidateParentLease(parent, parentLock) {
		t.Fatal("creation refusal closed or redirected original parent flock")
	}
}

// Missing child between mkdirat and its first Fstatat must be reported with
// a fixed, secret-free probe label, not as the undifferentiated create_scope.
func TestScopeCreationMissingAfterMkdiratReportsBoundedPhase(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	parentLock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer parentLock.Close()
	var mutationErr error
	var phases []string
	var injected bool
	path, created, createErr := createInertScopeAtLeasedParentProbed(
		parentLock, parent, func(phase string) bool {
			phases = append(phases, phase)
			if phase == "scope_mkdirat_created" {
				injected = true
				var child string
				child, mutationErr = singleCreatedScopeAtParent(parent)
				if mutationErr == nil {
					mutationErr = os.Remove(child)
				}
			}
			return true
		})
	if !injected || mutationErr != nil ||
		!errors.Is(createErr, ErrUnsafeInertRestoreCandidate) ||
		path != "" || created != nil ||
		!hasInertPhase(phases, "scope_created_fstatat_failed_missing_path") {
		t.Fatalf("missing created child did not fail with safe phase: injected=%t mutation=%v err=%v phases=%v",
			injected, mutationErr, createErr, phases)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("fault-injected missing child left scope entries: %v %v", entries, err)
	}
	if !sameInertCandidateParentLease(parent, parentLock) {
		t.Fatal("missing-child refusal closed original parent lease")
	}
}

// This exercises the actual Stage call into the creation helper, not just
// its direct test entrypoint. Stage must propagate the bounded diagnostic,
// refuse to adopt foreign 0700 inode and preserve both directories.
func TestStageScopeCreationRejectsReplacedInodeWithPrivateDiagnostic(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	source := filepath.Join(testSealedDir(t, f), "create-receipt-source.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	var injected bool
	var originalPath, replacementPath string
	var mutationErr error
	var phases []string
	candidate, stageErr := stageInertRestoreCandidate(
		context.Background(), source, parent, key, func(phase string) bool {
			phases = append(phases, phase)
			if phase != "scope_created_inode_receipt" {
				return true
			}
			injected = true
			replacementPath, mutationErr = singleCreatedScopeAtParent(parent)
			if mutationErr != nil {
				return true
			}
			originalPath = filepath.Join(f.stateRoot, "original-stage-created-scope")
			mutationErr = os.Rename(replacementPath, originalPath)
			if mutationErr != nil {
				return true
			}
			mutationErr = os.Mkdir(replacementPath, 0o700)
			if mutationErr != nil {
				return true
			}
			mutationErr = os.WriteFile(
				filepath.Join(replacementPath, "foreign-sentinel"), []byte("keep"), 0o600)
			return true
		})
	if candidate != nil {
		_ = candidate.Close()
	}
	if !injected || mutationErr != nil || candidate != nil ||
		!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) ||
		!hasInertPhase(phases, "scope_created_inode_changed") {
		t.Fatalf("Stage adopted foreign scope: injected=%t mutation=%v err=%v phases=%v",
			injected, mutationErr, stageErr, phases)
	}
	oldInfo, err := os.Lstat(originalPath)
	if err != nil || !oldInfo.IsDir() {
		t.Fatalf("original private scope lost: %v", err)
	}
	newInfo, err := os.Lstat(replacementPath)
	if err != nil || !newInfo.IsDir() || os.SameFile(oldInfo, newInfo) {
		t.Fatalf("foreign private scope unlinked/adopted: %v", err)
	}
	sentinel, err := os.ReadFile(filepath.Join(replacementPath, "foreign-sentinel"))
	if err != nil || string(sentinel) != "keep" {
		t.Fatalf("Stage modified foreign scope contents: %v", err)
	}
}
