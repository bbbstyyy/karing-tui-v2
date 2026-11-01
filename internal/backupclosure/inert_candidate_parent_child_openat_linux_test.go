//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Parent flock is advisory. The child must be opened from that parent fd,
// even if an uncooperative same-UID actor substitutes another private parent
// holding a child with the same random name and a conflicting flock.
func TestInertStageChildLeaseAnchoredToParentInode(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	archiveParent := testSealedDir(t, f)
	source := filepath.Join(archiveParent, "source-child-openat.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	moved := filepath.Join(f.stateRoot, "original-parent-inode")
	replacement := filepath.Join(f.stateRoot, "replacement-parent-inode")
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatal(err)
	}
	var replacementLease *os.File
	defer func() {
		if replacementLease != nil {
			_ = replacementLease.Close()
		}
	}()
	var scopeName string
	var injectionErr error
	mutated, acquiredOriginalChild := false, false
	candidate, stageErr := stageInertRestoreCandidate(
		context.Background(), source, parent, key,
		func(phase string) bool {
			if phase == "scope_child_open" && !mutated {
				mutated = true
				entries, err := os.ReadDir(parent)
				if err != nil || len(entries) != 1 {
					injectionErr = ErrUnsafeInertRestoreCandidate
					return false
				}
				scopeName = entries[0].Name()
				foreignChild := filepath.Join(replacement, scopeName)
				if injectionErr = os.Mkdir(foreignChild, 0o700); injectionErr != nil {
					return false
				}
				replacementLease, injectionErr = os.Open(foreignChild)
				if injectionErr != nil {
					return false
				}
				if injectionErr = syscall.Flock(int(replacementLease.Fd()),
					syscall.LOCK_EX|syscall.LOCK_NB); injectionErr != nil {
					return false
				}
				if injectionErr = os.Rename(parent, moved); injectionErr != nil {
					return false
				}
				injectionErr = os.Rename(replacement, parent)
				return injectionErr == nil
			}
			if phase == "scope_child_lock_held" {
				acquiredOriginalChild = true
			}
			return true
		},
	)
	if candidate != nil {
		_ = candidate.Close()
	}
	if injectionErr != nil || !mutated || !acquiredOriginalChild ||
		candidate != nil || !errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("wrong child lease: injected=%t original_locked=%t candidate=%t err=%v injection=%v",
			mutated, acquiredOriginalChild, candidate != nil, stageErr, injectionErr)
	}
	for _, dir := range []string{filepath.Join(moved, scopeName), filepath.Join(parent, scopeName)} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() {
			t.Fatalf("candidate directory lost or replaced: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("unsafe stage wrote data to untrusted scope: %v %v", entries, err)
		}
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source archive changed: %v", err)
	}
	// Test-owned cleanup, not a production guess across replaced paths.
	if err := replacementLease.Close(); err != nil {
		t.Fatal(err)
	}
	replacementLease = nil
	for _, dir := range []string{
		filepath.Join(moved, scopeName), filepath.Join(parent, scopeName), moved, parent,
	} {
		if err := os.Remove(dir); err != nil {
			t.Fatalf("test cleanup failed: %v", err)
		}
	}
}

// Reopen must not adopt an alternate parent containing a byte-for-byte copy
// of a valid candidate merely because it has the same child name, mode and
// full authenticated ciphertext. The original parent fd is authoritative.
func TestInertReopenRefusesForgedParentAfterInventory(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	archiveParent := testSealedDir(t, f)
	source := filepath.Join(archiveParent, "source-reopen-parent.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	candidate, err := StageInertRestoreCandidate(context.Background(), source, parent, key)
	if err != nil {
		t.Fatal(err)
	}
	scope := candidate.Directory()
	cipherPath := filepath.Join(scope, inertRestoreCipherName)
	originalCipher, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}

	foreign := filepath.Join(f.stateRoot, "foreign-reopen-parent")
	moved := filepath.Join(f.stateRoot, "moved-reopen-parent")
	foreignScope := filepath.Join(foreign, filepath.Base(scope))
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(foreignScope, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreignScope, inertRestoreCipherName),
		originalCipher, 0o600); err != nil {
		t.Fatal(err)
	}

	var injectionErr error
	injected := false
	reopened, reopenErr := reopenInertRestoreCandidateAtParentProbed(
		context.Background(), scope, key, func() {
			injected = true
			injectionErr = os.Rename(parent, moved)
			if injectionErr == nil {
				injectionErr = os.Rename(foreign, parent)
			}
		}, nil,
	)
	if reopened != nil {
		_ = reopened.Close()
	}
	if !injected || injectionErr != nil || reopened != nil ||
		!errors.Is(reopenErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("reopened ciphertext under forged parent: injected=%t candidate=%t err=%v injection=%v",
			injected, reopened != nil, reopenErr, injectionErr)
	}
	for _, path := range []string{
		filepath.Join(moved, filepath.Base(scope), inertRestoreCipherName),
		filepath.Join(parent, filepath.Base(scope), inertRestoreCipherName),
		source,
	} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, originalCipher) {
			t.Fatalf("candidate or original ciphertext was modified: %v", err)
		}
	}
	// Neither parent tree was removed by a failed Reopen.
	for _, path := range []string{moved, parent} {
		if info, err := os.Lstat(path); err != nil || !info.IsDir() {
			t.Fatalf("parent disappeared: %v", err)
		}
	}
}
