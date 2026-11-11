//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The candidate child is locked on an inode, not on its mutable pathname.
// Mutating that pathname during the copy boundary must never cause the
// ciphertext to be created in the substitute child or a symlink target.
func TestInertCandidateCipherCopyAnchorsLockedDirectoryFD(t *testing.T) {
	for _, tc := range []struct {
		name        string
		phase       string
		replacement string
	}{
		{"replaced_before_copy", "cipher_copy", "directory"},
		{"symlink_before_copy", "cipher_copy", "symlink"},
		{"replaced_before_openat", "cipher_before_openat", "directory"},
		{"symlink_before_openat", "cipher_before_openat", "symlink"},
		{"replaced_after_openat", "cipher_target_fd_opened", "directory"},
		{"symlink_after_openat", "cipher_target_fd_opened", "symlink"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.commit(t, true)
			closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
			if err != nil {
				t.Fatal(err)
			}
			defer closure.Close()
			sourceParent := testSealedDir(t, f)
			source := filepath.Join(sourceParent, "cipher-anchor.ktbackup")
			key := testSealedKey(t)
			if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
				t.Fatal(err)
			}
			parent := newInertCandidateParent(t, f.stateRoot)
			foreign := filepath.Join(f.stateRoot, "unrelated-private-scope")
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(f.stateRoot, "moved-original-inode")
			var substitute string
			var mutationErr error
			mutated := false
			candidate, err := stageInertRestoreCandidate(
				context.Background(), source, parent, key,
				func(phase string) bool {
					if phase != tc.phase {
						return true
					}
					mutated = true
					entries, readErr := os.ReadDir(parent)
					if readErr != nil || len(entries) != 1 {
						mutationErr = ErrUnsafeInertRestoreCandidate
						return false
					}
					substitute = filepath.Join(parent, entries[0].Name())
					if mutationErr = os.Rename(substitute, moved); mutationErr != nil {
						return false
					}
					if tc.replacement == "symlink" {
						mutationErr = os.Symlink(foreign, substitute)
					} else {
						mutationErr = os.Mkdir(substitute, 0o700)
					}
					return mutationErr == nil
				},
			)
			if candidate != nil {
				_ = candidate.Close()
			}
			if !mutated || mutationErr != nil || candidate != nil ||
				!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("path swap accepted: injected=%t candidate=%t err=%v mutationErr=%v",
					mutated, candidate != nil, err, mutationErr)
			}
			foreignEntries, err := os.ReadDir(foreign)
			if err != nil || len(foreignEntries) != 0 {
				t.Fatalf("ciphertext written to foreign private scope: entries=%d err=%v",
					len(foreignEntries), err)
			}
			if tc.replacement == "symlink" {
				link, err := os.Lstat(substitute)
				if err != nil || link.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("untrusted symlink unexpectedly deleted: %v", err)
				}
			} else {
				replacementEntries, err := os.ReadDir(substitute)
				if err != nil || len(replacementEntries) != 0 {
					t.Fatalf("ciphertext written to swapped child: entries=%d err=%v",
						len(replacementEntries), err)
				}
			}
			// Any ciphertext in moved was created under the original locked
			// inode and is test-owned. The Stage cleanup must not traverse
			// or delete the substitute path or the unrelated private scope.
			movedEntries, err := os.ReadDir(moved)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range movedEntries {
				if entry.Name() != inertRestoreCipherName || !entry.Type().IsRegular() {
					t.Fatalf("unrecognized file in test-owned original scope: %s", entry.Name())
				}
				if err := os.Remove(filepath.Join(moved, entry.Name())); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(substitute); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(foreign); err != nil {
				t.Fatal(err)
			}
			if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
				t.Fatalf("admission left foreign scope inside parent: count=%d err=%v",
					len(entries), err)
			}
			if _, err := os.Stat(source); err != nil {
				t.Fatalf("cipher copy refusal damaged authenticated source: %v", err)
			}
		})
	}
}

func TestInertCandidateCipherOpenatFaultRefusesWithoutRetry(t *testing.T) {
	// This new checkpoint cannot manufacture restore authority or attempt
	// an unguarded alternate pathname-based file open.
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sourceParent := testSealedDir(t, f)
	source := filepath.Join(sourceParent, "cipher-stage-fault.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	seen := 0
	result, err := stageInertRestoreCandidate(
		context.Background(), source, parent, key,
		func(phase string) bool {
			if phase == "cipher_before_openat" {
				seen++
				return false
			}
			return true
		},
	)
	if result != nil || !errors.Is(err, ErrUnsafeInertRestoreCandidate) || seen != 1 {
		t.Fatalf("cipher open interruption allowed candidate: candidate=%t err=%v seen=%d",
			result != nil, err, seen)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("cipher open refusal retained candidate scope: count=%d err=%v",
			len(entries), err)
	}
}
