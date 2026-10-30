//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// An advisory flock does not stop a same-UID actor from renaming a pathname.
// The child fd must refer to the directory made by this Stage invocation,
// and a failure must not delete a newly substituted directory or symlink.
func TestInertRestoreStageRefusesReplacedFreshScopeWithoutDeletingReplacement(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sealedParent := testSealedDir(t, f)
	source := filepath.Join(sealedParent, "source.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)

	for _, tc := range []struct {
		name string
		phase string
		replacement string
		continueAfterMutation bool
	}{
		{"post_create_replacement", "scope_created", "directory", true},
		{"post_create_denied", "scope_created", "directory", false},
		{"pre_child_open_replacement", "scope_child_open", "directory", true},
		{"post_child_flock_replacement", "scope_child_lock_held", "directory", true},
		{"pre_child_open_symlink", "scope_child_open", "symlink", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			moved := filepath.Join(f.stateRoot, tc.name+"-original")
			var mutationErr error
			var original os.FileInfo
			var replacedPath string
			injected := false
			candidate, stageErr := stageInertRestoreCandidate(
				context.Background(), source, parent, key,
				func(phase string) bool {
					if phase != tc.phase {
						return true
					}
					injected = true
					entries, err := os.ReadDir(parent)
					if err != nil || len(entries) != 1 {
						mutationErr = ErrUnsafeInertRestoreCandidate
						return false
					}
					replacedPath = filepath.Join(parent, entries[0].Name())
					original, mutationErr = os.Lstat(replacedPath)
					if mutationErr != nil {
						return false
					}
					if mutationErr = os.Rename(replacedPath, moved); mutationErr != nil {
						return false
					}
					if tc.replacement == "symlink" {
						mutationErr = os.Symlink(moved, replacedPath)
					} else {
						mutationErr = os.Mkdir(replacedPath, 0o700)
					}
					return mutationErr == nil && tc.continueAfterMutation
				},
			)
			if candidate != nil {
				_ = candidate.Close()
			}
			if mutationErr != nil || !injected ||
				candidate != nil || !errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("replaced candidate adopted: injected=%t candidate=%t stageErr=%v mutationErr=%v",
					injected, candidate != nil, stageErr, mutationErr)
			}
			atMoved, movedErr := os.Lstat(moved)
			atReplacement, replacementErr := os.Lstat(replacedPath)
			if movedErr != nil || replacementErr != nil ||
				!os.SameFile(original, atMoved) ||
				os.SameFile(original, atReplacement) {
				t.Fatalf("stage removed or adopted a substituted inode: movedErr=%v replacementErr=%v",
					movedErr, replacementErr)
			}
			if tc.replacement == "symlink" && atReplacement.Mode()&os.ModeSymlink == 0 {
				t.Fatal("untrusted symlink was replaced or removed")
			}
			// Cleanup is deliberately performed by the test owner, not by
			// Stage. This proves Stage did not delete a foreign path.
			if err := os.Remove(replacedPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(moved); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("test-owned scope cleanup failed: count=%d err=%v", len(entries), err)
			}
			if _, err := os.Stat(source); err != nil {
				t.Fatalf("candidate refusal deleted source ciphertext: %v", err)
			}
		})
	}
}

func TestInertNewScopeCleanupRequiresOriginalInode(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path, err := os.MkdirTemp(parent, inertRestoreCandidatePrefix)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !sameNewInertScopeIdentity(path, original) {
		t.Fatal("original private candidate inode not recognized")
	}
	moved := filepath.Join(parent, "moved-original")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeNewEmptyInertScopeIfIdentical(path, original); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("foreign inode was eligible for deletion: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("foreign inode was deleted: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, path); err != nil {
		t.Fatal(err)
	}
	if err := removeNewEmptyInertScopeIfIdentical(path, original); err != nil {
		t.Fatalf("owned empty inode was not removed: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned empty scope survived guarded deletion: %v", err)
	}
}
