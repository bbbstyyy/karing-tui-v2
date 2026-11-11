//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A same-UID process can ignore an advisory flock and rename the parent
// after the Stage inventory, before the new scope is created. Mkdirat must
// create under the old leased parent, never inside the replacement. Stage
// must then refuse adoption rather than deleting any foreign path.
func TestInertStageMkdiratAnchorsLeasedParentAcrossPathReplacement(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sourceParent := testSealedDir(t, f)
	source := filepath.Join(sourceParent, "parent-mkdirat-source.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}

	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			parent := filepath.Join(f.stateRoot, "candidate-parent-"+replacement)
			moved := filepath.Join(f.stateRoot, "moved-parent-"+replacement)
			foreign := filepath.Join(f.stateRoot, "foreign-parent-"+replacement)
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}

			injected := false
			var mutationErr error
			candidate, stageErr := stageInertRestoreCandidate(
				context.Background(), source, parent, key,
				func(phase string) bool {
					if phase != "scope_before_mkdirat" {
						return true
					}
					injected = true
					mutationErr = os.Rename(parent, moved)
					if mutationErr != nil {
						return false
					}
					if replacement == "directory" {
						mutationErr = os.Mkdir(parent, 0o700)
					} else {
						mutationErr = os.Symlink(foreign, parent)
					}
					return mutationErr == nil
				},
			)
			if candidate != nil {
				_ = candidate.Close()
			}
			if !injected || mutationErr != nil || candidate != nil ||
				!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("swapped parent adopted: injected=%t candidate=%t err=%v mutation=%v",
					injected, candidate != nil, stageErr, mutationErr)
			}

			originalEntries, err := os.ReadDir(moved)
			if err != nil || len(originalEntries) != 1 ||
				!strings.HasPrefix(originalEntries[0].Name(), inertRestoreCandidatePrefix) ||
				!originalEntries[0].IsDir() {
				t.Fatalf("mkdirat did not create only in leased parent: entries=%v err=%v",
					originalEntries, err)
			}
			scope := filepath.Join(moved, originalEntries[0].Name())
			if entries, err := os.ReadDir(scope); err != nil || len(entries) != 0 {
				t.Fatalf("refused candidate contains data: entries=%v err=%v", entries, err)
			}
			// No file or directory was created inside the unrelated
			// replacement, even though the old pathname looked valid.
			if entries, err := os.ReadDir(foreign); err != nil || len(entries) != 0 {
				t.Fatalf("foreign directory modified: entries=%v err=%v", entries, err)
			}
			if replacement == "directory" {
				if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
					t.Fatalf("replacement parent modified: entries=%v err=%v", entries, err)
				}
			} else if info, err := os.Lstat(parent); err != nil ||
				info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("foreign symlink changed: %v", err)
			}
			if _, err := os.Stat(source); err != nil {
				t.Fatalf("source archive lost: %v", err)
			}
			// The test owner deliberately cleans the moved empty scope:
			// production must never guess which changed pathname to unlink.
			for _, path := range []string{scope, moved, parent, foreign} {
				if err := os.Remove(path); err != nil {
					t.Fatalf("test cleanup %s: %v", filepath.Base(path), err)
				}
			}
		})
	}
}

// The lower-level creator also returns a child identity from the parent
// dirfd, not from whichever object the original pathname now resolves to.
func TestInertMkdiratIdentityFromLeasedParentFD(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	moved := filepath.Join(root, "moved")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	createdPath, identity, err := createInertScopeAtLeasedParent(lock, parent)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.Lstat(filepath.Join(moved, filepath.Base(createdPath)))
	if err != nil || !os.SameFile(actual, identity) {
		t.Fatalf("new child identity did not belong to locked parent: %v", err)
	}
	if sameInertCandidateParentLease(parent, lock) ||
		sameNewInertScopeIdentity(createdPath, identity) {
		t.Fatal("replaced canonical parent incorrectly passed inode validation")
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("foreign directory received mkdirat child: %v %v", entries, err)
	}
}
