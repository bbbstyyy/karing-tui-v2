//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A distinct parent fd must continue to identify the original inode after
// the reservation flock is released. Reopening by the canonical pathname
// would silently fsync a substitute private directory instead.
func TestPinnedInertParentSyncRequiresOriginalDirectoryInode(t *testing.T) {
	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(root, "parent")
			moved := filepath.Join(root, "moved-original")
			foreign := filepath.Join(root, "foreign")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			lock, err := lockSealedArchiveParent(context.Background(), parent)
			if err != nil {
				t.Fatal(err)
			}
			pinned, err := openLockedInertCandidateParentInventoryReader(lock)
			if err != nil {
				t.Fatal(err)
			}
			defer pinned.Close()
			leased, err := lock.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			// The independent fd outlives the short-lived parent flock.
			if err := syncPinnedInertCandidateParent(parent, pinned); err != nil {
				t.Fatalf("intact pinned parent refused: %v", err)
			}
			if err := os.Rename(parent, moved); err != nil {
				t.Fatal(err)
			}
			if replacement == "directory" {
				if err := os.Rename(foreign, parent); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink(foreign, parent); err != nil {
				t.Fatal(err)
			}
			if err := syncPinnedInertCandidateParent(parent, pinned); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("fsync accepted swapped parent: %v", err)
			}
			original, err := os.Lstat(moved)
			if err != nil || !os.SameFile(original, leased) {
				t.Fatalf("lost original directory inode: %v", err)
			}
			atFD, err := pinned.Stat()
			if err != nil || !os.SameFile(atFD, leased) {
				t.Fatalf("pinned fd followed replacement path: %v", err)
			}
			if err := syncPinnedInertCandidateParent(parent, nil); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("nil parent fd authorized sync: %v", err)
			}
		})
	}
}

// Stage releases the parent flock before copying ciphertext. Its second
// durability barrier must target the SAME parent inode, even when a same-UID
// process ignores the flock and replaces the path immediately before sync.
func TestInertStageRefusesReplacedParentAtPostCopySync(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	archiveParent := testSealedDir(t, f)
	source := filepath.Join(archiveParent, "source-pinned-parent.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	sourceContents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			parent := filepath.Join(f.stateRoot, "candidate-parent-"+replacement)
			moved := filepath.Join(f.stateRoot, "moved-candidate-parent-"+replacement)
			foreign := filepath.Join(f.stateRoot, "foreign-candidate-parent-"+replacement)
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, "sentinel"),
				[]byte("untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			injected := false
			var injectedErr error
			candidate, stageErr := stageInertRestoreCandidate(
				context.Background(), source, parent, key,
				func(phase string) bool {
					if phase != "parent_sync" {
						return true
					}
					injected = true
					injectedErr = os.Rename(parent, moved)
					if injectedErr != nil {
						return false
					}
					if replacement == "directory" {
						injectedErr = os.Rename(foreign, parent)
					} else {
						injectedErr = os.Symlink(foreign, parent)
					}
					return injectedErr == nil
				},
			)
			if candidate != nil {
				_ = candidate.Close()
			}
			if !injected || injectedErr != nil || candidate != nil ||
				!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("replaced parent accepted: injected=%t candidate=%t err=%v injectedErr=%v",
					injected, candidate != nil, stageErr, injectedErr)
			}
			entries, err := os.ReadDir(moved)
			if err != nil || len(entries) != 1 || !entries[0].IsDir() ||
				!validInertRestoreCandidateDir(filepath.Join(moved, entries[0].Name())) {
				t.Fatalf("original candidate scope not retained: entries=%v err=%v", entries, err)
			}
			cipher, err := os.ReadFile(filepath.Join(moved, entries[0].Name(), inertRestoreCipherName))
			if err != nil || string(cipher) != string(sourceContents) {
				t.Fatalf("original ciphertext lost after refusal: %v", err)
			}
			foreignSentinel := filepath.Join(foreign, "sentinel")
			if replacement == "directory" {
				foreignSentinel = filepath.Join(parent, "sentinel")
			}
			sentinel, err := os.ReadFile(foreignSentinel)
			if err != nil || string(sentinel) != "untouched" {
				t.Fatalf("foreign replacement data changed: %v", err)
			}
			if restoredSource, err := os.ReadFile(source); err != nil ||
				string(restoredSource) != string(sourceContents) {
				t.Fatalf("authenticated source changed: %v", err)
			}
		})
	}
}
