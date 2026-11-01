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

// A Discard must pin the parent inode before it removes even the encrypted
// leaf. The original child lease alone does not identify the parent in
// which the final directory entry should be removed.
func TestInertDiscardPinsOriginalParentFD(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "parent")
	moved := filepath.Join(root, "moved")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := openInertCandidateParentForDiscard(parent, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := openInertCandidateParentForDiscard(parent, identity);
		!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("opened foreign parent for unlink: %v", err)
	}
	opened, err := pinned.Stat()
	if err != nil || !os.SameFile(opened, identity) {
		t.Fatalf("pinned dirfd changed identity: %v", err)
	}
	foreign, err := os.Lstat(parent)
	if err != nil || os.SameFile(opened, foreign) {
		t.Fatalf("pinned fd followed replacement: %v", err)
	}
}

func TestInertDiscardRejectsParentSwapBeforeDirectoryUnlink(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sealedParent := testSealedDir(t, f)
	source := filepath.Join(sealedParent, "source-discard-parent.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	sourceBytes, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}

	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			parent := filepath.Join(f.stateRoot, "discard-parent-"+replacement)
			moved := filepath.Join(f.stateRoot, "discard-moved-"+replacement)
			foreign := filepath.Join(f.stateRoot, "discard-foreign-"+replacement)
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			candidate, err := StageInertRestoreCandidate(
				context.Background(), source, parent, key)
			if err != nil {
				t.Fatal(err)
			}
			defer candidate.Close()
			scope := candidate.Directory()
			name := filepath.Base(scope)
			created, err := os.ReadFile(filepath.Join(scope, inertRestoreCipherName))
			if err != nil || !bytes.Equal(created, sourceBytes) {
				t.Fatalf("invalid initial encrypted candidate: %v", err)
			}
			mutated := false
			var mutationErr error
			candidate.mu.Lock()
			discardErr := candidate.discardLockedProbed(true, func() {
				mutated = true
				mutationErr = os.Rename(parent, moved)
				if mutationErr != nil {
					return
				}
				// A forged parent contains an EMPTY same-name child,
				// deliberately making path-based os.Remove succeed.
				if replacement == "directory" {
					mutationErr = os.Rename(foreign, parent)
				} else {
					mutationErr = os.Symlink(foreign, parent)
				}
				if mutationErr != nil {
					return
				}
				mutationErr = os.Mkdir(filepath.Join(foreign, name), 0o700)
				if replacement == "directory" {
					mutationErr = os.Mkdir(filepath.Join(parent, name), 0o700)
				}
				if mutationErr != nil {
					return
				}
				sentinelPath := filepath.Join(foreign, "sentinel")
				if replacement == "directory" {
					sentinelPath = filepath.Join(parent, "sentinel")
				}
				mutationErr = os.WriteFile(sentinelPath, []byte("intact"), 0o600)
			})
			candidate.mu.Unlock()
			if !mutated || mutationErr != nil ||
				!errors.Is(discardErr, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("foreign scope removed: injected=%t mutation=%v err=%v",
					mutated, mutationErr, discardErr)
			}

			// Discard already unlinked only the authenticated ciphertext
			// within the ORIGINAL child directory before the injection.
			// A failed final step must not remove any foreign directory.
			atMoved := filepath.Join(moved, name)
			entries, err := os.ReadDir(atMoved)
			if err != nil || len(entries) != 0 {
				t.Fatalf("original child was removed or mutated: entries=%v err=%v", entries, err)
			}
			foreignScope := filepath.Join(foreign, name)
			foreignSentinel := filepath.Join(foreign, "sentinel")
			if replacement == "directory" {
				foreignScope = filepath.Join(parent, name)
				foreignSentinel = filepath.Join(parent, "sentinel")
			}
			if info, err := os.Lstat(foreignScope); err != nil || !info.IsDir() {
				t.Fatalf("deleted replacement same-name empty scope: %v", err)
			}
			if sentinel, err := os.ReadFile(foreignSentinel); err != nil ||
				string(sentinel) != "intact" {
				t.Fatalf("changed foreign parent sentinel: %v", err)
			}
			if actual, err := os.ReadFile(source); err != nil ||
				!bytes.Equal(actual, sourceBytes) {
				t.Fatalf("source encrypted archive modified: %v", err)
			}
		})
	}
}

// The legitimate internal Discard path still deletes exactly its own
// authenticated candidate, without removing the independent source archive.
func TestInertDiscardParentFDNormalPath(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sealedParent := testSealedDir(t, f)
	source := filepath.Join(sealedParent, "source-discard-normal.ktbackup")
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
	if err := candidate.Discard(context.Background()); err != nil {
		t.Fatalf("normal Discard failed: %v", err)
	}
	if _, err := os.Lstat(scope); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("normal Discard retained scope: %v", err)
	}
	if _, err := os.Lstat(source); err != nil {
		t.Fatalf("normal Discard deleted source archive: %v", err)
	}
}
