//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The inspection must pin the original locked child when a same-UID actor
// changes its pathname after ReadDir but before the ciphertext file opens.
func TestInertCandidateInspectionDoesNotReadReplacedDirectory(t *testing.T) {
	for _, replacement := range []string{"private_directory", "symlink_to_private"} {
		t.Run(replacement, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			scope, err := os.MkdirTemp(parent, inertRestoreCandidatePrefix)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(scope, inertRestoreCipherName),
				[]byte("original-synthetic-ciphertext"), 0o600); err != nil {
				t.Fatal(err)
			}
			locked, err := openLockedInertRestoreCandidate(scope)
			if err != nil {
				t.Fatal(err)
			}
			defer locked.Close()
			baseline, err := inspectInertCandidateFile(locked, false)
			if err != nil || baseline == nil {
				t.Fatalf("healthy locked inspection rejected: %v", err)
			}
			foreign := filepath.Join(parent, "foreign-private-dir")
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, inertRestoreCipherName),
				[]byte("foreign-synthetic-ciphertext"), 0o600); err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(parent, "original-moved")
			var swapErr error
			swapped := false
			info, err := inspectInertCandidateFileProbed(locked, false, func() bool {
				swapped = true
				if swapErr = os.Rename(scope, moved); swapErr != nil {
					return false
				}
				if replacement == "private_directory" {
					swapErr = os.Rename(foreign, scope)
				} else {
					swapErr = os.Symlink(foreign, scope)
				}
				return swapErr == nil
			})
			if !swapped || swapErr != nil || info != nil ||
				!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("substituted ciphertext inspection accepted: swapped=%t info=%t err=%v swapErr=%v",
					swapped, info != nil, err, swapErr)
			}
			atMoved, err := os.Lstat(moved)
			if err != nil || !os.SameFile(locked.directoryIdentity, atMoved) {
				t.Fatalf("original locked inode changed: %v", err)
			}
			atPath, err := os.Lstat(scope)
			if err != nil || os.SameFile(locked.directoryIdentity, atPath) {
				t.Fatalf("foreign replacement disappeared or matched original: %v", err)
			}
			// The inspection must not mutate either archive; it has no
			// cleanup authority over a foreign candidate directory.
			originalBytes, originalErr := os.ReadFile(filepath.Join(moved, inertRestoreCipherName))
			foreignPath := filepath.Join(foreign, inertRestoreCipherName)
			if replacement == "private_directory" {
				foreignPath = filepath.Join(scope, inertRestoreCipherName)
			}
			foreignBytes, foreignErr := os.ReadFile(foreignPath)
			if originalErr != nil || foreignErr != nil ||
				string(originalBytes) != "original-synthetic-ciphertext" ||
				string(foreignBytes) != "foreign-synthetic-ciphertext" {
				t.Fatalf("inspection changed ciphertext ownership: originalErr=%v foreignErr=%v",
					originalErr, foreignErr)
			}
		})
	}
}

func TestReopenInertCandidateRechecksIdentityAfterAuthenticatedPreflight(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	parent := newInertCandidateParent(t, f.stateRoot)
	sourceParent := testSealedDir(t, f)
	source := filepath.Join(sourceParent, "reopen-identity.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	candidate, err := StageInertRestoreCandidate(context.Background(), source, parent, key)
	if err != nil {
		t.Fatal(err)
	}
	location := candidate.Directory()
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(f.stateRoot, "original-before-reopen-swap")
	var mutationErr error
	mutated := false
	reopened, err := reopenInertRestoreCandidateProbed(
		context.Background(), location, key,
		func() {
			mutated = true
			if mutationErr = os.Rename(location, moved); mutationErr != nil {
				return
			}
			mutationErr = os.Mkdir(location, 0o700)
		},
	)
	if reopened != nil {
		_ = reopened.Close()
	}
	if !mutated || mutationErr != nil || reopened != nil ||
		!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("reopen adopted replaced path: mutated=%t reopened=%t err=%v mutationErr=%v",
			mutated, reopened != nil, err, mutationErr)
	}
	entries, err := os.ReadDir(location)
	if err != nil || len(entries) != 0 {
		t.Fatalf("reopen wrote to replacement path: entries=%d err=%v", len(entries), err)
	}
	original, err := os.ReadDir(moved)
	if err != nil || len(original) != 1 || original[0].Name() != inertRestoreCipherName {
		t.Fatalf("reopen removed original ciphertext: entries=%d err=%v", len(original), err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("reopen corrupted authenticated source: %v", err)
	}
}
