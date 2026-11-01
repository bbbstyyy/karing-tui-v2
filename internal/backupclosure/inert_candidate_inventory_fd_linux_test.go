//go:build linux

package backupclosure

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// This asserts the inode selected by the inventory fd, not just the final
// refusal. An advisory flock cannot prevent a different same-UID process
// from renaming the candidate directory while the lease is held.
func TestInertCandidateInventoryReaderAnchoredToLeasedInode(t *testing.T) {
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
			candidate, err := openLockedInertRestoreCandidate(scope)
			if err != nil {
				t.Fatal(err)
			}
			defer candidate.Close()

			// Two independent streams must each start at the first entry.
			for attempt := 0; attempt < 2; attempt++ {
				reader, err := openLockedInertCandidateInventoryReader(candidate)
				if err != nil {
					t.Fatalf("initial independent inventory %d: %v", attempt, err)
				}
				entries, readErr := reader.ReadDir(-1)
				closeErr := reader.Close()
				if readErr != nil || closeErr != nil || len(entries) != 1 ||
					entries[0].Name() != inertRestoreCipherName {
					t.Fatalf("inventory %d skipped the private ciphertext: entries=%v read=%v close=%v",
						attempt, entries, readErr, closeErr)
				}
			}

			moved := filepath.Join(parent, "moved-original")
			if err := os.Rename(scope, moved); err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(parent, "foreign-directory")
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, "foreign-only"),
				[]byte("untrusted"), 0o600); err != nil {
				t.Fatal(err)
			}
			if replacement == "private_directory" {
				if err := os.Rename(foreign, scope); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink(foreign, scope); err != nil {
				t.Fatal(err)
			}

			// A pathname-based reopened directory would refer to the
			// replacement; openat(".", leased_fd) must still see moved.
			reader, err := openLockedInertCandidateInventoryReader(candidate)
			if err != nil {
				t.Fatalf("lease-anchored inventory refused original fd: %v", err)
			}
			onFD, statErr := reader.Stat()
			entries, readErr := reader.ReadDir(-1)
			closeErr := reader.Close()
			if statErr != nil || !os.SameFile(onFD, candidate.directoryIdentity) ||
				readErr != nil || closeErr != nil || len(entries) != 1 ||
				entries[0].Name() != inertRestoreCipherName {
				t.Fatalf("inventory escaped leased inode: stat=%v entries=%v read=%v close=%v",
					statErr, entries, readErr, closeErr)
			}
			if _, err := inspectInertCandidateFile(candidate, false); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("adopted moved candidate despite pathname drift: %v", err)
			}
			atMoved, err := os.Lstat(moved)
			if err != nil || !os.SameFile(atMoved, candidate.directoryIdentity) {
				t.Fatalf("original locked inode lost after inventory: %v", err)
			}
			foreignPath := filepath.Join(scope, "foreign-only")
			if replacement == "symlink_to_private" {
				foreignPath = filepath.Join(foreign, "foreign-only")
			}
			if contents, err := os.ReadFile(foreignPath); err != nil || string(contents) != "untrusted" {
				t.Fatalf("inventory touched foreign replacement: %v", err)
			}
		})
	}
}

func TestInertCandidateInventoryReaderRequiresLiveLease(t *testing.T) {
	if _, err := openLockedInertCandidateInventoryReader(nil); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("nil candidate unexpectedly yielded inventory: %v", err)
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	scope, err := os.MkdirTemp(parent, inertRestoreCandidatePrefix)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := openLockedInertRestoreCandidate(scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openLockedInertCandidateInventoryReader(candidate); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("closed candidate unexpectedly yielded inventory: %v", err)
	}
}
