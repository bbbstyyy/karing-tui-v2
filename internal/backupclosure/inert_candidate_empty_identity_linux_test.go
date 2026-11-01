//go:build linux

package backupclosure

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Empty candidate scopes are permitted only for failed-stage cleanup. Their
// pathname must still resolve to the exact directory protected by the lease.
func TestEmptyCandidateInventoryRejectsPostScanPathSwap(t *testing.T) {
	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
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
			defer candidate.Close()
			if found, err := inspectInertCandidateFile(candidate, true); err != nil || found != nil {
				t.Fatalf("intact empty scope rejected: found=%v err=%v", found, err)
			}
			moved := filepath.Join(parent, "original")
			foreign := filepath.Join(parent, "foreign")
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, "sentinel"), []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			found, err := inspectInertCandidateFileProbed(candidate, true, func() bool {
				if err := os.Rename(scope, moved); err != nil {
					t.Fatal(err)
				}
				if replacement == "directory" {
					if err := os.Rename(foreign, scope); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Symlink(foreign, scope); err != nil {
					t.Fatal(err)
				}
				return true
			})
			if found != nil || !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("accepted replaced empty scope: found=%v err=%v", found, err)
			}
			original, err := os.Lstat(moved)
			if err != nil || !os.SameFile(original, candidate.directoryIdentity) {
				t.Fatalf("lost leased inode: %v", err)
			}
			sentinel := filepath.Join(foreign, "sentinel")
			if replacement == "directory" {
				sentinel = filepath.Join(scope, "sentinel")
			}
			data, err := os.ReadFile(sentinel)
			if err != nil || string(data) != "keep" {
				t.Fatalf("touched replacement: %v", err)
			}
		})
	}
}
