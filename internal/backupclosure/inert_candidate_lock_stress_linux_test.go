//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// This exercises exactly the fresh private scope + child directory flock
// sequence implicated by Issue #59. Unlike repeated encrypted preflights,
// it keeps the test bounded and isolates fd/lease lifecycle behaviour.
func TestInertCandidateScopeLeaseCyclesDoNotLeakOrGrantCompetingLease(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	const cycles = 128
	for cycle := 0; cycle < cycles; cycle++ {
		parentLock, err := lockSealedArchiveParent(context.Background(), parent)
		if err != nil {
			t.Fatalf("cycle %d: private parent lock: %v", cycle, err)
		}
		path, err := os.MkdirTemp(parent, inertRestoreCandidatePrefix)
		if err != nil {
			_ = parentLock.Close()
			t.Fatalf("cycle %d: private scope: %v", cycle, err)
		}
		candidate, err := openLockedInertRestoreCandidate(path)
		if err != nil || candidate == nil {
			_ = parentLock.Close()
			t.Fatalf("cycle %d: candidate lease denied: %v", cycle, err)
		}
		contender, conflict := openLockedInertRestoreCandidate(path)
		if contender != nil {
			_ = contender.Close()
		}
		if contender != nil || !errors.Is(conflict, ErrInertRestoreCandidateBusy) {
			_ = candidate.Close()
			_ = parentLock.Close()
			t.Fatalf("cycle %d: competing lease was not refused: %v", cycle, conflict)
		}
		if err := candidate.Close(); err != nil {
			_ = parentLock.Close()
			t.Fatalf("cycle %d: close active candidate: %v", cycle, err)
		}
		reopened, err := openLockedInertRestoreCandidate(path)
		if err != nil || reopened == nil {
			_ = parentLock.Close()
			t.Fatalf("cycle %d: closed lease cannot be reacquired: %v", cycle, err)
		}
		if err := reopened.Close(); err != nil {
			_ = parentLock.Close()
			t.Fatalf("cycle %d: close reopened candidate: %v", cycle, err)
		}
		if err := parentLock.Close(); err != nil {
			t.Fatalf("cycle %d: parent lock close: %v", cycle, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("cycle %d: exact empty scope not removable: %v", cycle, err)
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("repeated leases retained candidate scopes: count=%d err=%v", len(entries), err)
	}
}

// Between acquiring the fd/flock and checking identity, an attacker can
// replace the pathname. The fd must not be mistaken for the replacement,
// even when the replacement itself has private 0700 permissions.
func TestInertCandidateScopeIdentityRefusesPathSwapAndPermissionDrift(t *testing.T) {
	for _, mutation := range []string{"replace_inode", "replace_symlink", "weaken_mode"} {
		t.Run(mutation, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			path, err := os.MkdirTemp(parent, inertRestoreCandidatePrefix)
			if err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(parent, "original-inode")
			var mutationErr error
			injected := false
			candidate, err := openLockedInertRestoreCandidateProbed(path, func(phase string) bool {
				if phase != "scope_child_lock_held" {
					return true
				}
				injected = true
				switch mutation {
				case "replace_inode", "replace_symlink":
					mutationErr = os.Rename(path, moved)
					if mutationErr == nil && mutation == "replace_inode" {
						mutationErr = os.Mkdir(path, 0o700)
					}
					if mutationErr == nil && mutation == "replace_symlink" {
						mutationErr = os.Symlink(moved, path)
					}
				case "weaken_mode":
					mutationErr = os.Chmod(path, 0o755)
				}
				return true
			})
			if candidate != nil {
				_ = candidate.Close()
			}
			if mutationErr != nil {
				t.Fatalf("test-only scope mutation failed: %v", mutationErr)
			}
			if !injected || candidate != nil || !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("mutable scope path adopted: injected=%t candidate=%t err=%v",
					injected, candidate != nil, err)
			}
			if mutation == "replace_inode" {
				original, originalErr := os.Lstat(moved)
				replacement, replaceErr := os.Lstat(path)
				if originalErr != nil || replaceErr != nil || os.SameFile(original, replacement) {
					t.Fatalf("path swap test did not retain two distinct private inodes: %v %v",
						originalErr, replaceErr)
				}
			}
			if mutation == "replace_symlink" {
				link, linkErr := os.Lstat(path)
				if linkErr != nil || link.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("path swap test did not retain the untrusted symlink: %v", linkErr)
				}
			}
			if mutation == "weaken_mode" {
				scope, statErr := os.Lstat(path)
				if statErr != nil || scope.Mode().Perm() != 0o755 {
					t.Fatalf("permission drift was not exercised: %v", statErr)
				}
			}
		})
	}
}

// Stage does not retry on EAGAIN or silently trust a different directory.
// These syscall classifications remain stable without exposing OS paths.
func TestInertCandidateLockBusyClassification(t *testing.T) {
	if got := inertCandidateErrnoClass(syscall.EWOULDBLOCK); got != "lock_contention" {
		t.Fatalf("unexpected lock contention class: %q", got)
	}
}
