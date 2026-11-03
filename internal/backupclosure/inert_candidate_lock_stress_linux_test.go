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
	// Exercise enough repeated leases to expose uncommon, high-cycle
	// refusals such as the unexpected cycle 93 denial in PR #82. Keep this
	// bounded; no production retry or error classification is changed.
	const cycles = 512
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
		var phases []string
		candidate, err := openLockedInertRestoreCandidateProbed(path, func(phase string) bool {
			// Only fixed stage identifiers and bounded syscall classes
			// can enter these diagnostics; no paths, keys or errno text.
			phases = append(phases, phase)
			return true
		})
		if err != nil || candidate == nil {
			fdEntries, fdErr := os.ReadDir("/proc/self/fd")
			var limit syscall.Rlimit
			limitErr := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit)
			childInfo, childErr := os.Lstat(path)
			parentInfo, parentErr := os.Lstat(parent)
			parentIdentity, parentFDerr := parentLock.Stat()
			_ = parentLock.Close()
			t.Fatalf("cycle %d: candidate lease denied: %v; checkpoints=%v; proc_fd_count=%d fd_probe_ok=%t fd_soft_limit=%d rlimit_ok=%t; valid_name=%t; child_lstat_ok=%t child_private=%t; parent_lstat_ok=%t parent_fd_stat_ok=%t parent_same_inode=%t",
				cycle, err, phases, len(fdEntries), fdErr == nil,
				limit.Cur, limitErr == nil,
				validInertRestoreCandidateDir(path),
				childErr == nil,
				childErr == nil && childInfo.IsDir() && childInfo.Mode().Perm() == 0o700,
				parentErr == nil, parentFDerr == nil,
				parentErr == nil && parentFDerr == nil && os.SameFile(parentInfo, parentIdentity))
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


// A parent swapped after the child inode check but before the parent
// identity receipt must produce a bounded test-only refusal label. The
// replacement contains the SAME original child inode, so a child-only
// identity check would miss the change. Neither target is ever cleaned
// by this read-only diagnostic helper.
func TestInertCandidateParentIdentityRefusalHasFixedProbeLabel(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "parent")
	moved := filepath.Join(root, "moved-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	parentLock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer parentLock.Close()
	path, created, err := createInertScopeAtLeasedParent(parentLock, parent)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(path)
	var mutationErr error
	injected := false
	var phases []string
	candidate, openErr := openLockedInertRestoreCandidateAtParentProbed(
		path, parentLock, func(phase string) bool {
			phases = append(phases, phase)
			if phase == "scope_child_identity_verified" {
				injected = true
				mutationErr = os.Rename(parent, moved)
				if mutationErr != nil {
					return true
				}
				mutationErr = os.Mkdir(parent, 0o700)
				if mutationErr != nil {
					return true
				}
				mutationErr = os.Rename(filepath.Join(moved, name), path)
			}
			return true
		},
	)
	if candidate != nil {
		_ = candidate.Close()
	}
	if !injected || mutationErr != nil || candidate != nil ||
		!errors.Is(openErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("parent changed but child lease accepted: injected=%t err=%v mutation=%v",
			injected, openErr, mutationErr)
	}
	found := false
	for _, phase := range phases {
		if phase == "scope_child_parent_identity_refused" {
			found = true
		}
	}
	if !found {
		t.Fatalf("parent inode refusal did not emit fixed diagnostic phase: %v", phases)
	}
	atPath, err := os.Lstat(path)
	if err != nil || !os.SameFile(created, atPath) {
		t.Fatalf("failed scope admission modified original child inode: %v", err)
	}
}
