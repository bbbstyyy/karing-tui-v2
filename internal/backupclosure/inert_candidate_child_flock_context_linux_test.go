//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A cancellation at a PRIVATE checkpoint inside the initial child-fd
// handoff must prevent the next syscall or identity phase. The existing
// Stage-level post-handoff context check happens too late to prevent flock.
// No new encrypted target may be created and no parent/child lock may leak.
func TestStageCancelledDuringCreatedChildHandoffRefusesBeforeNextPhase(t *testing.T) {
	_, source, parent, key, sealed := stageTargetCustodyFixture(t)
	cases := []struct {
		phase        string
		mustNotReach string
	}{
		{"scope_child_open", "scope_child_fd_reused"},
		{"scope_child_fd_reused", "scope_child_fd_opened"},
		{"scope_child_fd_opened", "scope_child_flock"},
		{"scope_child_flock", "scope_child_lock_held"},
		{"scope_child_lock_held", "scope_child_identity"},
		{"scope_child_identity_verified", "scope_locked"},
	}
	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var phases []string
			injected := false
			candidate, err := stageInertRestoreCandidate(
				ctx, source, parent, key, func(phase string) bool {
					phases = append(phases, phase)
					if phase == tc.phase {
						injected = true
						cancel()
					}
					return true
				})
			if candidate != nil {
				_ = candidate.Close()
			}
			if !injected || candidate != nil ||
				!errors.Is(err, ErrUnsafeInertRestoreCandidate) ||
				!hasInertPhase(phases, "scope_child_context_cancelled") ||
				hasInertPhase(phases, tc.mustNotReach) {
				t.Fatalf("cancelled Stage crossed child lease boundary: injected=%t err=%v phases=%v",
					injected, err, phases)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("cancelled child handoff retained scope: entries=%v err=%v", entries, err)
			}
			parentLock, err := lockSealedArchiveParent(context.Background(), parent)
			if err != nil {
				t.Fatalf("cancelled child handoff retained parent flock: %v", err)
			}
			if err := parentLock.Close(); err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(actual, sealed) {
				t.Fatalf("cancelled handoff modified original encrypted archive: %v", err)
			}
		})
	}
}

// An already cancelled / missing context must refuse before attempting
// to flock. The exact original child FD is caller-owned on refusal.
// The same fd can still be inspected and the original empty child cleaned.
func TestCreatedChildContextRefusalPreservesCallerOwnedFD(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	parentLock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer parentLock.Close()
	var createdFD *os.File
	path, receipt, err := createInertScopeAtLeasedParentRetainedProbed(
		parentLock, parent, nil, &createdFD)
	if err != nil || createdFD == nil {
		t.Fatalf("failed to create original child fd: %v", err)
	}
	for _, name := range []string{"nil", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			var ctx context.Context
			if name == "cancelled" {
				c, cancel := context.WithCancel(context.Background())
				cancel()
				ctx = c
			}
			var phases []string
			candidate, err := lockCreatedInertRestoreCandidateAtParentContextProbed(
				ctx, path, parentLock, createdFD, receipt, func(phase string) bool {
					phases = append(phases, phase)
					return true
				})
			if candidate != nil {
				_ = candidate.Close()
			}
			if candidate != nil || !errors.Is(err, ErrUnsafeInertRestoreCandidate) ||
				!hasInertPhase(phases, "scope_child_context_cancelled") ||
				hasInertPhase(phases, "scope_child_flock") {
				t.Fatalf("context-refused child acquired lock: err=%v phases=%v", err, phases)
			}
			atFD, err := createdFD.Stat()
			if err != nil || !os.SameFile(receipt, atFD) {
				t.Fatalf("refusal closed or changed creator FD: %v", err)
			}
			contender, err := openLockedInertRestoreCandidate(path)
			if err != nil {
				t.Fatalf("refusal retained candidate flock: %v", err)
			}
			if err := contender.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := createdFD.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeNewEmptyInertScopeIfIdentical(parentLock, path, receipt); err != nil {
		t.Fatalf("cancelled creator's exact scope could not be safely removed: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected scope after exact cleanup: %v", err)
	}
}

// Even if cancellation and a non-cooperative same-UID scope replacement
// occur at the same original-fd checkpoint, Stage must never acquire a
// lock on or delete the foreign directory, and must release all its leases.
func TestCancelledCreatedChildHandoffPreservesForeignScope(t *testing.T) {
	root, source, parent, key, _ := stageTargetCustodyFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	moved := filepath.Join(root, "original-cancelled-scope")
	var scope string
	var original os.FileInfo
	var mutationErr error
	var phases []string
	injected := false
	candidate, stageErr := stageInertRestoreCandidate(
		ctx, source, parent, key, func(phase string) bool {
			phases = append(phases, phase)
			if phase != "scope_child_fd_reused" {
				return true
			}
			injected = true
			scope, mutationErr = singleCreatedScopeAtParent(parent)
			if mutationErr == nil {
				original, mutationErr = os.Lstat(scope)
			}
			if mutationErr == nil {
				mutationErr = os.Rename(scope, moved)
			}
			if mutationErr == nil {
				mutationErr = os.Mkdir(scope, 0o700)
			}
			if mutationErr == nil {
				mutationErr = os.WriteFile(
					filepath.Join(scope, "foreign-sentinel"), []byte("foreign-keep"), 0o600)
			}
			cancel()
			return true
		})
	if candidate != nil {
		_ = candidate.Close()
	}
	if !injected || mutationErr != nil || candidate != nil ||
		!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) ||
		!hasInertPhase(phases, "scope_child_context_cancelled") ||
		hasInertPhase(phases, "scope_child_flock") {
		t.Fatalf("cancelled Stage adopted foreign child: injected=%t err=%v mutation=%v phases=%v",
			injected, stageErr, mutationErr, phases)
	}
	atOld, err := os.Lstat(moved)
	if err != nil || !os.SameFile(original, atOld) {
		t.Fatalf("Stage deleted original created inode: %v", err)
	}
	atForeign, err := os.Lstat(scope)
	if err != nil || !atForeign.IsDir() || os.SameFile(original, atForeign) {
		t.Fatalf("Stage adopted/deleted foreign inode: %v", err)
	}
	foreign, err := os.ReadFile(filepath.Join(scope, "foreign-sentinel"))
	if err != nil || string(foreign) != "foreign-keep" {
		t.Fatalf("cancelled Stage changed foreign sentinel: %v", err)
	}
	relocked, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatalf("cancelled Stage retained parent reservation lock: %v", err)
	}
	if err := relocked.Close(); err != nil {
		t.Fatal(err)
	}
	// The original renamed child must also have no remaining flock.
	// Its basename is intentionally outside the candidate parent, so use
	// a raw fd to check the kernel flock rather than public path admission.
	hold, openErr := os.Open(moved)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer hold.Close()
	if info, err := hold.Stat(); err != nil || !os.SameFile(original, info) {
		t.Fatalf("original child inode no longer accessible: %v", err)
	}
	if err := syscall.Flock(int(hold.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("cancelled Stage left original child flock held: %v", err)
	}
	if err := syscall.Flock(int(hold.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}
