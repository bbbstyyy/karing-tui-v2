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

// Reopen opens an independent child fd and acquires its own flock. If the
// caller cancels at an existing private checkpoint, the next phase must
// not execute, and any newly opened/flocked child fd must be closed.
func TestReopenChildContextRefusalReleasesIndependentFlock(t *testing.T) {
	_, original, key, ciphertext := borrowedCandidatePreflightFixture(t)
	scope := original.Directory()
	identity, err := os.Lstat(scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		at, forbidden string
	}{
		{"scope_child_open", "scope_child_fd_opened"},
		{"scope_child_fd_opened", "scope_child_flock"},
		{"scope_child_flock", "scope_child_lock_held"},
		{"scope_child_lock_held", "scope_child_identity"},
		{"scope_child_identity_verified", "scope_child_parent_identity_refused"},
	} {
		t.Run(tc.at, func(t *testing.T) {
			parent, err := lockSealedArchiveParent(context.Background(), filepath.Dir(scope))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var phases []string
			injected := false
			leased, leaseErr := openLockedInertRestoreCandidateAtParentContextProbed(
				ctx, scope, parent, func(stage string) bool {
					phases = append(phases, stage)
					if stage == tc.at {
						injected = true
						cancel()
					}
					return true
				})
			if leased != nil {
				_ = leased.Close()
			}
			if !injected || leased != nil ||
				!errors.Is(leaseErr, ErrUnsafeInertRestoreCandidate) ||
				!hasInertPhase(phases, "scope_reopen_context_cancelled") ||
				hasInertPhase(phases, tc.forbidden) {
				t.Fatalf("cancelled Reopen continued child lease: phase=%s injected=%t err=%v phases=%v",
					tc.at, injected, leaseErr, phases)
			}
			if _, err := parent.Stat(); err != nil {
				t.Fatalf("Reopen closed borrowed parent lease: %v", err)
			}
			if err := parent.Close(); err != nil {
				t.Fatal(err)
			}
			// This must succeed even for cancellation AFTER flock: the
			// owned child fd must have been closed on refusal.
			contender, err := openLockedInertRestoreCandidate(scope)
			if err != nil {
				t.Fatalf("cancelled Reopen leaked exclusive flock: %v", err)
			}
			if err := contender.Close(); err != nil {
				t.Fatal(err)
			}
			atPath, err := os.Lstat(scope)
			if err != nil || !os.SameFile(identity, atPath) {
				t.Fatalf("cancelled Reopen replaced directory inode: %v", err)
			}
		})
	}
	if got, err := os.ReadFile(filepath.Join(scope, inertRestoreCipherName)); err != nil ||
		!bytes.Equal(got, ciphertext) {
		t.Fatalf("cancelled Reopen modified authenticated ciphertext: %v", err)
	}
	healthy, err := ReopenInertRestoreCandidate(context.Background(), scope, key)
	if err != nil {
		t.Fatalf("healthy Reopen after cancelled lease attempts refused: %v", err)
	}
	defer healthy.Close()
	if verified, err := healthy.Verify(context.Background(), key); err != nil ||
		!verified.SQLiteLogicalVerified || !verified.SchemaCatalogVerified ||
		verified.RestoreReady || verified.RestoreSupported {
		t.Fatalf("healthy Reopen/Verify degraded: %+v %v", verified, err)
	}
}

// An already cancelled or nil context is rejected BEFORE the independent
// child-open syscall. Neither refusal closes the original caller-owned
// parent fd or changes the encrypted candidate.
func TestReopenChildNilOrPreCancelledContextNoFlock(t *testing.T) {
	_, original, _, ciphertext := borrowedCandidatePreflightFixture(t)
	scope := original.Directory()
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	parent, err := lockSealedArchiveParent(context.Background(), filepath.Dir(scope))
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	for _, kind := range []string{"nil", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			var ctx context.Context
			if kind == "cancelled" {
				cancelled, cancel := context.WithCancel(context.Background())
				cancel()
				ctx = cancelled
			}
			var phases []string
			leased, err := openLockedInertRestoreCandidateAtParentContextProbed(
				ctx, scope, parent, func(s string) bool {
					phases = append(phases, s)
					return true
				})
			if leased != nil {
				_ = leased.Close()
			}
			if leased != nil || !errors.Is(err, ErrUnsafeInertRestoreCandidate) ||
				!hasInertPhase(phases, "scope_reopen_context_cancelled") ||
				hasInertPhase(phases, "scope_child_open") {
				t.Fatalf("rejected context acquired a child lease: err=%v phases=%v", err, phases)
			}
			if _, err := parent.Stat(); err != nil {
				t.Fatalf("rejected Reopen closed caller-owned parent: %v", err)
			}
			contender, err := openLockedInertRestoreCandidate(scope)
			if err != nil {
				t.Fatalf("refused Reopen retained a child flock: %v", err)
			}
			_ = contender.Close()
		})
	}
	if got, err := os.ReadFile(filepath.Join(scope, inertRestoreCipherName)); err != nil ||
		!bytes.Equal(got, ciphertext) {
		t.Fatalf("context refusal changed encrypted bytes: %v", err)
	}
}

// The actual Reopen entrypoint forwards cancellation after its parent
// inventory and also rechecks cancellation after a successful HMAC before
// returning a usable lease. Neither cancellation may orphan a lock.
func TestReopenCancellationBeforeChildOpenAndAfterPreflight(t *testing.T) {
	_, original, key, ciphertext := borrowedCandidatePreflightFixture(t)
	scope := original.Directory()
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"before_child_open", "before_hmac", "after_hmac"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := false
			var beforeOpen, beforeHMAC, afterHMAC func()
			mark := func() { called = true; cancel() }
			switch phase {
			case "before_child_open":
				beforeOpen = mark
			case "before_hmac":
				beforeHMAC = mark
			case "after_hmac":
				afterHMAC = mark
			}
			reopened, err := reopenInertRestoreCandidateAtFileProbed(
				ctx, scope, key, beforeOpen, beforeHMAC, afterHMAC)
			if reopened != nil {
				_ = reopened.Close()
			}
			if !called || reopened != nil ||
				!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("cancelled Reopen returned a candidate: phase=%s called=%t err=%v",
					phase, called, err)
			}
			contender, err := openLockedInertRestoreCandidate(scope)
			if err != nil {
				t.Fatalf("Reopen retained child flock after %s cancellation: %v", phase, err)
			}
			_ = contender.Close()
			parent, err := lockSealedArchiveParent(context.Background(), filepath.Dir(scope))
			if err != nil {
				t.Fatalf("Reopen retained parent flock after %s cancellation: %v", phase, err)
			}
			_ = parent.Close()
			if got, err := os.ReadFile(filepath.Join(scope, inertRestoreCipherName)); err != nil ||
				!bytes.Equal(got, ciphertext) {
				t.Fatalf("Reopen cancellation changed ciphertext: %v", err)
			}
		})
	}
}

// Cancellation and foreign child substitution together must never cause
// Reopen to adopt or clean up the unrelated private scope.
func TestCancelledReopenDoesNotAdoptForeignPrivateChild(t *testing.T) {
	root, original, key, ciphertext := borrowedCandidatePreflightFixture(t)
	scope := original.Directory()
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "reopen-original-before-child-open")
	var mutationErr error
	injected := false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reopened, reopenErr := reopenInertRestoreCandidateAtParentProbed(
		ctx, scope, key, func() {
			injected = true
			mutationErr = os.Rename(scope, moved)
			if mutationErr == nil {
				mutationErr = os.Mkdir(scope, 0o700)
			}
			if mutationErr == nil {
				mutationErr = os.WriteFile(filepath.Join(scope, "foreign-sentinel"),
					[]byte("preserved"), 0o600)
			}
			cancel()
		}, nil)
	if reopened != nil {
		_ = reopened.Close()
	}
	if !injected || mutationErr != nil || reopened != nil ||
		!errors.Is(reopenErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("cancelled Reopen adopted foreign scope: injected=%t mutation=%v err=%v",
			injected, mutationErr, reopenErr)
	}
	if data, err := os.ReadFile(filepath.Join(moved, inertRestoreCipherName)); err != nil ||
		!bytes.Equal(data, ciphertext) {
		t.Fatalf("cancelled Reopen damaged original ciphertext: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(scope, "foreign-sentinel")); err != nil ||
		string(data) != "preserved" {
		t.Fatalf("cancelled Reopen damaged foreign scope: %v", err)
	}
	parent, err := lockSealedArchiveParent(context.Background(), filepath.Dir(scope))
	if err != nil {
		t.Fatalf("cancelled Reopen retained parent lock: %v", err)
	}
	_ = parent.Close()
}
