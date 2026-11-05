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

// Stage cancellation at the last pre-mkdirat checkpoint is not allowed to
// allocate a directory. Cancellation after the child is created or flocked
// must release the original fds and remove only its own empty scope.
func TestStageCancellationBeforeAndAfterCreatedDirectoryClosesLeases(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	source := filepath.Join(testSealedDir(t, f), "cancellation-lease-source.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	originalCipher, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	for _, phase := range []string{
		"create_scope",
		"scope_before_mkdirat",
		"scope_created",
		"scope_child_fd_reused",
		"scope_child_lock_held",
		"scope_locked",
		"cipher_copy",
	} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			injected := false
			candidate, stageErr := stageInertRestoreCandidate(
				ctx, source, parent, key, func(at string) bool {
					if at == phase {
						injected = true
						cancel()
					}
					return true
				})
			if candidate != nil {
				_ = candidate.Close()
			}
			if !injected || candidate != nil ||
				!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("cancelled Stage allocated candidate: injected=%t err=%v",
					injected, stageErr)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("cancelled Stage retained private candidate scope: entries=%v err=%v",
					entries, err)
			}
			// The original parent flock must be released, even when
			// cancellation occurs after the new child fd acquires flock.
			reacquired, err := lockSealedArchiveParent(context.Background(), parent)
			if err != nil {
				t.Fatalf("cancelled Stage retained parent lock: %v", err)
			}
			if err := reacquired.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(got, originalCipher) {
				t.Fatalf("cancelled Stage modified original ciphertext: %v", err)
			}
		})
	}
}

// This 512-cycle stress test exercises the EXACT new production creation
// and child lease handoff. The older Issue #59 stress test intentionally
// exercises the independent standalone open path; both are required.
func TestStageCreatedFDHandoffLeaseCyclesNoLeaks(t *testing.T) {
	const cycles = 512
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	initial, listErr := os.ReadDir("/proc/self/fd")
	checkFDs := listErr == nil
	baselineFDs := len(initial)
	for cycle := 0; cycle < cycles; cycle++ {
		lock, err := lockSealedArchiveParent(context.Background(), parent)
		if err != nil {
			t.Fatalf("cycle %d: parent flock refused: %v", cycle, err)
		}
		var child *os.File
		path, receipt, err := createInertScopeAtLeasedParentRetainedProbed(
			lock, parent, nil, &child)
		if err != nil || child == nil {
			_ = lock.Close()
			t.Fatalf("cycle %d: exact creation fd refused: %v", cycle, err)
		}
		onFD, err := child.Stat()
		if err != nil || !os.SameFile(receipt, onFD) {
			_ = child.Close()
			_ = lock.Close()
			t.Fatalf("cycle %d: first opened inode differs from creation receipt: %v", cycle, err)
		}
		var phases []string
		candidate, err := lockCreatedInertRestoreCandidateAtParentProbed(
			path, lock, child, receipt, func(stage string) bool {
				// Only bounded, constant probe labels are recorded.
				phases = append(phases, stage)
				return true
			})
		if err != nil || candidate == nil {
			_ = child.Close()
			_ = lock.Close()
			t.Fatalf("cycle %d: initial created-fd flock refused: %v phases=%v",
				cycle, err, phases)
		}
		child = nil // ownership transferred to the active candidate.
		if !hasInertPhase(phases, "scope_child_fd_reused") ||
			!os.SameFile(receipt, candidate.directoryIdentity) {
			_ = candidate.Close()
			_ = lock.Close()
			t.Fatalf("cycle %d: lease did not reuse creation receipt fd", cycle)
		}
		other, contention := openLockedInertRestoreCandidate(path)
		if other != nil {
			_ = other.Close()
		}
		if other != nil || !errors.Is(contention, ErrInertRestoreCandidateBusy) {
			_ = candidate.Close()
			_ = lock.Close()
			t.Fatalf("cycle %d: competing child flock was not refused: %v",
				cycle, contention)
		}
		if err := candidate.Close(); err != nil {
			_ = lock.Close()
			t.Fatalf("cycle %d: active flock close failed: %v", cycle, err)
		}
		reopened, err := openLockedInertRestoreCandidate(path)
		if err != nil || reopened == nil {
			_ = lock.Close()
			t.Fatalf("cycle %d: closed child could not be reopened: %v", cycle, err)
		}
		if err := reopened.Close(); err != nil {
			_ = lock.Close()
			t.Fatalf("cycle %d: reopened flock close failed: %v", cycle, err)
		}
		if err := removeNewEmptyInertScopeIfIdentical(lock, path, receipt); err != nil {
			_ = lock.Close()
			t.Fatalf("cycle %d: exact empty scope cleanup refused: %v", cycle, err)
		}
		if err := lock.Close(); err != nil {
			t.Fatalf("cycle %d: original parent flock close failed: %v", cycle, err)
		}
		if checkFDs && cycle%64 == 63 {
			entries, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(entries) > baselineFDs+4 {
				t.Fatalf("cycle %d: leaked descriptors after created-fd lease cycles: initial=%d current=%d err=%v",
					cycle, baselineFDs, len(entries), err)
			}
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("bounded 512-cycle fd handoff left candidate scopes: entries=%v err=%v",
			entries, err)
	}
	// A finished Stage must never leave its parent reservation lock held.
	pin, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatalf("post-stress original parent flock still held: %v", err)
	}
	if err := syscall.Flock(int(pin.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
}
