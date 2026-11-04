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

// Stage must lock the SAME child directory fd whose inode was checked after
// mkdirat, rather than opening that child a second time by mutable basename.
// A same-UID test actor swaps the child path before Stage attempts flock.
// The original (renamed) inode must be locked and the foreign same-name inode
// must never be adopted, removed, or modified.
func TestStageLocksFirstCreatedChildFDDespiteSameNameReplacement(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	source := filepath.Join(testSealedDir(t, f), "source-scope-fd-handoff.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	moved := filepath.Join(f.stateRoot, "created-child-original")
	var scope string
	var original os.FileInfo
	var mutationErr error
	var movedOriginal, heldOriginalLock bool
	var phases []string
	candidate, stageErr := stageInertRestoreCandidate(
		context.Background(), source, parent, key, func(phase string) bool {
			phases = append(phases, phase)
			switch phase {
			case "scope_child_fd_reused":
				movedOriginal = true
				scope, mutationErr = singleCreatedScopeAtParent(parent)
				if mutationErr != nil {
					return false
				}
				original, mutationErr = os.Lstat(scope)
				if mutationErr != nil {
					return false
				}
				if mutationErr = os.Rename(scope, moved); mutationErr != nil {
					return false
				}
				if mutationErr = os.Mkdir(scope, 0o700); mutationErr != nil {
					return false
				}
				mutationErr = os.WriteFile(
					filepath.Join(scope, "foreign-sentinel"), []byte("do-not-touch"), 0o600)
				return mutationErr == nil
			case "scope_child_lock_held":
				if mutationErr != nil || !movedOriginal {
					return false
				}
				// The original child has been RENAMED away; an independent
				// flock on it must contend with Stage's original fd.
				contender, openErr := os.Open(moved)
				if openErr != nil {
					mutationErr = openErr
					return false
				}
				err := syscall.Flock(int(contender.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
				heldOriginalLock = errors.Is(err, syscall.EWOULDBLOCK) ||
					errors.Is(err, syscall.EAGAIN)
				if err == nil {
					_ = syscall.Flock(int(contender.Fd()), syscall.LOCK_UN)
				}
				_ = contender.Close()
			}
			return true
		})
	if candidate != nil {
		_ = candidate.Close()
	}
	if mutationErr != nil || !movedOriginal || !heldOriginalLock ||
		!hasInertPhase(phases, "scope_child_identity_refused") ||
		candidate != nil || !errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Stage flock followed foreign directory: moved=%t original_locked=%t error=%v mutation=%v phases=%v",
			movedOriginal, heldOriginalLock, stageErr, mutationErr, phases)
	}
	atMoved, err := os.Lstat(moved)
	if err != nil || !os.SameFile(original, atMoved) {
		t.Fatalf("Stage changed originally created child inode: %v", err)
	}
	atForeign, err := os.Lstat(scope)
	if err != nil || !atForeign.IsDir() || os.SameFile(original, atForeign) {
		t.Fatalf("Stage adopted or deleted foreign child inode: %v", err)
	}
	sentinel, err := os.ReadFile(filepath.Join(scope, "foreign-sentinel"))
	if err != nil || string(sentinel) != "do-not-touch" {
		t.Fatalf("Stage changed foreign scope contents: %v", err)
	}
	// Failed Stage must have closed its original child fd, releasing flock.
	contender, err := os.Open(moved)
	if err != nil {
		t.Fatal(err)
	}
	defer contender.Close()
	if err := syscall.Flock(int(contender.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("rejected candidate retained original flock: %v", err)
	}
	if err := syscall.Flock(int(contender.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	// The parent reservation is also released after stage refusal.
	parentAgain, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatalf("parent flock remained held after Stage refusal: %v", err)
	}
	_ = parentAgain.Close()
}

// Successful Stage reuses the original child fd and retains the same inode
// from the creation receipt through its candidate lease. Other candidates
// cannot obtain a competing flock. Full encrypted verification remains
// read-only and does not permit restore.
func TestStageCreatedScopeFDReusedOnHealthyEncryptedLifecycle(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	source := filepath.Join(testSealedDir(t, f), "source-healthy-created-fd.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	var created os.FileInfo
	var reused bool
	candidate, err := stageInertRestoreCandidate(
		context.Background(), source, parent, key, func(phase string) bool {
			if phase == "scope_created" {
				scope, statErr := singleCreatedScopeAtParent(parent)
				if statErr != nil {
					return false
				}
				created, statErr = os.Lstat(scope)
				return statErr == nil
			}
			if phase == "scope_child_fd_reused" {
				reused = true
			}
			return true
		})
	if err != nil || candidate == nil || !reused {
		t.Fatalf("healthy Stage did not retain created fd: reused=%t candidate=%t err=%v",
			reused, candidate != nil, err)
	}
	defer candidate.Close()
	atFD, err := candidate.dir.Stat()
	if err != nil || !os.SameFile(created, atFD) ||
		!os.SameFile(created, candidate.directoryIdentity) {
		t.Fatalf("candidate flock fd differs from creation receipt: %v", err)
	}
	contender, conflict := openLockedInertRestoreCandidate(candidate.Directory())
	if contender != nil {
		_ = contender.Close()
	}
	if contender != nil || !errors.Is(conflict, ErrInertRestoreCandidateBusy) {
		t.Fatalf("created child's exclusive flock not retained: %v", conflict)
	}
	report, err := candidate.Verify(context.Background(), key)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.RestoreReady || report.RestoreSupported {
		t.Fatalf("healthy Stage produced invalid/readiness-changing receipt: %+v %v",
			report, err)
	}
	directory := candidate.Directory()
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := ReopenInertRestoreCandidate(context.Background(), directory, key)
	if err != nil {
		t.Fatalf("reopening exactly created candidate failed: %v", err)
	}
	if err := reopened.Discard(context.Background()); err != nil {
		t.Fatalf("explicitly discarding healthy candidate failed: %v", err)
	}
}

// The new internal lock adapter borrows the creator's descriptor on failure:
// ownership must never be silently transferred or closed before the caller
// can perform safe original-inode cleanup.
func TestCreatedChildFlockFailureKeepsCreatorFDOwnedByCaller(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	parentLock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer parentLock.Close()
	var child *os.File
	path, receipt, err := createInertScopeAtLeasedParentRetainedProbed(
		parentLock, parent, nil, &child)
	if err != nil || child == nil {
		t.Fatalf("creator failed to hand out original fd: %v", err)
	}
	atFD, err := child.Stat()
	if err != nil || !os.SameFile(atFD, receipt) {
		t.Fatalf("retained created fd did not match receipt: %v", err)
	}
	var injected bool
	candidate, err := lockCreatedInertRestoreCandidateAtParentProbed(
		path, parentLock, child, receipt, func(phase string) bool {
			if phase == "scope_child_fd_opened" {
				injected = true
				return false
			}
			return true
		})
	if candidate != nil || !injected || !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("injected child flock boundary unexpectedly succeeded: %v", err)
	}
	if _, err := child.Stat(); err != nil {
		t.Fatalf("failed child-adoption routine closed caller-owned fd: %v", err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeNewEmptyInertScopeIfIdentical(parentLock, path, receipt); err != nil {
		t.Fatalf("original empty created scope was not safely removed: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original empty scope remains: %v", err)
	}
}
