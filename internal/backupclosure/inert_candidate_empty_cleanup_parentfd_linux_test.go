//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The child's pathname and inode can still match after a same-UID actor
// replaces the private parent and moves the *same* empty child into it.
// Checking only sameNewInertScopeIdentity would wrongly authorize cleanup.
func TestInertEmptyStageCleanupRefusesSameChildUnderReplacedParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "parent")
	moved := filepath.Join(root, "moved-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	scope, original, err := createInertScopeAtLeasedParent(lock, parent)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(scope)
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(moved, name), scope); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "foreign-sentinel"), []byte("intact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !sameNewInertScopeIdentity(scope, original) {
		t.Fatal("test setup must preserve same child inode and pathname")
	}
	if err := removeNewEmptyInertScopeIfIdentical(lock, scope, original); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("removed original child under new parent: %v", err)
	}
	atPath, err := os.Lstat(scope)
	if err != nil || !os.SameFile(atPath, original) {
		t.Fatalf("original empty child missing after refusal: %v", err)
	}
	if entries, err := os.ReadDir(scope); err != nil || len(entries) != 0 {
		t.Fatalf("refusal changed original empty child: %v %v", entries, err)
	}
	sentinel, err := os.ReadFile(filepath.Join(parent, "foreign-sentinel"))
	if err != nil || string(sentinel) != "intact" {
		t.Fatalf("replacement parent sentinel changed: %v", err)
	}
}

func TestInertEmptyStageCleanupRefusesNonemptyLeasedScope(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	scope, created, err := createInertScopeAtLeasedParent(lock, parent)
	if err != nil {
		t.Fatal(err)
	}
	sentinelPath := filepath.Join(scope, "unknown-file")
	if err := os.WriteFile(sentinelPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeNewEmptyInertScopeIfIdentical(lock, scope, created); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("nonempty scope removed by failed-stage cleanup: %v", err)
	}
	sentinel, err := os.ReadFile(sentinelPath)
	if err != nil || string(sentinel) != "preserve" {
		t.Fatalf("nonempty scope or unknown file damaged: %v", err)
	}
}

// Exercise the actual early Stage rejection, not just the standalone helper.
// The current canonical child is still the original created inode; only the
// parent inode changed at the fixed scope_created checkpoint.
func TestInertStageRefusesCleanupAfterParentReplacementWithOriginalChild(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sealedParent := testSealedDir(t, f)
	source := filepath.Join(sealedParent, "early-cleanup-parent-source.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	moved := filepath.Join(f.stateRoot, "moved-early-cleanup-parent")
	var mutationErr error
	var original os.FileInfo
	var scope string
	mutated := false
	candidate, stageErr := stageInertRestoreCandidate(
		context.Background(), source, parent, key,
		func(phase string) bool {
			if phase != "scope_created" {
				return true
			}
			mutated = true
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 1 {
				mutationErr = ErrUnsafeInertRestoreCandidate
				return false
			}
			scope = filepath.Join(parent, entries[0].Name())
			original, mutationErr = os.Lstat(scope)
			if mutationErr != nil {
				return false
			}
			mutationErr = os.Rename(parent, moved)
			if mutationErr != nil {
				return false
			}
			mutationErr = os.Mkdir(parent, 0o700)
			if mutationErr != nil {
				return false
			}
			mutationErr = os.Rename(filepath.Join(moved, entries[0].Name()), scope)
			if mutationErr != nil {
				return false
			}
			mutationErr = os.WriteFile(filepath.Join(parent, "foreign-sentinel"), []byte("keep"), 0o600)
			return false
		},
	)
	if candidate != nil {
		_ = candidate.Close()
	}
	if !mutated || mutationErr != nil || candidate != nil ||
		!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("early stage adopted or deleted foreign-parent child: mutated=%t candidate=%t err=%v mutation=%v",
			mutated, candidate != nil, stageErr, mutationErr)
	}
	if atPath, err := os.Lstat(scope); err != nil || !os.SameFile(original, atPath) {
		t.Fatalf("same original child was unlinked after parent replacement: %v", err)
	}
	if entries, err := os.ReadDir(scope); err != nil || len(entries) != 0 {
		t.Fatalf("untrusted early cleanup changed candidate contents: %v %v", entries, err)
	}
	if sentinel, err := os.ReadFile(filepath.Join(parent, "foreign-sentinel")); err != nil || string(sentinel) != "keep" {
		t.Fatalf("foreign replacement modified: %v", err)
	}
	if _, err := os.Lstat(source); err != nil {
		t.Fatalf("stage rejection removed original encrypted source: %v", err)
	}
}
