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

// A same-UID actor can replace an owner-private parent and move the SAME
// locked candidate child inode into it. Checking only the child fd/path
// identity would accept this change in custody.
func TestInertCandidateVerifyAndDiscardRejectReplacedParentWithSameChild(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sourceParent := testSealedDir(t, f)
	source := filepath.Join(sourceParent, "parent-identity-source.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	candidate, err := StageInertRestoreCandidate(context.Background(), source, parent, key)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Close()
	scope := candidate.Directory()
	name := filepath.Base(scope)
	before, err := os.ReadFile(filepath.Join(scope, inertRestoreCipherName))
	if err != nil {
		t.Fatal(err)
	}
	parentBefore, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.Verify(context.Background(), key); err != nil {
		t.Fatalf("healthy candidate failed original Verify: %v", err)
	}

	moved := filepath.Join(f.stateRoot, "moved-verify-parent")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(moved, name), scope); err != nil {
		t.Fatal(err)
	}
	child, err := os.Lstat(scope)
	if err != nil || !os.SameFile(child, candidate.directoryIdentity) {
		t.Fatalf("test must preserve the original locked child inode: %v", err)
	}
	if sameInertCandidateParentIdentity(parent, candidate.parentIdentity) {
		t.Fatal("substituted parent was accepted as leased parent")
	}
	movedParent, err := os.Lstat(moved)
	if err != nil || !os.SameFile(movedParent, parentBefore) {
		t.Fatalf("original parent inode lost: %v", err)
	}
	if _, err := candidate.Verify(context.Background(), key); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Verify adopted moved child under foreign parent: %v", err)
	}
	if err := candidate.Discard(context.Background()); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Discard removed moved child under foreign parent: %v", err)
	}
	remaining, err := os.ReadFile(filepath.Join(scope, inertRestoreCipherName))
	if err != nil || !bytes.Equal(remaining, before) {
		t.Fatalf("Discard damaged retained encrypted candidate: %v", err)
	}
	sourceBytes, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(sourceBytes, before) {
		t.Fatalf("source archive damaged: %v", err)
	}
}

// A Reopen parent lease is released before multi-pass authenticated SQLite
// preflight. Replacing that parent's inode and moving the identical candidate
// child into its place must not result in successful re-adoption.
func TestInertCandidateReopenRejectsParentSwapAfterAuthenticatedPreflight(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sourceParent := testSealedDir(t, f)
	source := filepath.Join(sourceParent, "parent-reopen-source.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	candidate, err := StageInertRestoreCandidate(context.Background(), source, parent, key)
	if err != nil {
		t.Fatal(err)
	}
	scope := candidate.Directory()
	cipher, err := os.ReadFile(filepath.Join(scope, inertRestoreCipherName))
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}

	moved := filepath.Join(f.stateRoot, "moved-reopen-parent-identity")
	var injectionErr error
	injected := false
	reopened, reopenErr := reopenInertRestoreCandidateProbed(
		context.Background(), scope, key, func() {
			injected = true
			injectionErr = os.Rename(parent, moved)
			if injectionErr != nil {
				return
			}
			injectionErr = os.Mkdir(parent, 0o700)
			if injectionErr != nil {
				return
			}
			injectionErr = os.WriteFile(filepath.Join(parent, "foreign-sentinel"),
				[]byte("untouched"), 0o600)
			if injectionErr != nil {
				return
			}
			injectionErr = os.Rename(filepath.Join(moved, filepath.Base(scope)), scope)
		},
	)
	if reopened != nil {
		_ = reopened.Close()
	}
	if !injected || injectionErr != nil || reopened != nil ||
		!errors.Is(reopenErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Reopen adopted moved child: injected=%t candidate=%t err=%v injection=%v",
			injected, reopened != nil, reopenErr, injectionErr)
	}
	remaining, err := os.ReadFile(filepath.Join(scope, inertRestoreCipherName))
	if err != nil || !bytes.Equal(remaining, cipher) {
		t.Fatalf("Reopen changed encrypted candidate: %v", err)
	}
	sourceBytes, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(sourceBytes, cipher) {
		t.Fatalf("source archive modified: %v", err)
	}
	sentinel, err := os.ReadFile(filepath.Join(parent, "foreign-sentinel"))
	if err != nil || string(sentinel) != "untouched" {
		t.Fatalf("replacement parent sentinel changed: %v", err)
	}
}
