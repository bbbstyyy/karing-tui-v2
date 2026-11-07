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

// Reopen owns a NEW child flock, unlike the read-only Verify operation.
// Cancellation after final successful identity inspection must return no
// candidate receipt and release both new child and parent reservation locks.
func TestReopenCancellationAfterFinalIdentityReleasesOwnedLeases(t *testing.T) {
	_, original, key, ciphertext := borrowedCandidatePreflightFixture(t)
	scope := original.Directory()
	dirIdentity, err := os.Lstat(scope)
	if err != nil {
		t.Fatal(err)
	}
	cipherIdentity, err := os.Lstat(original.archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hits := 0
	reopened, reopenErr := reopenInertRestoreCandidateAtFinalIdentityProbed(
		ctx, scope, key, nil, nil, nil, func() { hits++; cancel() })
	if reopened != nil {
		_ = reopened.Close()
	}
	if hits != 1 || reopened != nil || !errors.Is(reopenErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("cancelled after final Reopen inspection returned candidate: hits=%d err=%v",
			hits, reopenErr)
	}
	atDir, err := os.Lstat(scope)
	if err != nil || !os.SameFile(dirIdentity, atDir) {
		t.Fatalf("cancelled Reopen replaced candidate directory: %v", err)
	}
	atCipher, err := os.Lstat(filepath.Join(scope, inertRestoreCipherName))
	if err != nil || !os.SameFile(cipherIdentity, atCipher) {
		t.Fatalf("cancelled Reopen replaced ciphertext file: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(scope, inertRestoreCipherName)); err != nil ||
		!bytes.Equal(got, ciphertext) {
		t.Fatalf("cancelled final Reopen modified encrypted file: %v", err)
	}
	contender, err := openLockedInertRestoreCandidate(scope)
	if err != nil {
		t.Fatalf("cancelled final Reopen leaked child flock: %v", err)
	}
	if err := contender.Close(); err != nil {
		t.Fatal(err)
	}
	parent, err := lockSealedArchiveParent(context.Background(), filepath.Dir(scope))
	if err != nil {
		t.Fatalf("cancelled final Reopen leaked parent reservation flock: %v", err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	healthy, err := ReopenInertRestoreCandidate(context.Background(), scope, key)
	if err != nil {
		t.Fatalf("healthy Reopen after cancelled final inspection failed: %v", err)
	}
	defer healthy.Close()
	verified, err := healthy.Verify(context.Background(), key)
	if err != nil || !verified.SQLiteLogicalVerified || !verified.SchemaCatalogVerified ||
		verified.RestoreReady || verified.RestoreSupported {
		t.Fatalf("healthy Reopen/Verify after cancellation degraded: %+v %v", verified, err)
	}
}

// After a successful final Reopen inspection, a non-cooperating same-UID
// actor can still rename files in the original child inode. Cancellation at
// that checkpoint must never adopt or delete the foreign valid ciphertext.
func TestReopenFinalIdentityCancellationPreservesForeignCipher(t *testing.T) {
	root, original, key, ciphertext := borrowedCandidatePreflightFixture(t)
	scope := original.Directory()
	archive := original.archive
	originalIdentity, err := os.Lstat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "reopen-final-original.ktbackup")
	foreign := filepath.Join(root, "reopen-final-foreign.ktbackup")
	sentinel := filepath.Join(root, "reopen-final-sentinel")
	if err := os.WriteFile(foreign, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	foreignIdentity, err := os.Lstat(foreign)
	if err != nil || os.SameFile(originalIdentity, foreignIdentity) {
		t.Fatalf("expected distinct foreign authenticated inode: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mutationErr error
	hits := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reopened, reopenErr := reopenInertRestoreCandidateAtFinalIdentityProbed(
		ctx, scope, key, nil, nil, nil, func() {
			hits++
			mutationErr = os.Rename(archive, moved)
			if mutationErr == nil {
				mutationErr = os.Rename(foreign, archive)
			}
			cancel()
		})
	if reopened != nil {
		_ = reopened.Close()
	}
	if hits != 1 || mutationErr != nil || reopened != nil ||
		!errors.Is(reopenErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Reopen adopted swapped cipher after cancel: hits=%d mutation=%v err=%v",
			hits, mutationErr, reopenErr)
	}
	oldAtPath, err := os.Lstat(moved)
	if err != nil || !os.SameFile(originalIdentity, oldAtPath) {
		t.Fatalf("Reopen deleted original moved file: %v", err)
	}
	foreignAtPath, err := os.Lstat(archive)
	if err != nil || !os.SameFile(foreignIdentity, foreignAtPath) {
		t.Fatalf("Reopen deleted or replaced foreign file: %v", err)
	}
	for _, name := range []string{archive, moved} {
		got, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(got, ciphertext) {
			t.Fatalf("Reopen changed ciphertext at %s: %v", filepath.Base(name), err)
		}
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
		t.Fatalf("Reopen changed foreign sentinel: %v", err)
	}
	receipt, err := PreflightInertArchive(context.Background(), archive, key, nil)
	if err != nil || !receipt.SQLiteLogicalVerified || !receipt.SchemaCatalogVerified ||
		receipt.RestoreReady || receipt.RestoreSupported {
		t.Fatalf("byte-identical foreign leaf not independently authenticated: %+v %v",
			receipt, err)
	}
	contender, err := openLockedInertRestoreCandidate(scope)
	if err != nil {
		t.Fatalf("cancelled final Reopen held child flock: %v", err)
	}
	if err := contender.Close(); err != nil {
		t.Fatal(err)
	}
	parent, err := lockSealedArchiveParent(context.Background(), filepath.Dir(scope))
	if err != nil {
		t.Fatalf("cancelled final Reopen held parent flock: %v", err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
}
