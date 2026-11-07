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

// A cancelled explicit Discard must not unlink authenticated ciphertext
// when cancellation happens after parent/leaf leases are acquired but before
// the FIRST irreversible unlink. An aborted Discard releases its flock.
func TestExplicitDiscardCancellationBeforeCipherUnlinkPreservesCandidate(t *testing.T) {
	_, candidate, key, ciphertext := borrowedCandidatePreflightFixture(t)
	scope := candidate.Directory()
	original, err := os.Lstat(candidate.archive)
	if err != nil {
		t.Fatal(err)
	}
	child, err := os.Lstat(scope)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	err = candidate.discardLockedWithLeafContextProbed(
		ctx, true, nil, false, func() { called = true; cancel() }, nil)
	if !called || !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("cancelled Discard proceeded to unlink: called=%t err=%v", called, err)
	}
	if candidate.dir != nil {
		t.Fatal("cancelled Discard retained caller's old flock")
	}
	afterCipher, err := os.Lstat(candidate.archive)
	if err != nil || !os.SameFile(original, afterCipher) {
		t.Fatalf("cancelled Discard replaced or removed original ciphertext inode: %v", err)
	}
	afterScope, err := os.Lstat(scope)
	if err != nil || !os.SameFile(child, afterScope) {
		t.Fatalf("cancelled Discard removed original scope inode: %v", err)
	}
	if got, err := os.ReadFile(candidate.archive); err != nil ||
		!bytes.Equal(got, ciphertext) {
		t.Fatalf("cancelled Discard changed authenticated ciphertext: %v", err)
	}
	reopened, err := ReopenInertRestoreCandidate(context.Background(), scope, key)
	if err != nil {
		t.Fatalf("cancelled Discard leaked parent/child flock: %v", err)
	}
	defer reopened.Close()
	report, err := reopened.Verify(context.Background(), key)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.RestoreReady || report.RestoreSupported {
		t.Fatalf("cancelled Discard damaged healthy read-only preflight: %+v %v", report, err)
	}
}

// Once the first irreversible ciphertext unlink completes, a later context
// cancellation cannot restore the original file. Finish fsync/empty scope
// unlink rather than strand a half-discarded candidate.
func TestExplicitDiscardCancellationAfterCipherUnlinkCompletesCleanup(t *testing.T) {
	_, candidate, _, _ := borrowedCandidatePreflightFixture(t)
	scope := candidate.Directory()
	parent := filepath.Dir(scope)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	var callbackErr error
	err := candidate.discardLockedWithLeafContextProbed(
		ctx, true, nil, false, nil, func() {
			called = true
			if _, statErr := os.Lstat(candidate.archive); !errors.Is(statErr, os.ErrNotExist) {
				callbackErr = statErr
				if statErr == nil {
					callbackErr = errors.New("ciphertext still present after first unlink")
				}
			}
			cancel()
		})
	if err != nil || !called || callbackErr != nil || ctx.Err() == nil {
		t.Fatalf("post-unlink cancel stranded half-discard: called=%t callback=%v err=%v",
			called, callbackErr, err)
	}
	if candidate.dir != nil {
		t.Fatal("completed Discard retained child flock")
	}
	if _, err := os.Lstat(scope); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-unlink cancelled Discard retained scope: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("post-unlink cancelled Discard left parent entries: %v %v", entries, err)
	}
	parentLease, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatalf("completed post-unlink Discard retained parent flock: %v", err)
	}
	if err := parentLease.Close(); err != nil {
		t.Fatal(err)
	}
}

// Pre-cancelled user intent is rejected by the public API before deletion
// starts; the existing caller-owned lease remains usable in this case.
func TestExplicitDiscardPreCancelledContextDoesNotStartOrReleaseLease(t *testing.T) {
	_, candidate, key, ciphertext := borrowedCandidatePreflightFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := candidate.Discard(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled Discard changed error contract: %v", err)
	}
	if candidate.dir == nil {
		t.Fatal("pre-cancelled public Discard unexpectedly closed candidate lease")
	}
	if got, err := os.ReadFile(candidate.archive); err != nil ||
		!bytes.Equal(got, ciphertext) {
		t.Fatalf("pre-cancelled Discard changed source bytes: %v", err)
	}
	contender, busyErr := openLockedInertRestoreCandidate(candidate.Directory())
	if contender != nil {
		_ = contender.Close()
	}
	if !errors.Is(busyErr, ErrInertRestoreCandidateBusy) {
		t.Fatalf("pre-cancelled Discard relinquished exclusive flock: %v", busyErr)
	}
	report, err := candidate.Verify(context.Background(), key)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.RestoreReady || report.RestoreSupported {
		t.Fatalf("pre-cancelled Discard degraded live candidate: %+v %v", report, err)
	}
}
