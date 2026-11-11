//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

// Verify is read-only and borrows the candidate's existing exclusive flock.
// Cancellation after an otherwise successful HMAC/SQLite preflight must not
// return a stale receipt or close the caller-owned child descriptor.
func TestVerifyCancellationDoesNotPublishReceiptOrReleaseLease(t *testing.T) {
	_, candidate, key, ciphertext := borrowedCandidatePreflightFixture(t)
	scope := candidate.Directory()
	identity, err := os.Lstat(scope)
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := candidate.Verify(context.Background(), key)
	if err != nil || !healthy.SQLiteLogicalVerified || !healthy.SchemaCatalogVerified ||
		healthy.RestoreReady || healthy.RestoreSupported {
		t.Fatalf("fixture not a healthy inert candidate: %+v %v", healthy, err)
	}
	for _, phase := range []string{
		"before_inventory", "before_preflight", "after_preflight", "after_identity",
	} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var beforeInventory, beforePreflight, afterPreflight, afterIdentity func()
			hits := 0
			mark := func() { hits++; cancel() }
			switch phase {
			case "before_inventory":
				beforeInventory = mark
			case "before_preflight":
				beforePreflight = mark
			case "after_preflight":
				afterPreflight = mark
			case "after_identity":
				afterIdentity = mark
			}
			report, verifyErr := candidate.verifyInertRestoreCandidateCancellationProbed(
				ctx, key, beforeInventory, beforePreflight, afterPreflight, afterIdentity)
			if hits != 1 || !errors.Is(verifyErr, ErrUnsafeInertRestoreCandidate) ||
				!reflect.DeepEqual(report, InertArchivePreflight{}) {
				t.Fatalf("cancelled Verify published receipt: phase=%s hits=%d err=%v report=%+v",
					phase, hits, verifyErr, report)
			}
			if candidate.dir == nil {
				t.Fatal("cancelled Verify closed caller-owned child flock fd")
			}
			atFD, err := candidate.dir.Stat()
			if err != nil || !os.SameFile(identity, atFD) {
				t.Fatalf("cancelled Verify lost original child inode: %v", err)
			}
			contender, busyErr := openLockedInertRestoreCandidate(scope)
			if contender != nil {
				_ = contender.Close()
			}
			if !errors.Is(busyErr, ErrInertRestoreCandidateBusy) {
				t.Fatalf("cancelled Verify released original flock: %v", busyErr)
			}
			next, err := candidate.Verify(context.Background(), key)
			if err != nil || !reflect.DeepEqual(next, healthy) {
				t.Fatalf("healthy Verify after cancelled operation degraded: %+v %v", next, err)
			}
			got, err := os.ReadFile(candidate.archive)
			if err != nil || !bytes.Equal(got, ciphertext) {
				t.Fatalf("cancelled Verify changed encrypted source: %v", err)
			}
		})
	}
}

// Cancellation before Verify begins must not enter even the first inventory
// checkpoint. Missing contexts and invalid keys also preserve the lease.
func TestVerifyRefusesInvalidOrAlreadyCancelledRequestBeforeInventory(t *testing.T) {
	_, candidate, key, ciphertext := borrowedCandidatePreflightFixture(t)
	scope := candidate.Directory()
	for _, phase := range []string{"nil_context", "cancelled_context", "empty_key"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			usedKey := key
			switch phase {
			case "nil_context":
				ctx = nil
			case "cancelled_context":
				cancelled, cancel := context.WithCancel(context.Background())
				cancel()
				ctx = cancelled
			case "empty_key":
				usedKey = [32]byte{}
			}
			called := false
			report, err := candidate.verifyInertRestoreCandidateCancellationProbed(
				ctx, usedKey, func() { called = true }, nil, nil, nil)
			if called || !errors.Is(err, ErrUnsafeInertRestoreCandidate) ||
				!reflect.DeepEqual(report, InertArchivePreflight{}) {
				t.Fatalf("invalid Verify request entered inventory: phase=%s called=%t err=%v",
					phase, called, err)
			}
			if _, err := candidate.dir.Stat(); err != nil {
				t.Fatalf("invalid Verify request released child lease: %v", err)
			}
			contender, busyErr := openLockedInertRestoreCandidate(scope)
			if contender != nil {
				_ = contender.Close()
			}
			if !errors.Is(busyErr, ErrInertRestoreCandidateBusy) {
				t.Fatalf("invalid Verify request released child flock: %v", busyErr)
			}
			if got, err := os.ReadFile(candidate.archive); err != nil ||
				!bytes.Equal(got, ciphertext) {
				t.Fatalf("invalid Verify request changed ciphertext: %v", err)
			}
		})
	}
	if report, err := candidate.Verify(context.Background(), key); err != nil ||
		!report.SQLiteLogicalVerified || report.RestoreReady || report.RestoreSupported {
		t.Fatalf("valid Verify after invalid requests degraded: %+v %v", report, err)
	}
}
