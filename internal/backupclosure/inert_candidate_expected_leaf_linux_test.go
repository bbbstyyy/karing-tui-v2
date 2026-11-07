//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A complete preflight must authenticate the EXACT leaf inode inspected
// beneath the locked candidate before the first HMAC read, not a different
// same-name file containing byte-for-byte identical valid ciphertext.
func TestCandidateVerifyAndReopenRefuseSameParentLeafSwapBeforeHMAC(t *testing.T) {
	for _, operation := range []string{"verify", "reopen"} {
		t.Run(operation, func(t *testing.T) {
			root, candidate, key, originalBytes := borrowedCandidatePreflightFixture(t)
			directory := candidate.Directory()
			original, err := os.Lstat(candidate.archive)
			if err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(root, "original-"+operation+".ktbackup")
			substitute := filepath.Join(root, "substitute-"+operation+".ktbackup")
			sentinel := filepath.Join(root, "sentinel-"+operation)
			if err := os.WriteFile(substitute, originalBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			foreign, err := os.Lstat(substitute)
			if err != nil || os.SameFile(original, foreign) {
				t.Fatalf("replacement must have a different inode: %v", err)
			}
			if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			injected := false
			var mutationErr error
			swap := func() {
				injected = true
				mutationErr = os.Rename(candidate.archive, moved)
				if mutationErr != nil {
					return
				}
				mutationErr = os.Rename(substitute, candidate.archive)
			}

			var refused error
			if operation == "verify" {
				report, err := candidate.verifyInertRestoreCandidateProbed(
					context.Background(), key, swap)
				refused = err
				if !reflect.DeepEqual(report, InertArchivePreflight{}) {
					t.Fatalf("Verify returned a nonempty report after source swap: %+v", report)
				}
			} else {
				if err := candidate.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := reopenInertRestoreCandidateAtFileProbed(
					context.Background(), directory, key, nil, swap, nil)
				if reopened != nil {
					_ = reopened.Close()
					t.Fatal("Reopen adopted a replacement ciphertext file")
				}
				refused = err
			}
			if !injected || mutationErr != nil ||
				!errors.Is(refused, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("%s accepted a different valid file inode: injected=%t mutation=%v err=%v",
					operation, injected, mutationErr, refused)
			}
			retained, err := os.Lstat(moved)
			if err != nil || !os.SameFile(original, retained) {
				t.Fatalf("original candidate inode changed: %v", err)
			}
			atPath, err := os.Lstat(candidate.archive)
			if err != nil || !os.SameFile(foreign, atPath) {
				t.Fatalf("replacement candidate inode modified: %v", err)
			}
			for _, path := range []string{moved, candidate.archive} {
				data, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(data, originalBytes) {
					t.Fatalf("candidate rejection damaged valid ciphertext: %v", err)
				}
			}
			unchanged, err := os.ReadFile(sentinel)
			if err != nil || string(unchanged) != "preserve" {
				t.Fatalf("unrelated sentinel modified: %v", err)
			}
			// The replacement really is valid ciphertext. Fresh standalone
			// preflight accepts it; rejection above is the inode lease check.
			report, err := PreflightInertArchive(context.Background(), candidate.archive, key, nil)
			if err != nil || !report.SQLiteLogicalVerified || report.RestoreReady ||
				report.RestoreSupported {
				t.Fatalf("replacement was not valid ciphertext: %+v %v", report, err)
			}
		})
	}
}

// A sibling file can replace the inspected inode between file inventory
// and the pinned open. Reject before authentication, without closing the
// locked directory or deleting the foreign inode.
func TestCandidatePinRejectsLeafReplacedSinceInspection(t *testing.T) {
	root, candidate, _, ciphertext := borrowedCandidatePreflightFixture(t)
	before, err := inspectInertCandidateFile(candidate, false)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "inspected-original.ktbackup")
	replacement := filepath.Join(root, "inspected-replacement.ktbackup")
	if err := os.WriteFile(replacement, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(candidate.archive, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, candidate.archive); err != nil {
		t.Fatal(err)
	}
	pinned, err := pinInspectedInertCandidateCipher(candidate, before)
	if pinned != nil {
		_ = pinned.Close()
	}
	if pinned != nil || !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("inspection adopted different file inode: %v", err)
	}
	if _, err := candidate.dir.Stat(); err != nil {
		t.Fatalf("file-pin refusal closed candidate flock fd: %v", err)
	}
	for _, path := range []string{moved, candidate.archive} {
		bytesAtPath, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(bytesAtPath, ciphertext) {
			t.Fatalf("inspection refusal modified ciphertext: %v", err)
		}
	}
}

func TestCandidatePinnedLeafHealthyLifetimeAndReadOffset(t *testing.T) {
	_, candidate, key, _ := borrowedCandidatePreflightFixture(t)
	before, err := inspectInertCandidateFile(candidate, false)
	if err != nil {
		t.Fatal(err)
	}
	original, err := pinInspectedInertCandidateCipher(candidate, before)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	if _, err := original.Seek(11, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	report, err := preflightInertArchiveAtParentExpectedFile(
		context.Background(), candidate.archive, key, nil, candidate.dir, original)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.RestoreSupported || report.RestoreReady {
		t.Fatalf("healthy original-file preflight failed: %+v %v", report, err)
	}
	at, err := original.Seek(0, io.SeekCurrent)
	if err != nil || at != 11 {
		t.Fatalf("borrowed candidate source FD offset modified: %d %v", at, err)
	}
	verified, err := candidate.Verify(context.Background(), key)
	if err != nil || !reflect.DeepEqual(verified, report) {
		t.Fatalf("held Verify changed preflight report: %+v %v", verified, err)
	}
	directory := candidate.Directory()
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := ReopenInertRestoreCandidate(context.Background(), directory, key)
	if err != nil {
		t.Fatalf("healthy candidate Reopen failed: %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.Verify(context.Background(), key); err != nil {
		t.Fatalf("healthy candidate Verify after Reopen failed: %v", err)
	}
}
