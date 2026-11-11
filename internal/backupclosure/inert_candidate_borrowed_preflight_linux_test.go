//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func borrowedCandidatePreflightFixture(t *testing.T) (string, *InertRestoreCandidate, [32]byte, []byte) {
	t.Helper()
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closure.Close() })
	source := filepath.Join(testSealedDir(t, f), "borrowed-parent-source.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	candidate, err := StageInertRestoreCandidate(
		context.Background(), source, newInertCandidateParent(t, f.stateRoot), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = candidate.Close() })
	cipher, err := os.ReadFile(candidate.archive)
	if err != nil {
		t.Fatal(err)
	}
	return f.stateRoot, candidate, key, cipher
}

// Stage, Reopen and Verify reuse the already locked candidate inode for all
// authenticated passes. A borrowed preflight never closes its caller's flock.
func TestBorrowedCandidatePreflightPreservesFlockAndHealthyReceipt(t *testing.T) {
	_, candidate, key, _ := borrowedCandidatePreflightFixture(t)
	before, err := candidate.dir.Stat()
	if err != nil {
		t.Fatal(err)
	}
	borrowed, err := preflightInertArchiveAtParent(
		context.Background(), candidate.archive, key, nil, candidate.dir)
	if err != nil || !borrowed.SQLiteLogicalVerified ||
		!borrowed.SchemaCatalogVerified || borrowed.RestoreReady || borrowed.RestoreSupported {
		t.Fatalf("borrowed preflight failed or authorized restore: %+v %v", borrowed, err)
	}
	standalone, err := PreflightInertArchive(context.Background(), candidate.archive, key, nil)
	if err != nil || !reflect.DeepEqual(borrowed, standalone) {
		t.Fatalf("borrowed and standalone preflight disagree: %v", err)
	}
	after, err := candidate.dir.Stat()
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("borrowed preflight closed or changed candidate lease: %v", err)
	}
	if _, err := candidate.Verify(context.Background(), key); err != nil {
		t.Fatalf("borrowed Verify rejected healthy candidate: %v", err)
	}
	directory := candidate.Directory()
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := ReopenInertRestoreCandidate(context.Background(), directory, key)
	if err != nil {
		t.Fatalf("borrowed Reopen rejected healthy candidate: %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.Verify(context.Background(), key); err != nil {
		t.Fatalf("borrowed Verify after Reopen failed: %v", err)
	}
}

// Identically authenticated ciphertext under a different owner-private inode
// must not become the source of a previously flocked candidate Preflight.
func TestBorrowedCandidatePreflightRefusesReplacedScopeBeforeHMAC(t *testing.T) {
	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			root, candidate, key, cipher := borrowedCandidatePreflightFixture(t)
			scope := candidate.Directory()
			moved := filepath.Join(root, "original-borrowed-"+replacement)
			foreign := filepath.Join(root, "foreign-borrowed-"+replacement)
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, inertRestoreCipherName), cipher, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, "sentinel"), []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			original, err := candidate.dir.Stat()
			if err != nil {
				t.Fatal(err)
			}
			injected := false
			var mutationErr error
			report, preflightErr := preflightInertArchiveAtParentProbed(
				context.Background(), candidate.archive, key, nil, candidate.dir,
				func() {
					injected = true
					if mutationErr = os.Rename(scope, moved); mutationErr != nil {
						return
					}
					if replacement == "directory" {
						mutationErr = os.Rename(foreign, scope)
					} else {
						mutationErr = os.Symlink(foreign, scope)
					}
				}, nil, nil,
			)
			if !injected || mutationErr != nil ||
				!errors.Is(preflightErr, ErrUnsafeSealedArchive) ||
				!reflect.DeepEqual(report, InertArchivePreflight{}) {
				t.Fatalf("preflight adopted replaced scope: injected=%t mutation=%v err=%v report=%+v",
					injected, mutationErr, preflightErr, report)
			}
			stillOpen, err := candidate.dir.Stat()
			if err != nil || !os.SameFile(original, stillOpen) {
				t.Fatalf("refusal closed or redirected original flock fd: %v", err)
			}
			originalBytes, err := os.ReadFile(filepath.Join(moved, inertRestoreCipherName))
			if err != nil || !bytes.Equal(originalBytes, cipher) {
				t.Fatalf("original encrypted candidate modified: %v", err)
			}
			replacementBytes, err := os.ReadFile(filepath.Join(scope, inertRestoreCipherName))
			if err != nil || !bytes.Equal(replacementBytes, cipher) {
				t.Fatalf("identical foreign ciphertext modified: %v", err)
			}
			sentinel, err := os.ReadFile(filepath.Join(scope, "sentinel"))
			if err != nil || string(sentinel) != "keep" {
				t.Fatalf("foreign sentinel modified: %v", err)
			}
			if _, err := candidate.Verify(context.Background(), key); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("Verify accepted replaced candidate scope: %v", err)
			}
		})
	}
}

func TestBorrowedPreflightRejectsUnrelatedParentWithoutClosingFd(t *testing.T) {
	root, _, archive, key, encrypted := newSealedVerifyParentFixture(t)
	pinned, err := pinSealedArchiveReadParent(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	healthy, err := preflightInertArchiveAtParent(
		context.Background(), archive, key, nil, pinned)
	if err != nil || !healthy.SQLiteLogicalVerified || healthy.RestoreReady || healthy.RestoreSupported {
		t.Fatalf("borrowed source preflight changed behavior: %+v %v", healthy, err)
	}
	wrongPath := filepath.Join(root, "wrong-borrowed-parent")
	if err := os.Mkdir(wrongPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wrongPath, filepath.Base(archive)), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	wrong, err := pinSealedArchiveReadParent(filepath.Join(wrongPath, filepath.Base(archive)))
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	report, err := preflightInertArchiveAtParent(context.Background(), archive, key, nil, wrong)
	if !errors.Is(err, ErrUnsafeSealedArchive) || !reflect.DeepEqual(report, InertArchivePreflight{}) {
		t.Fatalf("unrelated borrowed directory authenticated: %+v %v", report, err)
	}
	if _, err := wrong.Stat(); err != nil {
		t.Fatalf("rejected parent fd was closed: %v", err)
	}
}
