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

// The standalone Preflight is allowed to choose its initial archive inode.
// Stage is not: it owns an earlier file descriptor and must reject an
// identically encrypted REPLACEMENT inode before the first HMAC byte is read.
func TestPreflightExpectedSourceFileRejectsSameParentLeafSwapBeforeHMAC(t *testing.T) {
	_, parentPath, archive, key, ciphertext := newSealedVerifyParentFixture(t)
	parent, err := pinSealedArchiveReadParent(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	original, err := openSealedArchiveAtPinnedParent(archive, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	before, err := original.Stat()
	if err != nil {
		t.Fatal(err)
	}
	alternate := filepath.Join(parentPath, "same-valid-source.ktbackup")
	retained := filepath.Join(parentPath, "original-source-retained.ktbackup")
	if err := os.WriteFile(alternate, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.Lstat(alternate)
	if err != nil || os.SameFile(before, foreign) {
		t.Fatalf("expected distinct ciphertext inode: %v", err)
	}
	if err := os.WriteFile(filepath.Join(parentPath, "sentinel"), []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	injected := false
	var injectErr error
	report, err := preflightInertArchiveAtParentExpectedFileProbed(
		context.Background(), archive, key, nil, parent, original,
		func() {
			injected = true
			if injectErr = os.Rename(archive, retained); injectErr != nil {
				return
			}
			injectErr = os.Rename(alternate, archive)
		}, nil, nil)
	if !injected || injectErr != nil ||
		!errors.Is(err, ErrUnsafeSealedArchive) ||
		!reflect.DeepEqual(report, InertArchivePreflight{}) {
		t.Fatalf("expected-file Preflight accepted replacement inode: injected=%t mutation=%v report=%+v err=%v",
			injected, injectErr, report, err)
	}
	opened, err := original.Stat()
	if err != nil || !os.SameFile(before, opened) {
		t.Fatalf("failed Preflight closed original source fd: %v", err)
	}
	if !sameLeasedSealedArchiveParent(parentPath, parent) {
		t.Fatal("source parent fd was closed or replaced")
	}
	atRetained, err := os.Lstat(retained)
	if err != nil || !os.SameFile(before, atRetained) {
		t.Fatalf("original sealed source inode lost: %v", err)
	}
	atPath, err := os.Lstat(archive)
	if err != nil || !os.SameFile(foreign, atPath) {
		t.Fatalf("valid replacement source inode changed: %v", err)
	}
	for _, path := range []string{archive, retained} {
		data, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(data, ciphertext) {
			t.Fatalf("ciphertext changed during preflight refusal: %v", readErr)
		}
	}
	sentinel, err := os.ReadFile(filepath.Join(parentPath, "sentinel"))
	if err != nil || string(sentinel) != "unchanged" {
		t.Fatalf("unrelated sentinel changed: %v", err)
	}
	// The replacement remains an independently valid archive. Rejection is
	// based on inode custody, not a bad key or ciphertext digest.
	if replacement, err := PreflightInertArchive(context.Background(), archive, key, nil); err != nil ||
		!replacement.SQLiteLogicalVerified || replacement.RestoreReady {
		t.Fatalf("replacement was not a valid encrypted archive: %+v %v", replacement, err)
	}
}

// Borrowing the previously pinned Stage source FD does not transfer its
// ownership, mutate its read offset, or weaken full SQLite/HMAC checking.
func TestPreflightExpectedSourceFileHealthyAndWrongFDRefusal(t *testing.T) {
	_, parentPath, archive, key, ciphertext := newSealedVerifyParentFixture(t)
	parent, err := pinSealedArchiveReadParent(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	original, err := openSealedArchiveAtPinnedParent(archive, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	if _, err := original.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	expectedInfo, err := original.Stat()
	if err != nil {
		t.Fatal(err)
	}
	report, err := preflightInertArchiveAtParentExpectedFile(
		context.Background(), archive, key, nil, parent, original)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.RestoreReady || report.RestoreSupported {
		t.Fatalf("source-file-pinned Preflight failed: %+v %v", report, err)
	}
	standalone, err := PreflightInertArchive(context.Background(), archive, key, nil)
	if err != nil || !reflect.DeepEqual(report, standalone) {
		t.Fatalf("expected-file vs ordinary Preflight disagreement: %+v %v", standalone, err)
	}
	offset, err := original.Seek(0, io.SeekCurrent)
	if err != nil || offset != 7 {
		t.Fatalf("borrowed source FD seek offset modified: offset=%d err=%v", offset, err)
	}
	after, err := original.Stat()
	if err != nil || !os.SameFile(expectedInfo, after) {
		t.Fatalf("borrowed source file fd closed or redirected: %v", err)
	}

	other := filepath.Join(parentPath, "wrong-expected-source.ktbackup")
	if err := os.WriteFile(other, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	foreign, err := openSealedArchiveAtPinnedParent(other, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	rejected, err := preflightInertArchiveAtParentExpectedFile(
		context.Background(), archive, key, nil, parent, foreign)
	if !errors.Is(err, ErrUnsafeSealedArchive) ||
		!reflect.DeepEqual(rejected, InertArchivePreflight{}) {
		t.Fatalf("foreign caller-owned FD admitted: %+v %v", rejected, err)
	}
	if _, err := foreign.Stat(); err != nil {
		t.Fatalf("invalid expected file FD was closed: %v", err)
	}
}

// A failed first HMAC pass never grants a retained file lease and must
// preserve both the old original source FD and the borrowed parent FD.
func TestExpectedSourceVerifierNoRetainedFileOnReplacement(t *testing.T) {
	_, parentPath, archive, key, ciphertext := newSealedVerifyParentFixture(t)
	parent, err := pinSealedArchiveReadParent(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	original, err := openSealedArchiveAtPinnedParent(archive, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	alternate := filepath.Join(parentPath, "other-valid-source.ktbackup")
	moved := filepath.Join(parentPath, "first-source-moved.ktbackup")
	if err := os.WriteFile(alternate, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(archive, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(alternate, archive); err != nil {
		t.Fatal(err)
	}
	retained := parent // Must reset to nil on failed HMAC admission.
	_, err = verifyInertArchiveAtParentExpectedFileProbed(
		context.Background(), archive, key, parent, original, &retained, nil, nil)
	if !errors.Is(err, ErrUnsafeSealedArchive) || retained != nil {
		t.Fatalf("different original source inode accepted/retained: %v", err)
	}
	if _, err := original.Stat(); err != nil {
		t.Fatalf("original source descriptor unexpectedly closed: %v", err)
	}
	if _, err := parent.Stat(); err != nil {
		t.Fatalf("borrowed parent descriptor unexpectedly closed: %v", err)
	}
}

// The public Stage entrypoint must refuse same-private-parent substitution
// without creating a candidate and without touching either valid ciphertext.
func TestStageSourcePinRejectsIdenticalLeafBeforeFirstPreflight(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sourceDir := testSealedDir(t, f)
	source := filepath.Join(sourceDir, "original-stage-source.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	alternate := filepath.Join(sourceDir, "other-stage-source.ktbackup")
	retained := filepath.Join(sourceDir, "original-stage-retained.ktbackup")
	if err := os.WriteFile(alternate, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	candidateParent := newInertCandidateParent(t, f.stateRoot)
	injected := false
	var mutationErr error
	candidate, stageErr := stageInertRestoreCandidate(
		context.Background(), source, candidateParent, key, func(phase string) bool {
			if phase == "source_inode_pinned" {
				injected = true
				if mutationErr = os.Rename(source, retained); mutationErr != nil {
					return true
				}
				mutationErr = os.Rename(alternate, source)
			}
			return true
		})
	if candidate != nil {
		_ = candidate.Close()
	}
	if !injected || mutationErr != nil || candidate != nil ||
		!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Stage adopted different same-content source inode: injected=%t mutation=%v err=%v",
			injected, mutationErr, stageErr)
	}
	for _, path := range []string{source, retained} {
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, ciphertext) {
			t.Fatalf("stage refusal changed encrypted source: %v", err)
		}
	}
	entries, err := os.ReadDir(candidateParent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("stage created candidate after rejected source: entries=%v err=%v", entries, err)
	}
}
