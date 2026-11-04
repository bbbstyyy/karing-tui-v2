//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Discard must not delete an unrelated same-name inode that replaces the
// encrypted file AFTER its inventory and exact file fd are pinned, even
// when the new ciphertext is byte-identical and fully authenticated.
func TestExplicitDiscardRejectsSameDirectoryIdenticalCipherSwapBeforeUnlink(t *testing.T) {
	root, candidate, key, ciphertext := borrowedCandidatePreflightFixture(t)
	original, err := os.Lstat(candidate.archive)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "original-explicit-discard.ktbackup")
	foreignPath := filepath.Join(root, "foreign-explicit-discard.ktbackup")
	sentinel := filepath.Join(root, "discard-foreign-sentinel")
	if err := os.WriteFile(foreignPath, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.Lstat(foreignPath)
	if err != nil || os.SameFile(original, foreign) {
		t.Fatalf("expected distinct valid ciphertext inode: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	scope := candidate.Directory()
	injected := false
	var mutationErr error
	discardErr := candidate.discardLockedBeforeCipherUnlinkProbed(true, func() {
		injected = true
		if mutationErr = os.Rename(candidate.archive, moved); mutationErr != nil {
			return
		}
		mutationErr = os.Rename(foreignPath, candidate.archive)
	})
	if !injected || mutationErr != nil ||
		!errors.Is(discardErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("explicit Discard unlinked replacement: injected=%t mutation=%v err=%v",
			injected, mutationErr, discardErr)
	}
	// Refusal releases the active lease, but never discards either inode,
	// changes ciphertext or deletes the private scope.
	if candidate.dir != nil {
		t.Fatal("failed explicit Discard did not release its directory fd")
	}
	if info, err := os.Stat(scope); err != nil || !info.IsDir() {
		t.Fatalf("failed explicit Discard deleted the candidate scope: %v", err)
	}
	oldAtPath, err := os.Lstat(moved)
	if err != nil || !os.SameFile(original, oldAtPath) {
		t.Fatalf("original candidate inode removed or replaced: %v", err)
	}
	substitute, err := os.Lstat(candidate.archive)
	if err != nil || !os.SameFile(foreign, substitute) ||
		os.SameFile(oldAtPath, substitute) {
		t.Fatalf("foreign candidate inode removed or replaced: %v", err)
	}
	for _, path := range []string{candidate.archive, moved} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, ciphertext) {
			t.Fatalf("explicit Discard modified encrypted bytes at %q: %v",
				filepath.Base(path), err)
		}
	}
	preserved, err := os.ReadFile(sentinel)
	if err != nil || string(preserved) != "keep" {
		t.Fatalf("foreign sentinel modified: %v", err)
	}
	// The replacement is independently valid encrypted ciphertext. The
	// refusal is inode custody, not a failed HMAC or wrong symmetric key.
	receipt, err := PreflightInertArchive(context.Background(), candidate.archive, key, nil)
	if err != nil || !receipt.SQLiteLogicalVerified || !receipt.SchemaCatalogVerified ||
		receipt.RestoreSupported || receipt.RestoreReady {
		t.Fatalf("substitute ciphertext unexpectedly invalid: %+v %v", receipt, err)
	}
}

// Changing only metadata in place also breaks the original inspection
// snapshot. The exact held fd cannot silently become authority for a
// modified leaf between inventory and the destructive unlinkat.
func TestExplicitDiscardRejectsMetadataMutationBeforeUnlink(t *testing.T) {
	_, candidate, _, ciphertext := borrowedCandidatePreflightFixture(t)
	before, err := os.Lstat(candidate.archive)
	if err != nil {
		t.Fatal(err)
	}
	injected := false
	var mutationErr error
	err = candidate.discardLockedBeforeCipherUnlinkProbed(true, func() {
		injected = true
		past := before.ModTime().Add(-4 * time.Hour)
		mutationErr = os.Chtimes(candidate.archive, past, past)
	})
	if !injected || mutationErr != nil ||
		!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Discard accepted metadata-changed leaf: injected=%t mutation=%v err=%v",
			injected, mutationErr, err)
	}
	after, err := os.Lstat(candidate.archive)
	if err != nil || !os.SameFile(before, after) ||
		before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("metadata mutation did not preserve the same different-mtime inode: %v", err)
	}
	got, err := os.ReadFile(candidate.archive)
	if err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatalf("metadata-changed ciphertext was deleted or modified: %v", err)
	}
	if candidate.dir != nil {
		t.Fatal("refused Discard failed to close the directory lease")
	}
}

// A healthy explicit Discard still removes its precisely inspected original
// ciphertext and the empty locked child scope; this remains a manual action.
func TestExplicitDiscardWithPinnedCipherHealthyLifecycle(t *testing.T) {
	_, candidate, key, _ := borrowedCandidatePreflightFixture(t)
	receipt, err := candidate.Verify(context.Background(), key)
	if err != nil || !receipt.SQLiteLogicalVerified || receipt.RestoreSupported ||
		receipt.RestoreReady {
		t.Fatalf("healthy candidate verification failed: %+v %v", receipt, err)
	}
	dir := candidate.Directory()
	parent := candidate.parent
	if err := candidate.Discard(context.Background()); err != nil {
		t.Fatalf("healthy explicit Discard refused own ciphertext: %v", err)
	}
	if candidate.dir != nil {
		t.Fatal("completed Discard did not release held flock")
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("discarded candidate scope still exists: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("manual Discard left candidate entries: %v %v", entries, err)
	}
}
