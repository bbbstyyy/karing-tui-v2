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

// Verify's entire HMAC and resource digest pass must use the parent inode
// already captured by Preflight, never a second unrelated name-based open.
// The foreign parent holds an EXACT valid encrypted copy: cryptographic
// equality by itself must not change the allowed source directory inode.
func TestSealedPreflightFirstHMACRejectsSubstitutedParent(t *testing.T) {
	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			root, parent, archive, key, encrypted := newSealedVerifyParentFixture(t)
			moved := filepath.Join(root, "moved-before-hmac")
			foreign := filepath.Join(root, "foreign-before-hmac")
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, filepath.Base(archive)), encrypted, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, "sentinel"), []byte("safe"), 0o600); err != nil {
				t.Fatal(err)
			}
			injected := false
			var mutationErr error
			report, err := preflightInertArchiveBeforeVerifyProbed(
				context.Background(), archive, key, nil,
				func() {
					injected = true
					mutationErr = os.Rename(parent, moved)
					if mutationErr != nil {
						return
					}
					if replacement == "directory" {
						mutationErr = os.Rename(foreign, parent)
					} else {
						mutationErr = os.Symlink(foreign, parent)
					}
				}, nil, nil,
			)
			if !injected || mutationErr != nil ||
				!errors.Is(err, ErrUnsafeSealedArchive) ||
				!reflect.DeepEqual(report, InertArchivePreflight{}) {
				t.Fatalf("preflight authenticated substituted parent: injected=%t mutation=%v report=%+v err=%v",
					injected, mutationErr, report, err)
			}
			actualOriginal, readErr := os.ReadFile(filepath.Join(moved, filepath.Base(archive)))
			if readErr != nil || !bytes.Equal(actualOriginal, encrypted) {
				t.Fatalf("original ciphertext modified: %v", readErr)
			}
			substituted := foreign
			if replacement == "directory" {
				substituted = parent
			}
			actualForeign, readErr := os.ReadFile(filepath.Join(substituted, filepath.Base(archive)))
			if readErr != nil || !bytes.Equal(actualForeign, encrypted) {
				t.Fatalf("foreign authenticated copy modified: %v", readErr)
			}
			sentinel, readErr := os.ReadFile(filepath.Join(substituted, "sentinel"))
			if readErr != nil || string(sentinel) != "safe" {
				t.Fatalf("foreign sentinel modified: %v", readErr)
			}
		})
	}
}

func TestSealedPreflightFirstHMACRejectsSameChildMovedToOtherParent(t *testing.T) {
	root, parent, archive, key, encrypted := newSealedVerifyParentFixture(t)
	moved := filepath.Join(root, "moved-original-hmac-parent")
	original, err := os.Lstat(archive)
	if err != nil {
		t.Fatal(err)
	}
	injected := false
	var mutationErr error
	report, err := preflightInertArchiveBeforeVerifyProbed(
		context.Background(), archive, key, nil,
		func() {
			injected = true
			mutationErr = os.Rename(parent, moved)
			if mutationErr != nil {
				return
			}
			mutationErr = os.Mkdir(parent, 0o700)
			if mutationErr != nil {
				return
			}
			mutationErr = os.Rename(filepath.Join(moved, filepath.Base(archive)), archive)
			if mutationErr != nil {
				return
			}
			mutationErr = os.WriteFile(filepath.Join(parent, "sentinel"), []byte("keep"), 0o600)
		}, nil, nil,
	)
	if !injected || mutationErr != nil ||
		!errors.Is(err, ErrUnsafeSealedArchive) ||
		!reflect.DeepEqual(report, InertArchivePreflight{}) {
		t.Fatalf("preflight accepted same child inode under new parent: injected=%t mutation=%v report=%+v err=%v",
			injected, mutationErr, report, err)
	}
	after, err := os.Lstat(archive)
	if err != nil || !os.SameFile(original, after) {
		t.Fatalf("source test inode changed: %v", err)
	}
	data, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(data, encrypted) {
		t.Fatalf("original encrypted file modified: %v", err)
	}
	sentinel, err := os.ReadFile(filepath.Join(parent, "sentinel"))
	if err != nil || string(sentinel) != "keep" {
		t.Fatalf("replacement parent sentinel modified: %v", err)
	}
}

// On a healthy private parent the caller-owned parent fd can be reused
// without changing the public HMAC receipt or the full SQLite preflight.
// An fd for a DIFFERENT owner-private parent cannot be supplied, even if
// that directory contains a byte-identical encrypted archive.
func TestSealedVerifyWithCallerPinnedParentMatchesPublicAndRejectsDifferentParent(t *testing.T) {
	root, parentPath, archive, key, encrypted := newSealedVerifyParentFixture(t)
	parent, err := pinSealedArchiveReadParent(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	before, err := parent.Stat()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyInertArchiveAtParentProbed(context.Background(), archive, key, parent, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	public, err := VerifyInertArchive(context.Background(), archive, key)
	if err != nil || verified != public {
		t.Fatalf("pinned and standalone Verify disagree: pinned=%+v public=%+v err=%v",
			verified, public, err)
	}
	report, err := PreflightInertArchive(context.Background(), archive, key, nil)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.ArchiveSHA256 != verified.ArchiveSHA256 ||
		report.RestoreReady || report.RestoreSupported {
		t.Fatalf("shared-parent Preflight changed healthy receipt or restored authority: %+v %v", report, err)
	}
	after, err := parent.Stat()
	if err != nil || !os.SameFile(before, after) ||
		!sameLeasedSealedArchiveParent(parentPath, parent) {
		t.Fatalf("Verify consumed/changed caller-owned parent fd: %v", err)
	}
	other := filepath.Join(root, "unrelated-parent")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	otherArchive := filepath.Join(other, filepath.Base(archive))
	if err := os.WriteFile(otherArchive, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyInertArchiveAtParentProbed(context.Background(), otherArchive, key,
		parent, nil, nil); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatalf("Verify accepted caller-owned parent fd from a different directory: %v", err)
	}
	if !sameLeasedSealedArchiveParent(parentPath, parent) {
		t.Fatal("rejected mismatch closed or invalidated the caller-owned fd")
	}
}
