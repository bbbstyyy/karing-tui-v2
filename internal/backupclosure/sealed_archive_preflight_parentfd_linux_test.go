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

// Complete HMAC verification cannot grant the next read permission to choose
// a different same-UID parent. A copy of the same VALID ciphertext has the
// same archive SHA and inventory, so the existing full-file hash alone
// cannot bind preflight to the original parent inode across all passes.
func TestPreflightInertArchiveRetainsParentAcrossAllThreeReads(t *testing.T) {
	for _, phase := range []string{"after-auth", "after-inventory"} {
		for _, replacement := range []string{"directory", "symlink"} {
			t.Run(phase+"_"+replacement, func(t *testing.T) {
				root, parent, archive, key, ciphertext := newSealedVerifyParentFixture(t)
				// Confirm the unmodified encrypted fixture and in-memory
				// SQLite preflight both pass before injecting namespace drift.
				if report, err := PreflightInertArchive(context.Background(), archive, key, nil); err != nil ||
					!report.SQLiteLogicalVerified || report.RestoreReady {
					t.Fatalf("healthy preflight rejected before mutation: report=%+v err=%v", report, err)
				}
				moved := filepath.Join(root, "moved-preflight-"+phase)
				foreign := filepath.Join(root, "foreign-preflight-"+phase)
				if err := os.Mkdir(foreign, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, filepath.Base(archive)), ciphertext, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, "sentinel"), []byte("unchanged"), 0o600); err != nil {
					t.Fatal(err)
				}
				injected := false
				var mutationErr error
				swap := func() {
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
				}
				var afterAuth, afterInventory func()
				if phase == "after-auth" {
					afterAuth = swap
				} else {
					afterInventory = swap
				}
				report, preflightErr := preflightInertArchiveProbed(
					context.Background(), archive, key, nil, afterAuth, afterInventory)
				if !injected || mutationErr != nil ||
					!errors.Is(preflightErr, ErrUnsafeSealedArchive) ||
					!reflect.DeepEqual(report, InertArchivePreflight{}) {
					t.Fatalf("preflight adopted foreign parent: injected=%t mutation=%v err=%v report=%+v",
						injected, mutationErr, preflightErr, report)
				}
				original, err := os.ReadFile(filepath.Join(moved, filepath.Base(archive)))
				if err != nil || !bytes.Equal(original, ciphertext) {
					t.Fatalf("original sealed archive changed: %v", err)
				}
				foreignDir := foreign
				if replacement == "directory" {
					foreignDir = parent
				}
				copyBytes, err := os.ReadFile(filepath.Join(foreignDir, filepath.Base(archive)))
				if err != nil || !bytes.Equal(copyBytes, ciphertext) {
					t.Fatalf("foreign identical archive modified: %v", err)
				}
				sentinel, err := os.ReadFile(filepath.Join(foreignDir, "sentinel"))
				if err != nil || string(sentinel) != "unchanged" {
					t.Fatalf("foreign parent sentinel modified: %v", err)
				}
			})
		}
	}
}

// Moving the SAME authenticated child inode under a new owner-private
// parent at the same path must not preserve the preflight lease. Both
// archive content and file fd/path can still match in this case.
func TestPreflightInertArchiveRejectsOriginalChildMovedUnderNewParent(t *testing.T) {
	root, parent, archive, key, original := newSealedVerifyParentFixture(t)
	moved := filepath.Join(root, "moved-preflight-original-child")
	before, err := os.Lstat(archive)
	if err != nil {
		t.Fatal(err)
	}
	injected := false
	var mutationErr error
	report, preflightErr := preflightInertArchiveProbed(
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
		}, nil,
	)
	if !injected || mutationErr != nil ||
		!errors.Is(preflightErr, ErrUnsafeSealedArchive) ||
		!reflect.DeepEqual(report, InertArchivePreflight{}) {
		t.Fatalf("accepted original child in substituted parent: injected=%t err=%v mutation=%v report=%+v",
			injected, preflightErr, mutationErr, report)
	}
	after, err := os.Lstat(archive)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("test failed to preserve authenticated archive inode: %v", err)
	}
	data, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatalf("preflight refusal changed archive: %v", err)
	}
	sentinel, err := os.ReadFile(filepath.Join(parent, "sentinel"))
	if err != nil || string(sentinel) != "keep" {
		t.Fatalf("replacement parent sentinel changed: %v", err)
	}
}
