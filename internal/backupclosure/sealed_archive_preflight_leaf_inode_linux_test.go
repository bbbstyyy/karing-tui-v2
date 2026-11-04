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

// Cryptographic equality is not directory-entry identity. Replacing only the
// archive leaf inside its ORIGINAL private parent after HMAC or inventory
// creates a different valid inode with exactly the same SHA and MAC. Full
// Preflight must refuse it rather than selecting a new file for a later pass.
func TestSealedPreflightRejectsIdenticalLeafReplacementBetweenPasses(t *testing.T) {
	for _, phase := range []string{"after_hmac", "after_inventory"} {
		for _, borrowed := range []bool{false, true} {
			name := phase + "_standalone"
			if borrowed {
				name = phase + "_borrowed_parent"
			}
			t.Run(name, func(t *testing.T) {
				_, parentPath, archive, key, authenticated := newSealedVerifyParentFixture(t)
				before, err := os.Lstat(archive)
				if err != nil {
					t.Fatal(err)
				}
				if healthy, err := PreflightInertArchive(context.Background(), archive, key, nil); err != nil ||
					!healthy.SQLiteLogicalVerified || !healthy.SchemaCatalogVerified ||
					healthy.RestoreSupported || healthy.RestoreReady {
					t.Fatalf("healthy fixture failed before injection: %+v %v", healthy, err)
				}

				moved := filepath.Join(parentPath, "original-retained.ktbackup")
				alternate := filepath.Join(parentPath, "same-bytes-alternate.ktbackup")
				if err := os.WriteFile(alternate, authenticated, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(parentPath, "sentinel"), []byte("preserved"), 0o600); err != nil {
					t.Fatal(err)
				}
				altInfo, err := os.Lstat(alternate)
				if err != nil || os.SameFile(before, altInfo) {
					t.Fatalf("test requires a distinct regular alternate inode: %v", err)
				}

				injected := false
				var mutationErr error
				swap := func() {
					injected = true
					mutationErr = os.Rename(archive, moved)
					if mutationErr != nil {
						return
					}
					mutationErr = os.Rename(alternate, archive)
				}
				var afterAuth, afterInventory func()
				if phase == "after_hmac" {
					afterAuth = swap
				} else {
					afterInventory = swap
				}

				var report InertArchivePreflight
				var preflightErr error
				if borrowed {
					parent, err := pinSealedArchiveReadParent(archive)
					if err != nil {
						t.Fatal(err)
					}
					defer parent.Close()
					parentInfo, err := parent.Stat()
					if err != nil {
						t.Fatal(err)
					}
					report, preflightErr = preflightInertArchiveAtParentProbed(
						context.Background(), archive, key, nil, parent, nil, afterAuth, afterInventory)
					after, err := parent.Stat()
					if err != nil || !os.SameFile(parentInfo, after) ||
						!sameLeasedSealedArchiveParent(parentPath, parent) {
						t.Fatalf("borrowed parent fd was closed or replaced: %v", err)
					}
				} else {
					report, preflightErr = preflightInertArchiveProbed(
						context.Background(), archive, key, nil, afterAuth, afterInventory)
				}
				if !injected || mutationErr != nil ||
					!errors.Is(preflightErr, ErrUnsafeSealedArchive) ||
					!reflect.DeepEqual(report, InertArchivePreflight{}) {
					t.Fatalf("preflight adopted same-byte replacement: phase=%s borrowed=%t injected=%t mutation=%v err=%v report=%+v",
						phase, borrowed, injected, mutationErr, preflightErr, report)
				}

				oldInfo, err := os.Lstat(moved)
				if err != nil || !os.SameFile(before, oldInfo) {
					t.Fatalf("original authenticated inode was lost: %v", err)
				}
				newInfo, err := os.Lstat(archive)
				if err != nil || !os.SameFile(altInfo, newInfo) ||
					os.SameFile(oldInfo, newInfo) {
					t.Fatalf("replacement archive inode changed: %v", err)
				}
				originalData, err := os.ReadFile(moved)
				if err != nil || !bytes.Equal(originalData, authenticated) {
					t.Fatalf("original ciphertext changed: %v", err)
				}
				replacementData, err := os.ReadFile(archive)
				if err != nil || !bytes.Equal(replacementData, authenticated) {
					t.Fatalf("foreign authenticated ciphertext changed: %v", err)
				}
				sentinel, err := os.ReadFile(filepath.Join(parentPath, "sentinel"))
				if err != nil || string(sentinel) != "preserved" {
					t.Fatalf("unrelated sentinel changed: %v", err)
				}
			})
		}
	}
}

// Only a successful full HMAC verification may transfer an owned leaf fd
// to the full preflight. Failed authentication must leave no retained pin.
func TestSealedPreflightHMACFilePinTransfersOnlyOnSuccess(t *testing.T) {
	_, _, archive, key, _ := newSealedVerifyParentFixture(t)
	parent, err := pinSealedArchiveReadParent(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	var pinned *os.File
	receipt, err := verifyInertArchiveAtParentPinnedFileProbed(
		context.Background(), archive, key, parent, &pinned, nil, nil)
	if err != nil || pinned == nil {
		t.Fatalf("successful HMAC did not retain its exact file fd: %v", err)
	}
	if !samePinnedSealedPreflightFile(archive, parent, pinned, pinned, receipt.Bytes) {
		t.Fatal("healthy authenticated pin failed identity validation")
	}
	if err := pinned.Close(); err != nil {
		t.Fatal(err)
	}

	badKey := key
	badKey[0] ^= 0xff
	pinned = parent // Must be reset even when authentication fails.
	_, err = verifyInertArchiveAtParentPinnedFileProbed(
		context.Background(), archive, badKey, parent, &pinned, nil, nil)
	if !errors.Is(err, ErrUnsafeSealedArchive) || pinned != nil {
		t.Fatalf("failed HMAC leaked a file fd or accepted wrong key: %v", err)
	}
	if _, err := parent.Stat(); err != nil {
		t.Fatalf("failed HMAC closed caller-owned parent fd: %v", err)
	}
}
