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

func newSealedVerifyParentFixture(t *testing.T) (string, string, string, [32]byte, []byte) {
	t.Helper()
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closure.Close() })
	parent := testSealedDir(t, f)
	destination := filepath.Join(parent, "verified-parent.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), destination, key); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyInertArchive(context.Background(), destination, key); err != nil {
		t.Fatalf("healthy sealed archive failed verification: %v", err)
	}
	return f.stateRoot, parent, destination, key, ciphertext
}

// Even if the substituted 0700 parent contains a byte-for-byte copy of
// the correct authenticated ciphertext, Verify must not adopt the archive
// from a directory never covered by the initially validated parent fd.
func TestSealedVerifyOpenatRejectsCopiedCiphertextInSubstitutedParent(t *testing.T) {
	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			root, parent, archive, key, ciphertext := newSealedVerifyParentFixture(t)
			moved := filepath.Join(root, "moved-verify-parent")
			foreign := filepath.Join(root, "foreign-verify-parent")
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, filepath.Base(archive)), ciphertext, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, "sentinel"), []byte("intact"), 0o600); err != nil {
				t.Fatal(err)
			}
			injected := false
			var mutationErr error
			receipt, verifyErr := verifyInertArchiveProbed(
				context.Background(), archive, key,
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
				}, nil,
			)
			if !injected || mutationErr != nil ||
				!errors.Is(verifyErr, ErrUnsafeSealedArchive) ||
				receipt != (SealedArchiveReceipt{}) {
				t.Fatalf("verified foreign ciphertext after parent swap: injected=%t mutation=%v err=%v receipt=%+v",
					injected, mutationErr, verifyErr, receipt)
			}
			original, err := os.ReadFile(filepath.Join(moved, filepath.Base(archive)))
			if err != nil || !bytes.Equal(original, ciphertext) {
				t.Fatalf("original sealed archive modified: %v", err)
			}
			foreignPath := foreign
			if replacement == "directory" {
				foreignPath = parent
			}
			copyBytes, err := os.ReadFile(filepath.Join(foreignPath, filepath.Base(archive)))
			if err != nil || !bytes.Equal(copyBytes, ciphertext) {
				t.Fatalf("copied foreign ciphertext modified: %v", err)
			}
			sentinel, err := os.ReadFile(filepath.Join(foreignPath, "sentinel"))
			if err != nil || string(sentinel) != "intact" {
				t.Fatalf("foreign private parent modified: %v", err)
			}
		})
	}
}

// After complete HMAC authentication a same-UID actor can move the exact
// original archive inode into a new 0700 directory at the same canonical
// pathname. The original file fd and path inode checks alone would pass;
// the parent lease must still reject the change of custody.
func TestSealedVerifyRejectsSameArchiveInodeMovedAfterAuthentication(t *testing.T) {
	root, parent, archive, key, ciphertext := newSealedVerifyParentFixture(t)
	moved := filepath.Join(root, "moved-after-auth-parent")
	before, err := os.Lstat(archive)
	if err != nil {
		t.Fatal(err)
	}
	injected := false
	var mutationErr error
	receipt, verifyErr := verifyInertArchiveProbed(
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
		},
	)
	if !injected || mutationErr != nil ||
		!errors.Is(verifyErr, ErrUnsafeSealedArchive) ||
		receipt != (SealedArchiveReceipt{}) {
		t.Fatalf("same archive inode under changed parent accepted: injected=%t mutation=%v err=%v receipt=%+v",
			injected, mutationErr, verifyErr, receipt)
	}
	after, err := os.Lstat(archive)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("test must preserve original archive inode: %v", err)
	}
	data, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(data, ciphertext) {
		t.Fatalf("authentication refusal changed ciphertext: %v", err)
	}
	sentinel, err := os.ReadFile(filepath.Join(parent, "sentinel"))
	if err != nil || string(sentinel) != "keep" {
		t.Fatalf("replacement parent sentinel modified: %v", err)
	}
}
