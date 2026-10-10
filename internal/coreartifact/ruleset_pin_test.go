package coreartifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func pinnedRuleSetFixture(t *testing.T) (string, string, []byte) {
	t.Helper()
	root := t.TempDir()
	store, err := NewStore(filepath.Join(root, "core"))
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"version":2,"rules":[{"domain":["example.org"]}]}`)
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	path, _, err := store.PutRuleSet(context.Background(), bytes.NewReader(content), want, "source")
	if err != nil {
		t.Fatal(err)
	}
	return path, want, content
}

func TestRuleSetPinKeepsOriginalFileAndRejectsPathReplacement(t *testing.T) {
	path, sha, content := pinnedRuleSetFixture(t)
	pin, err := PinRuleSet(path, sha)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if pin.Size() != int64(len(content)) || pin.Reverify(context.Background()) != nil {
		t.Fatal("verified artifact was not pinned correctly")
	}
	original := path + ".previous"
	if err := os.Rename(path, original); err != nil {
		t.Fatal(err)
	}
	// Even an identical digest under a DIFFERENT inode is not the resource
	// checked at the beginning of this operation.
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pin.Reverify(context.Background()); !errors.Is(err, ErrUnsafeRuleSetPath) {
		t.Fatalf("replaced path accepted despite held original inode: %v", err)
	}
	if err := VerifyRuleSet(path, sha); err != nil {
		t.Fatalf("fixture replacement no longer hashes correctly: %v", err)
	}
}

func TestRuleSetPinRejectsInPlaceMutationAndPathRemoval(t *testing.T) {
	path, sha, _ := pinnedRuleSetFixture(t)
	pin, err := PinRuleSet(path, sha)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pin.Reverify(context.Background()); !errors.Is(err, ErrRuleSetHashMismatch) {
		t.Fatalf("in-place change was not detected: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := pin.Reverify(context.Background()); !errors.Is(err, ErrUnsafeRuleSetPath) {
		t.Fatalf("unlinked held file accepted: %v", err)
	}
}

func TestRuleSetPinRejectsSymlinkAndWorldReadableArtifact(t *testing.T) {
	path, sha, _ := pinnedRuleSetFixture(t)
	link := filepath.Join(t.TempDir(), "bad.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := PinRuleSet(link, sha); !errors.Is(err, ErrUnsafeRuleSetPath) {
		t.Fatalf("pinned symlink: %v", err)
	}
	pin, err := PinRuleSet(path, sha)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pin.Reverify(context.Background()); !errors.Is(err, ErrUnsafeRuleSetPath) {
		t.Fatalf("unsafe permissions accepted: %v", err)
	}
}

func TestRuleSetPinCancellationCloseAndBadHashFailClosed(t *testing.T) {
	path, sha, _ := pinnedRuleSetFixture(t)
	badHash := sha256.Sum256([]byte("different"))
	if _, err := PinRuleSet(path, hex.EncodeToString(badHash[:])); !errors.Is(err, ErrRuleSetHashMismatch) {
		t.Fatalf("pin with wrong hash: %v", err)
	}
	pin, err := PinRuleSet(path, sha)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pin.Reverify(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled hash attempt: %v", err)
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pin.Reverify(context.Background()); !errors.Is(err, ErrUnsafeRuleSetPath) {
		t.Fatalf("closed descriptor remained usable: %v", err)
	}
}
