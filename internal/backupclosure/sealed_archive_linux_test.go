//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func testSealedKey(t *testing.T) [32]byte {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return key
}

func testSealedDir(t *testing.T, f *fixture) string {
	t.Helper()
	parent := filepath.Join(f.stateRoot, "sealed-archives")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return parent
}

func TestSealInertArchiveRoundtripAndPrivateCiphertext(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	parent := testSealedDir(t, f)
	path := filepath.Join(parent, "snapshot.ktbackup")
	key := testSealedKey(t)
	saved, err := closure.SealInertArchive(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Format != ManifestVersion || saved.InventorySHA256 != closure.InventorySHA256 ||
		saved.Bytes <= closure.Inventory.DatabaseBytes || len(saved.ArchiveSHA256) != 64 {
		t.Fatalf("unexpected internal encrypted archive receipt: %+v", saved)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(content)) != saved.Bytes ||
		bytes.Contains(content, []byte("token-DO-NOT-EXPOSE")) ||
		bytes.Contains(content, []byte(closure.InventoryJSON)) ||
		bytes.Contains(content, []byte(f.stateRoot)) {
		t.Fatal("sealed ciphertext contains cleartext inventory or private content")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive has unsafe permissions: %v %v", info, err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoBackupScopes(t, f)
	verified, err := VerifyInertArchive(context.Background(), path, key)
	if err != nil || verified != saved {
		t.Fatalf("offline archive verification mismatch: %+v %+v %v", verified, saved, err)
	}
	otherKey := testSealedKey(t)
	if _, err := VerifyInertArchive(context.Background(), path, otherKey); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("wrong encryption key was accepted")
	}
}

func TestSealInertArchiveRejectsTamperingTruncationAndTrailingData(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	parent := testSealedDir(t, f)
	key := testSealedKey(t)
	original := filepath.Join(parent, "original.ktbackup")
	if _, err := closure.SealInertArchive(context.Background(), original, key); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		name string
		edit func([]byte) []byte
	}{
		{"corrupt_header", func(b []byte) []byte { b[0] ^= 0x40; return b }},
		{"corrupt_ciphertext", func(b []byte) []byte { b[sealedArchiveHeaderBytes+50] ^= 0x40; return b }},
		{"corrupt_tag", func(b []byte) []byte { b[len(b)-1] ^= 0x40; return b }},
		{"truncate", func(b []byte) []byte { return b[:len(b)-33] }},
		{"append", func(b []byte) []byte { return append(b, 0xaa) }},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(parent, tc.name+".ktbackup")
			if err := os.WriteFile(path, tc.edit(bytes.Clone(content)), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyInertArchive(context.Background(), path, key); !errors.Is(err, ErrUnsafeSealedArchive) {
				t.Fatalf("modified sealed archive accepted: %v", err)
			}
		})
	}
}

func TestSealInertArchiveRefusesUnsafeFilesAndExistingDestination(t *testing.T) {
	f := newFixture(t)
	f.commit(t, false)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	parent := testSealedDir(t, f)
	key := testSealedKey(t)
	path := filepath.Join(parent, "new.ktbackup")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := closure.SealInertArchive(ctx, path, key); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled writer accepted: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled writer left a visible archive")
	}
	if _, err := closure.SealInertArchive(context.Background(), path, key); err != nil {
		t.Fatal(err)
	}
	if _, err := closure.SealInertArchive(context.Background(), path, key); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("existing archive was overwritten")
	}
	link := filepath.Join(parent, "symlink.ktbackup")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := closure.SealInertArchive(context.Background(), link, key); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("symlink destination was accepted")
	}
	if _, err := VerifyInertArchive(context.Background(), link, key); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("symlink source was accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyInertArchive(context.Background(), path, key); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("publicly readable archive was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyInertArchive(context.Background(), path, key); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("public directory was accepted")
	}
	if _, err := closure.SealInertArchive(context.Background(),
		filepath.Join(parent, "another.ktbackup"), key); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("writer accepted nonprivate parent")
	}
}

func TestSealInertArchiveRefusesWeakKeyAndUnsafePath(t *testing.T) {
	f := newFixture(t)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	parent := testSealedDir(t, f)
	path := filepath.Join(parent, "valid.ktbackup")
	if _, err := closure.SealInertArchive(context.Background(), path, [32]byte{}); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("zero key was accepted")
	}
	for _, bad := range []string{
		"relative.ktbackup",
		parent + "/../unsafe.ktbackup",
		filepath.Join(parent, "file.zip"),
		filepath.Join(parent, ".hidden.ktbackup"),
		filepath.Join(parent, "spaces are bad.ktbackup"),
	} {
		if _, err := closure.SealInertArchive(context.Background(), bad, testSealedKey(t)); !errors.Is(err, ErrUnsafeSealedArchive) {
			t.Fatalf("unsafe destination %q was accepted: %v", bad, err)
		}
	}
	var zero [32]byte
	if _, err := VerifyInertArchive(context.Background(), path, zero); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("zero key accepted by verifier")
	}
}

func TestSealedPlainBytesBudgetAndManifestConstraints(t *testing.T) {
	fixture := sampleInertInventory()
	for _, altered := range []func(*Inventory){
		func(i *Inventory) { i.DatabaseBytes = 0 },
		func(i *Inventory) { i.DatabaseBytes = storage.MaxDatabaseSnapshotBytes+1 },
		func(i *Inventory) { i.RestoreReady = true },
		func(i *Inventory) { i.RuleSets[0].Size = coreartifact.MaxRuleSetUploadBytes+1 },
	} {
		inv := fixture
		inv.RuleSets = append([]RuleDigest(nil), fixture.RuleSets...)
		altered(&inv)
		if _, err := sealedPlainBytes(inv, 200); !errors.Is(err, ErrUnsafeSealedArchive) {
			t.Fatal("unsafe manifest declared a valid archive size")
		}
	}
	for _, n := range []int{0, maxManifestBytes+1} {
		if _, err := sealedPlainBytes(fixture, n); !errors.Is(err, ErrUnsafeSealedArchive) {
			t.Fatal("manifest-length budget was ignored")
		}
	}
	if size, err := sealedPlainBytes(fixture, 200); err != nil || size != 4+200+4096+123 {
		t.Fatal("valid archive size was miscomputed")
	}
}

func TestSealedArchiveNoStrayTemporaryScopes(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	c, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	parent := testSealedDir(t, f)
	original := filepath.Join(parent, "exists.ktbackup")
	if err := os.WriteFile(original, []byte("already exists"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SealInertArchive(context.Background(), original, testSealedKey(t)); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("existing output unexpectedly accepted")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".ktbackup") {
		t.Fatalf("failed operation left temporary scopes: %+v %v", entries, err)
	}
}
