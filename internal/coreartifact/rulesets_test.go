package coreartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageRuleSetPublishesContentAddressedPrivateCopy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}

	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "china.srs")
	content := []byte("rule-set-binary-fixture")
	if err := os.WriteFile(source, content, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256Hex(content)

	path, err := store.StageRuleSet(context.Background(), source, hash)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "rule-sets", "sha256", hash+".srs")
	if path != want {
		t.Fatalf("staged path = %q, want %q", path, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("staged rule-set mode = %04o, want 0600", got)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("staged content = %q, want %q", got, content)
	}
	if err := VerifyRuleSet(path, hash); err != nil {
		t.Fatal(err)
	}

	again, err := store.StageRuleSet(context.Background(), source, strings.ToUpper(hash))
	if err != nil {
		t.Fatal(err)
	}
	if again != path {
		t.Fatalf("idempotent staged path = %q, want %q", again, path)
	}
}

func TestStageRuleSetSupportsSourceJSON(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "rules.json")
	content := []byte(`{"version":4,"rules":[]}`)
	if err := os.WriteFile(source, content, 0o444); err != nil {
		t.Fatal(err)
	}
	hash := sha256Hex(content)
	path, err := store.StageRuleSet(context.Background(), source, hash)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(path) != ".json" {
		t.Fatalf("staged extension = %q, want .json", filepath.Ext(path))
	}
}

func TestStageRuleSetRejectsWrongHashWithoutPublishing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "rules.srs")
	if err := os.WriteFile(source, []byte("actual"), 0o644); err != nil {
		t.Fatal(err)
	}
	expected := sha256Hex([]byte("expected"))
	if _, err := store.StageRuleSet(context.Background(), source, expected); !errors.Is(err, ErrRuleSetHashMismatch) {
		t.Fatalf("hash mismatch error = %v", err)
	}
	destination := filepath.Join(root, "rule-sets", "sha256", expected+".srs")
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched rule-set unexpectedly published: %v", err)
	}
}

func TestStageRuleSetRejectsSymlinkAndUnsupportedExtension(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.srs")
	content := []byte("fixture")
	if err := os.WriteFile(target, content, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.srs")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageRuleSet(context.Background(), link, sha256Hex(content)); !errors.Is(err, ErrUnsafeRuleSetPath) {
		t.Fatalf("symlink source error = %v", err)
	}

	txt := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(txt, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageRuleSet(context.Background(), txt, sha256Hex(content)); !errors.Is(err, ErrRuleSetExtension) {
		t.Fatalf("unsupported extension error = %v", err)
	}
}

func TestVerifyRuleSetRejectsMutablePrivateCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.srs")
	content := []byte("fixture")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRuleSet(path, sha256Hex(content)); !errors.Is(err, ErrUnsafeRuleSetPath) {
		t.Fatalf("permissive staged file error = %v", err)
	}
}

func TestStageRuleSetRejectsMutatedExistingContentAddress(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "rules.srs")
	content := []byte("fixture")
	if err := os.WriteFile(source, content, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256Hex(content)
	path, err := store.StageRuleSet(context.Background(), source, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageRuleSet(context.Background(), source, hash); !errors.Is(err, ErrRuleSetImmutable) {
		t.Fatalf("mutated content-address error = %v", err)
	}
}

func TestStageRuleSetHonorsCanceledContext(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "rules.srs")
	content := []byte("fixture")
	if err := os.WriteFile(source, content, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.StageRuleSet(ctx, source, sha256Hex(content)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled staging error = %v", err)
	}
}

func TestVerifyRuleSetRequiresCleanAbsolutePath(t *testing.T) {
	hash := hex.EncodeToString(make([]byte, sha256.Size))
	if err := VerifyRuleSet("relative.srs", hash); !errors.Is(err, ErrUnsafeRuleSetPath) {
		t.Fatalf("relative path error = %v", err)
	}
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
