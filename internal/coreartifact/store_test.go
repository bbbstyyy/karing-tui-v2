package coreartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreStagesImmutablePrivateGeneration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"inbounds":[]}`)
	sum := sha256.Sum256(config)
	hash := hex.EncodeToString(sum[:])

	path, err := store.Stage(context.Background(), 7, config, hash)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := path, filepath.Join(root, "generations", "7", "config.json"); got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("generation dir mode = %04o, want 0700", got)
	}

	if _, err := store.Stage(context.Background(), 7, config, hash); err != nil {
		t.Fatalf("staging identical immutable config failed: %v", err)
	}

	changed := []byte(`{"inbounds":[{"type":"mixed"}]}`)
	changedSum := sha256.Sum256(changed)
	_, err = store.Stage(context.Background(), 7, changed, hex.EncodeToString(changedSum[:]))
	if !errors.Is(err, ErrGenerationImmutable) {
		t.Fatalf("changed immutable generation error = %v", err)
	}
}

func TestStoreRejectsHashMismatchAndSymlinkGeneration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{}`)
	sum := sha256.Sum256([]byte("other"))
	if _, err := store.Stage(context.Background(), 1, config, hex.EncodeToString(sum[:])); !errors.Is(err, ErrConfigHashMismatch) {
		t.Fatalf("hash mismatch error = %v", err)
	}

	if err := os.MkdirAll(filepath.Join(root, "generations"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "generations", "2")); err != nil {
		t.Fatal(err)
	}
	sum = sha256.Sum256(config)
	if _, err := store.Stage(context.Background(), 2, config, hex.EncodeToString(sum[:])); !errors.Is(err, ErrUnsafeGenerationPath) {
		t.Fatalf("symlink generation error = %v", err)
	}
}

func TestStoreHonorsCanceledContext(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{}`)
	sum := sha256.Sum256(config)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Stage(ctx, 1, config, hex.EncodeToString(sum[:])); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stage error = %v", err)
	}
}

func TestStoreRejectsPermissiveExistingGenerationDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	generationDir := filepath.Join(root, "generations", "3")
	if err := os.MkdirAll(generationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(generationDir, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{}`)
	sum := sha256.Sum256(config)
	if _, err := store.Stage(context.Background(), 3, config, hex.EncodeToString(sum[:])); !errors.Is(err, ErrUnsafeGenerationPath) {
		t.Fatalf("permissive generation directory error = %v", err)
	}
}

func TestVerifyGenerationConfigRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	content := []byte(`{}`)
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if err := VerifyGenerationConfig(link, hex.EncodeToString(sum[:])); !errors.Is(err, ErrUnsafeGenerationPath) {
		t.Fatalf("symlink generation config error = %v", err)
	}
}

func TestVerifyGenerationConfigRejectsPermissiveMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := []byte(`{}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if err := VerifyGenerationConfig(path, hex.EncodeToString(sum[:])); !errors.Is(err, ErrUnsafeGenerationPath) {
		t.Fatalf("permissive config error = %v", err)
	}
}

func TestVerifyGenerationConfigRequiresAbsolutePath(t *testing.T) {
	sum := sha256.Sum256(nil)
	if err := VerifyGenerationConfig("config.json", hex.EncodeToString(sum[:])); !errors.Is(err, ErrUnsafeGenerationPath) {
		t.Fatalf("relative generation config error = %v", err)
	}
}


func TestStorePrunesOldUnprotectedStagedGenerations(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}

	configs := [][]byte{
		[]byte(`{"id":1}`),
		[]byte(`{"id":2}`),
		[]byte(`{"id":3}`),
		[]byte(`{"id":4}`),
		[]byte(`{"id":5}`),
	}
	hashes := make(map[int64]string, len(configs))
	for index, config := range configs {
		id := int64(index + 1)
		sum := sha256.Sum256(config)
		hash := hex.EncodeToString(sum[:])
		hashes[id] = hash
		if _, err := store.Stage(context.Background(), id, config, hash); err != nil {
			t.Fatalf("stage generation %d: %v", id, err)
		}
	}

	removed, err := store.PruneStagedGenerations(context.Background(), []int64{2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 || removed[0] != 3 || removed[1] != 1 {
		t.Fatalf("removed generations = %#v, want [3 1]", removed)
	}

	for _, id := range []int64{1, 3} {
		path, err := store.ConfigPath(id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pruned generation %d config still exists: %v", id, err)
		}
	}
	for _, id := range []int64{2, 4, 5} {
		path, err := store.ConfigPath(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyGenerationConfig(path, hashes[id]); err != nil {
			t.Fatalf("kept generation %d failed verification: %v", id, err)
		}
	}
}

func TestStorePruneFailsClosedOnUnexpectedGenerationEntry(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for id, config := range map[int64][]byte{
		1: []byte(`{"id":1}`),
		2: []byte(`{"id":2}`),
	} {
		sum := sha256.Sum256(config)
		if _, err := store.Stage(context.Background(), id, config, hex.EncodeToString(sum[:])); err != nil {
			t.Fatal(err)
		}
	}

	unexpected := filepath.Join(root, "generations", "1", "unexpected")
	if err := os.WriteFile(unexpected, []byte("do not remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PruneStagedGenerations(context.Background(), nil, 1); !errors.Is(err, ErrUnsafeGenerationPath) {
		t.Fatalf("unexpected-entry prune error = %v, want ErrUnsafeGenerationPath", err)
	}
	configPath, err := store.ConfigPath(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("failed prune removed generation before validation completed: %v", err)
	}
}

func TestStorePruneHonorsCanceledContext(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"id":1}`)
	sum := sha256.Sum256(config)
	if _, err := store.Stage(context.Background(), 1, config, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.PruneStagedGenerations(ctx, nil, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled prune error = %v, want context.Canceled", err)
	}
}
