package runtimepath

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveRequiresRuntimeDirectory(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("KARING_TUI_RUNTIME_DIR", "")
	_, err := Resolve()
	if !errors.Is(err, ErrRuntimeDirUnavailable) {
		t.Fatalf("expected ErrRuntimeDirUnavailable, got %v", err)
	}
}

func TestResolveAndEnsureUsesPrivateOverride(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KARING_TUI_RUNTIME_DIR", base)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "data"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(base, "state"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(base, "cache"))

	paths, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(paths.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("runtime permissions = %04o, want 0700", got)
	}
}

func TestResolveRejectsWorldWritableRuntimeDirectory(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KARING_TUI_RUNTIME_DIR", base)

	_, err := Resolve()
	if !errors.Is(err, ErrRuntimeDirUnavailable) {
		t.Fatalf("expected secure runtime dir error, got %v", err)
	}
}
