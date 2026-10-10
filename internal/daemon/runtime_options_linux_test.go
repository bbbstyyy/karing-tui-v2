//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
)

func TestResolveManagedCoreOptionsDisabledWithoutCorePath(t *testing.T) {
	t.Setenv(corePathEnv, "")
	paths := runtimeConfigTestPaths(t)
	options, err := resolveManagedCoreOptionsWithVerify(paths, func(string) error {
		t.Fatal("verifier should not run when core is disabled")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if options != nil {
		t.Fatalf("options = %+v, want nil", options)
	}
}

func TestResolveManagedCoreOptionsCreatesPersistentPrivateSecret(t *testing.T) {
	paths := runtimeConfigTestPaths(t)
	corePath := filepath.Join(paths.Data, "karing-tui-core")
	if err := os.WriteFile(corePath, []byte("fixture"), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Setenv(corePathEnv, corePath)
	t.Setenv(coreControlPortEnv, "")

	var verified string
	verify := func(path string) error {
		verified = path
		return nil
	}
	first, err := resolveManagedCoreOptionsWithVerify(paths, verify)
	if err != nil {
		t.Fatal(err)
	}
	if verified != corePath || first.Executable != corePath {
		t.Fatalf("unexpected verified core path: verified=%q options=%q", verified, first.Executable)
	}
	if first.ControlEndpoint != "http://127.0.0.1:3057" {
		t.Fatalf("control endpoint = %q", first.ControlEndpoint)
	}
	if len(first.ControlSecret) != 64 {
		t.Fatalf("secret length = %d, want 64", len(first.ControlSecret))
	}
	if first.Inbounds.RulePort != 2080 || first.Inbounds.DirectPort != 2081 || first.Inbounds.SelectedPort != 2082 {
		t.Fatalf("unexpected default inbounds: %+v", first.Inbounds)
	}

	secretPath := filepath.Join(paths.State, "core-control.secret")
	info, err := os.Stat(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("secret mode = %04o, want 0600", got)
	}

	second, err := resolveManagedCoreOptionsWithVerify(paths, verify)
	if err != nil {
		t.Fatal(err)
	}
	if second.ControlSecret != first.ControlSecret {
		t.Fatal("control secret changed across reload")
	}
}

func TestResolveManagedCoreOptionsRejectsRelativeCorePath(t *testing.T) {
	paths := runtimeConfigTestPaths(t)
	t.Setenv(corePathEnv, "karing-tui-core")
	if _, err := resolveManagedCoreOptionsWithVerify(paths, func(string) error { return nil }); err == nil {
		t.Fatal("expected relative core path to be rejected")
	}
}

func TestResolveManagedCoreOptionsPropagatesArtifactVerification(t *testing.T) {
	paths := runtimeConfigTestPaths(t)
	corePath := filepath.Join(paths.Data, "core")
	t.Setenv(corePathEnv, corePath)
	sentinel := errors.New("bad core")
	if _, err := resolveManagedCoreOptionsWithVerify(paths, func(string) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("verification error = %v", err)
	}
}

func TestResolveManagedCoreOptionsRejectsControlPortCollision(t *testing.T) {
	paths := runtimeConfigTestPaths(t)
	corePath := filepath.Join(paths.Data, "core")
	t.Setenv(corePathEnv, corePath)
	t.Setenv(coreControlPortEnv, "2081")
	if _, err := resolveManagedCoreOptionsWithVerify(paths, func(string) error { return nil }); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestControlSecretRejectsSymlinkAndPermissiveFile(t *testing.T) {
	paths := runtimeConfigTestPaths(t)
	secretPath := filepath.Join(paths.State, "core-control.secret")
	target := filepath.Join(paths.State, "target.secret")
	if err := os.WriteFile(target, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, secretPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateControlSecret(secretPath); err == nil {
		t.Fatal("expected symlink secret to be rejected")
	}
	if err := os.Remove(secretPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte(strings.Repeat("b", 64)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateControlSecret(secretPath); err == nil || !strings.Contains(err.Error(), "too permissive") {
		t.Fatalf("permissive secret error = %v", err)
	}
}

func runtimeConfigTestPaths(t *testing.T) runtimepath.Paths {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := runtimepath.Paths{
		Config:   filepath.Join(base, "config"),
		Data:     filepath.Join(base, "data"),
		State:    filepath.Join(base, "state"),
		Cache:    filepath.Join(base, "cache"),
		Runtime:  filepath.Join(base, "runtime"),
		Socket:   filepath.Join(base, "runtime", "daemon.sock"),
		Database: filepath.Join(base, "state", "state.db"),
	}
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	return paths
}
