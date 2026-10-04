//go:build linux

package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
)

func TestGenerationRunnerRequiresBoundConfig(t *testing.T) {
	executable := writeExecutableFixture(t, "#!/bin/sh\nexit 0\n")
	runner, err := NewGenerationRunner(executable, func(string) error { return nil }, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Start(context.Background()); !errors.Is(err, ErrGenerationConfigUnset) {
		t.Fatalf("start error = %v, want ErrGenerationConfigUnset", err)
	}
}

func TestGenerationRunnerStartsBoundConfigThroughVerifier(t *testing.T) {
	executable := writeExecutableFixture(t, "#!/bin/sh\nif [ \"$1\" != \"run\" ] || [ \"$2\" != \"-c\" ] || [ ! -f \"$3\" ]; then\n  exit 42\nfi\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n")
	configPath, configSHA := writeConfigFixture(t)
	var verifies atomic.Int32
	runner, err := NewGenerationRunner(executable, func(path string) error {
		if path != executable {
			t.Fatalf("verify path = %q, want %q", path, executable)
		}
		verifies.Add(1)
		return nil
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.BindConfig(configPath, configSHA); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	process, err := runner.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if verifies.Load() != 1 {
		t.Fatalf("verify calls = %d, want 1", verifies.Load())
	}
	if err := process.Terminate(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("wait after terminate: %v", err)
	}
}

func TestGenerationRunnerDetectsConfigTamperBeforeStart(t *testing.T) {
	executable := writeExecutableFixture(t, "#!/bin/sh\nexit 0\n")
	configPath, configSHA := writeConfigFixture(t)
	runner, err := NewGenerationRunner(executable, func(string) error { return nil }, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.BindConfig(configPath, configSHA); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("{\"tampered\":true}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Start(context.Background()); !errors.Is(err, coreartifact.ErrConfigHashMismatch) {
		t.Fatalf("tampered start error = %v", err)
	}
}

func TestCheckGenerationConfigUsesVerifierAndExactPath(t *testing.T) {
	executable := writeExecutableFixture(t, "#!/bin/sh\nif [ \"$1\" != \"check\" ] || [ \"$2\" != \"-c\" ] || [ ! -f \"$3\" ]; then\n  exit 43\nfi\nexit 0\n")
	configPath, configSHA := writeConfigFixture(t)
	var verifies atomic.Int32
	var stderr strings.Builder
	if err := CheckGenerationConfig(context.Background(), executable, func(string) error {
		verifies.Add(1)
		return nil
	}, configPath, configSHA, nil, &stderr); err != nil {
		t.Fatalf("check failed: %v stderr=%q", err, stderr.String())
	}
	if verifies.Load() != 1 {
		t.Fatalf("verify calls = %d, want 1", verifies.Load())
	}
}

func TestGenerationRunnerRejectsSymlinkAndPermissiveConfig(t *testing.T) {
	executable := writeExecutableFixture(t, "#!/bin/sh\nexit 0\n")
	runner, err := NewGenerationRunner(executable, func(string) error { return nil }, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	target, targetSHA := writeConfigFixture(t)
	link := filepath.Join(t.TempDir(), "config-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := runner.BindConfig(link, targetSHA); err == nil {
		t.Fatal("expected symlink generation config to be rejected")
	}

	permissive := filepath.Join(t.TempDir(), "config.json")
	content := []byte("{}")
	if err := os.WriteFile(permissive, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if err := runner.BindConfig(permissive, hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("expected permissive generation config to be rejected")
	}
}

func writeExecutableFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "core")
	if err := os.WriteFile(path, []byte(content), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o500); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeConfigFixture(t *testing.T) (string, string) {
	t.Helper()
	content := []byte("{}")
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	return path, hex.EncodeToString(sum[:])
}
