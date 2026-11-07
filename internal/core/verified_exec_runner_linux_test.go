//go:build linux

package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifiedExecRunnerVerifiesEveryStart(t *testing.T) {
	executable := writeExecutableFixture(t, "#!/bin/sh\nexit 0\n")
	count := 0
	runner, err := NewVerifiedExecRunner(ExecConfig{Executable: executable}, func(path string) error {
		count++
		if path != executable {
			t.Fatalf("verified path = %q, want %q", path, executable)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		process, err := runner.Start(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := process.Wait(); err != nil {
			t.Fatalf("process wait %d: %v", i, err)
		}
	}
	if count != 2 {
		t.Fatalf("verification count = %d, want 2", count)
	}
}

func TestVerifiedExecRunnerFailsClosedBeforeExec(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	executable := writeExecutableFixture(t, "#!/bin/sh\ntouch \""+marker+"\"\n")
	verifyErr := errors.New("artifact hash mismatch")
	runner, err := NewVerifiedExecRunner(ExecConfig{Executable: executable}, func(string) error {
		return verifyErr
	})
	if err != nil {
		t.Fatal(err)
	}

	process, err := runner.Start(context.Background())
	if !errors.Is(err, verifyErr) {
		t.Fatalf("start error = %v, want verifier error", err)
	}
	if process != nil {
		t.Fatal("verification failure returned a process")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unverified executable ran; marker stat error = %v", err)
	}
}

func TestVerifiedExecRunnerRequiresVerifier(t *testing.T) {
	executable := writeExecutableFixture(t, "#!/bin/sh\nexit 0\n")
	if _, err := NewVerifiedExecRunner(ExecConfig{Executable: executable}, nil); err == nil {
		t.Fatal("expected nil verifier to be rejected")
	}
}

func writeExecutableFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "core-fixture")
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
