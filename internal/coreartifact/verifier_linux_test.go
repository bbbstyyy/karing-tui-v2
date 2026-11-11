//go:build linux

package coreartifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExpectedSHA256(t *testing.T) {
	tests := map[string]string{
		"amd64": SHA256AMD64,
		"arm64": SHA256ARM64,
	}
	for arch, want := range tests {
		got, err := ExpectedSHA256(arch)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s hash = %q, want %q", arch, got, want)
		}
	}
	if _, err := ExpectedSHA256("386"); !errors.Is(err, ErrUnsupportedArchitecture) {
		t.Fatalf("unsupported architecture error = %v", err)
	}
}

func TestVerifyFileAcceptsExactExecutable(t *testing.T) {
	path, expected := writeFixture(t, 0o700, []byte("locked-core-fixture"))
	if err := verifyFile(path, expected); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFileRejectsHashMismatch(t *testing.T) {
	path, _ := writeFixture(t, 0o700, []byte("candidate"))
	other := sha256.Sum256([]byte("different"))
	err := verifyFile(path, hex.EncodeToString(other[:]))
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("hash mismatch error = %v", err)
	}
}

func TestVerifyFileRejectsSymlink(t *testing.T) {
	target, expected := writeFixture(t, 0o700, []byte("candidate"))
	link := filepath.Join(t.TempDir(), "core-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(link, expected); err == nil {
		t.Fatal("expected symlink core artifact to be rejected")
	}
}

func TestVerifyFileRejectsUnsafeModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o720, 0o702} {
		t.Run(mode.String(), func(t *testing.T) {
			path, expected := writeFixture(t, mode, []byte("candidate"))
			if err := verifyFile(path, expected); !errors.Is(err, ErrUnsafeArtifact) {
				t.Fatalf("mode %o error = %v", mode, err)
			}
		})
	}
}

func TestVerifyFileRequiresAbsolutePath(t *testing.T) {
	hash := sha256.Sum256(nil)
	if err := verifyFile("relative-core", hex.EncodeToString(hash[:])); !errors.Is(err, ErrUnsafeArtifact) {
		t.Fatalf("relative path error = %v", err)
	}
}

func writeFixture(t *testing.T, mode os.FileMode, content []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "core")
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	return path, hex.EncodeToString(hash[:])
}
