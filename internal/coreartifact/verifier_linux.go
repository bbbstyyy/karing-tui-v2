//go:build linux

package coreartifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

const (
	CandidateCommit  = "beddeababcc71dfb0c78124598b13341c06c69fb"
	CandidateVersion = "karing-tui-v2-core-1.13.19-beddeaba"

	SHA256AMD64 = "829452e2927ab8a9836fec398d5bbade259b3837df774c53afb3ec4eb20a1569"
	SHA256ARM64 = "77a46000241540067c903bbfdf7c320638066abb9888635bc7a3f1810ee4b512"
)

var (
	ErrUnsupportedArchitecture = errors.New("unsupported core architecture")
	ErrUnsafeArtifact          = errors.New("unsafe core artifact")
	ErrHashMismatch            = errors.New("core artifact SHA-256 mismatch")
)

func ExpectedSHA256(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return SHA256AMD64, nil
	case "arm64":
		return SHA256ARM64, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedArchitecture, goarch)
	}
}

func Verify(path string) error {
	return VerifyForArch(path, runtime.GOARCH)
}

func VerifyForArch(path, goarch string) error {
	expected, err := ExpectedSHA256(goarch)
	if err != nil {
		return err
	}
	if err := verifyFile(path, expected); err != nil {
		return err
	}
	return nil
}

func verifyFile(path, expectedSHA256 string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: core path must be absolute", ErrUnsafeArtifact)
	}
	if len(expectedSHA256) != sha256.Size*2 {
		return errors.New("invalid expected core SHA-256")
	}
	if _, err := hex.DecodeString(expectedSHA256); err != nil {
		return fmt.Errorf("invalid expected core SHA-256: %w", err)
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open core artifact without following symlink: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return errors.New("wrap core artifact file descriptor")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened core artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: core artifact is not a regular file", ErrUnsafeArtifact)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%w: core artifact is not executable", ErrUnsafeArtifact)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: core artifact is writable by group or others", ErrUnsafeArtifact)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := uint32(os.Getuid())
		if stat.Uid != 0 && stat.Uid != uid {
			return fmt.Errorf("%w: core artifact owner uid %d is neither root nor current uid %d", ErrUnsafeArtifact, stat.Uid, uid)
		}
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("hash core artifact: %w", err)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != expectedSHA256 {
		return fmt.Errorf("%w: got %s, want %s", ErrHashMismatch, actual, expectedSHA256)
	}
	return nil
}
