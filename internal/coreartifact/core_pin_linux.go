//go:build linux

package coreartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

const MaxPinnedCoreBytes = int64(256 << 20)

var ErrCorePinChanged = errors.New("approved core artifact changed during snapshot")

// CorePin is a process-lifetime no-follow inode pin, not activation authority.
type CorePin struct {
	file                 *os.File
	path, expected, arch string
	size                 int64
}

// PinApprovedCore admits only the repository-locked hash for this architecture.
func PinApprovedCore(ctx context.Context, path string) (*CorePin, error) {
	expected, err := ExpectedSHA256(runtime.GOARCH)
	if err != nil {
		return nil, ErrUnsafeArtifact
	}
	pin, err := pinCoreExpected(ctx, path, expected)
	if err != nil {
		return nil, err
	}
	pin.arch = runtime.GOARCH
	return pin, nil
}

// pinCoreExpected is private to allow synthetic fixture digests in unit tests.
func pinCoreExpected(ctx context.Context, path, expected string) (*CorePin, error) {
	if ctx == nil || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		len(expected) != 64 {
		return nil, ErrUnsafeArtifact
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bytes, err := hex.DecodeString(expected)
	if err != nil || len(bytes) != 32 || hex.EncodeToString(bytes) != expected {
		return nil, ErrUnsafeArtifact
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafeArtifact
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafeArtifact
	}
	pin := &CorePin{file: file, path: path, expected: expected}
	if err := pin.Reverify(ctx); err != nil {
		_ = pin.Close()
		return nil, err
	}
	return pin, nil
}

func (p *CorePin) SHA256() string {
	if p == nil {
		return ""
	}
	return p.expected
}
func (p *CorePin) Size() int64 {
	if p == nil {
		return 0
	}
	return p.size
}
func (p *CorePin) Architecture() string {
	if p == nil {
		return ""
	}
	return p.arch
}

func (p *CorePin) Reverify(ctx context.Context) error {
	if p == nil || p.file == nil || ctx == nil {
		return ErrUnsafeArtifact
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := p.file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 ||
		before.Size() > MaxPinnedCoreBytes ||
		before.Mode().Perm()&0o111 == 0 || before.Mode().Perm()&0o022 != 0 {
		return ErrUnsafeArtifact
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && int(st.Uid) != os.Getuid()) || st.Nlink != 1 {
		return ErrUnsafeArtifact
	}
	if err := p.verifyPath(before); err != nil {
		return err
	}
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		return ErrUnsafeArtifact
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(&contextReader{ctx: ctx, reader: p.file}, MaxPinnedCoreBytes+1))
	if err != nil || n != before.Size() || hex.EncodeToString(h.Sum(nil)) != p.expected {
		return ErrCorePinChanged
	}
	after, err := p.file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return ErrCorePinChanged
	}
	if err := p.verifyPath(after); err != nil {
		return err
	}
	p.size = after.Size()
	return nil
}

func (p *CorePin) verifyPath(opened os.FileInfo) error {
	current, err := os.Lstat(p.path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return ErrCorePinChanged
	}
	return nil
}

// CopyVerified reads the held descriptor, detecting path/inode and byte drift.
func (p *CorePin) CopyVerified(ctx context.Context, dst io.Writer) (int64, error) {
	if err := p.Reverify(ctx); err != nil {
		return 0, err
	}
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		return 0, ErrUnsafeArtifact
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h),
		io.LimitReader(&contextReader{ctx: ctx, reader: p.file}, MaxPinnedCoreBytes+1))
	if err != nil || n != p.size || hex.EncodeToString(h.Sum(nil)) != p.expected {
		return n, ErrCorePinChanged
	}
	if err := p.Reverify(ctx); err != nil {
		return n, err
	}
	return n, nil
}

// verifyIsolatedCore validates a private 0400 copy without execute permission.
func verifyIsolatedCore(ctx context.Context, path, expected string, size int64) error {
	if ctx == nil || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		size <= 0 || size > MaxPinnedCoreBytes {
		return ErrUnsafeArtifact
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafeArtifact
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return ErrUnsafeArtifact
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != size ||
		before.Mode().Perm() != 0o400 {
		return ErrUnsafeArtifact
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() || st.Nlink != 1 {
		return ErrUnsafeArtifact
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, pathInfo) {
		return ErrUnsafeArtifact
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(&contextReader{ctx: ctx, reader: file}, MaxPinnedCoreBytes+1))
	if err != nil || n != size || hex.EncodeToString(h.Sum(nil)) != expected {
		return ErrCorePinChanged
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return ErrCorePinChanged
	}
	pathInfo, err = os.Lstat(path)
	if err != nil || !os.SameFile(after, pathInfo) {
		return ErrCorePinChanged
	}
	return nil
}

func (p *CorePin) Close() error {
	if p == nil || p.file == nil {
		return nil
	}
	file := p.file
	p.file = nil
	return file.Close()
}
