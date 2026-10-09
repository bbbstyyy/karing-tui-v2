package coreartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// RuleSetPin retains a verified no-follow file descriptor while a bounded
// historical core check runs. It does NOT make the pathname immutable or
// authorize activation: a malicious rename-and-restore between observations
// is not excluded by this process-local pin.
type RuleSetPin struct {
	file     *os.File
	path     string
	expected string
	size     int64
}

// PinRuleSet verifies the content-addressed file and holds its original inode
// open. The caller must Close it on every path, including a canceled Check.
func PinRuleSet(path, expectedSHA256 string) (_ *RuleSetPin, err error) {
	expected, err := normalizeSHA256(expectedSHA256)
	if err != nil {
		return nil, err
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: pinned rule-set path must be clean and absolute", ErrUnsafeRuleSetPath)
	}
	switch filepath.Ext(path) {
	case ".json", ".srs":
	default:
		return nil, ErrRuleSetExtension
	}
	file, err := openPrivateRuleSetNoFollow(path)
	if err != nil {
		return nil, err
	}
	pin := &RuleSetPin{file: file, path: path, expected: expected}
	if err := pin.Reverify(context.Background()); err != nil {
		_ = pin.Close()
		return nil, err
	}
	return pin, nil
}

// Size is the number of bytes hashed when the pin was first acquired.
func (p *RuleSetPin) Size() int64 {
	if p == nil {
		return 0
	}
	return p.size
}

// Reverify checks that the original descriptor is still private and owned by
// the current user, that its path still resolves to the same inode, and that
// its full bounded content still hashes to the manifest's expected SHA-256.
// It also rejects detectable in-place mutations during the hashing pass.
func (p *RuleSetPin) Reverify(ctx context.Context) error {
	if p == nil || p.file == nil {
		return ErrUnsafeRuleSetPath
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := p.file.Stat()
	if err != nil {
		return fmt.Errorf("%w: inspect pinned rule-set", ErrUnsafeRuleSetPath)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return ErrUnsafeRuleSetPath
	}
	if stat, ok := before.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return ErrUnsafeRuleSetPath
	}
	if before.Size() < 0 || before.Size() > MaxRuleSetUploadBytes {
		return ErrRuleSetTooLarge
	}
	if err := p.verifyPathIdentity(before); err != nil {
		return err
	}
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%w: seek pinned rule-set", ErrUnsafeRuleSetPath)
	}
	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(&contextReader{ctx: ctx, reader: p.file}, MaxRuleSetUploadBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read pinned rule-set", ErrUnsafeRuleSetPath)
	}
	if n != before.Size() {
		return ErrRuleSetHashMismatch
	}
	if hex.EncodeToString(hasher.Sum(nil)) != p.expected {
		return ErrRuleSetHashMismatch
	}
	after, err := p.file.Stat()
	if err != nil || !os.SameFile(before, after) ||
		before.Size() != after.Size() || before.Mode() != after.Mode() ||
		!before.ModTime().Equal(after.ModTime()) {
		return ErrUnsafeRuleSetPath
	}
	if err := p.verifyPathIdentity(after); err != nil {
		return err
	}
	p.size = after.Size()
	return nil
}

func (p *RuleSetPin) verifyPathIdentity(opened os.FileInfo) error {
	atPath, err := os.Lstat(p.path)
	if err != nil || !atPath.Mode().IsRegular() || !os.SameFile(opened, atPath) {
		return ErrUnsafeRuleSetPath
	}
	return nil
}

// Close releases the descriptor. It is safe to call more than once.
func (p *RuleSetPin) Close() error {
	if p == nil || p.file == nil {
		return nil
	}
	file := p.file
	p.file = nil
	return file.Close()
}
