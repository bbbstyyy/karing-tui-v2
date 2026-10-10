package coreartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// This is an ephemeral, private copy used by a non-activating historical
// compatibility check. It is not a persisted lease or an activation permit.
const (
	MaxRuleSetSnapshotFiles = 128
	MaxRuleSetSnapshotBytes = int64(128 << 20)
)

var ErrUnsafeRuleSetSnapshot = errors.New("unsafe historical rule-set snapshot")

type snapshotFile struct {
	name     string
	source   string
	hash     string
	size     int64
	identity os.FileInfo
}

// RuleSetSnapshot owns a freshly created private directory. Call Close on
// every path; the snapshot is not retained across process restarts.
type RuleSetSnapshot struct {
	dir      string
	parent   string
	identity os.FileInfo
	files    []snapshotFile
	lock     *os.File // exclusive flock on directory inode, held through Close
	closed   bool
}

// FileFor reports the isolated copy for an original pinned path. It is an
// internal helper for future manifest re-binding, never a user API.
func (s *RuleSetSnapshot) FileFor(source string) (string, bool) {
	if s == nil || s.closed {
		return "", false
	}
	for _, file := range s.files {
		if file.source == source {
			return filepath.Join(s.dir, file.name), true
		}
	}
	return "", false
}

// StagePinnedRuleSetSnapshot copies each distinct pinned, verified inode to
// a private directory on the same filesystem. Files are independent copies,
// not hard links to mutable content-addressed source files. Each copy is
// SHA-256 checked and fsynced before the directory is made available.
//
// A caller MUST keep its RuleSetPin descriptors open and reverify them after
// core Check. This staging itself does not change the runtime's rule paths.
func StagePinnedRuleSetSnapshot(
	ctx context.Context, coreRoot string, pins []*RuleSetPin,
) (_ *RuleSetSnapshot, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(pins) == 0 {
		return &RuleSetSnapshot{}, nil
	}
	if len(pins) > MaxRuleSetSnapshotFiles || coreRoot == "" ||
		!filepath.IsAbs(coreRoot) || filepath.Clean(coreRoot) != coreRoot {
		return nil, ErrUnsafeRuleSetSnapshot
	}
	if err := ensurePrivateDir(coreRoot); err != nil {
		return nil, err
	}
	// Recover only abandoned private scopes before reserving more disk.
	// Another process's still-locked scope is always left untouched.
	if _, err := ReclaimOrphanedRuleSetSnapshots(ctx, coreRoot); err != nil {
		return nil, err
	}
	parent := filepath.Join(coreRoot, "historical-check-snapshots")
	if err := ensurePrivateDir(parent); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(parent, ".check-")
	if err != nil {
		return nil, fmt.Errorf("%w: create isolated snapshot", ErrUnsafeRuleSetSnapshot)
	}
	snapshot := &RuleSetSnapshot{dir: dir, parent: parent}
	// Acquire the scope lock before copying the first byte, and hold it
	// until cleanup. Failure before taking the lock removes only our empty
	// freshly-created directory, never other scopes.
	if snapshot.lock, err = lockSnapshotDirectory(dir); err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, snapshot.Close())
		}
	}()
	if snapshot.identity, err = snapshot.lock.Stat(); err != nil {
		return nil, err
	}
	if err := snapshot.verifyDirectory(); err != nil {
		return nil, err
	}

	remaining := MaxRuleSetSnapshotBytes
	seen := make(map[string]string, len(pins))
	for _, pin := range pins {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pin == nil || pin.file == nil || pin.expected == "" ||
			!filepath.IsAbs(pin.path) || filepath.Clean(pin.path) != pin.path {
			return nil, ErrUnsafeRuleSetSnapshot
		}
		ext := filepath.Ext(pin.path)
		if ext != ".json" && ext != ".srs" {
			return nil, ErrUnsafeRuleSetSnapshot
		}
		name := pin.expected + ext
		if existing, exists := seen[name]; exists {
			if existing != pin.path {
				return nil, ErrUnsafeRuleSetSnapshot
			}
			continue
		}
		if err := pin.Reverify(ctx); err != nil {
			return nil, fmt.Errorf("%w: source pin changed", ErrUnsafeRuleSetSnapshot)
		}
		size := pin.Size()
		if size < 0 || size > MaxRuleSetUploadBytes || size > remaining {
			return nil, ErrRuleSetTooLarge
		}
		remaining -= size

		path := filepath.Join(dir, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("%w: create isolated file", ErrUnsafeRuleSetSnapshot)
		}
		info, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return nil, statErr
		}
		snapshot.files = append(snapshot.files, snapshotFile{
			name: name, source: pin.path, hash: pin.expected, size: size, identity: info,
		})
		n, copyErr := pin.copyVerified(ctx, file)
		if copyErr == nil && n != size {
			copyErr = ErrRuleSetHashMismatch
		}
		if copyErr == nil {
			copyErr = file.Chmod(0o400)
		}
		if copyErr == nil {
			copyErr = file.Sync()
		}
		copyErr = errors.Join(copyErr, file.Close())
		if copyErr != nil {
			return nil, fmt.Errorf("%w: copy isolated rule-set: %v", ErrUnsafeRuleSetSnapshot, copyErr)
		}
		if err := VerifyRuleSet(path, pin.expected); err != nil {
			return nil, fmt.Errorf("%w: copied rule-set verification failed", ErrUnsafeRuleSetSnapshot)
		}
		seen[name] = pin.path
	}
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	if err := syncDir(parent); err != nil {
		return nil, err
	}
	if err := snapshot.Verify(ctx); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// copyVerified copies from the OPEN descriptor, never a reopened pathname.
// It rejects source identity/content drift before and after copying.
func (p *RuleSetPin) copyVerified(ctx context.Context, destination io.Writer) (int64, error) {
	if err := p.Reverify(ctx); err != nil {
		return 0, err
	}
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(destination, h),
		io.LimitReader(&contextReader{ctx: ctx, reader: p.file}, MaxRuleSetUploadBytes+1))
	if err != nil {
		return n, err
	}
	if n != p.size || hex.EncodeToString(h.Sum(nil)) != p.expected {
		return n, ErrRuleSetHashMismatch
	}
	if err := p.Reverify(ctx); err != nil {
		return n, err
	}
	return n, nil
}

func (s *RuleSetSnapshot) verifyDirectory() error {
	if s == nil || s.closed {
		return ErrUnsafeRuleSetSnapshot
	}
	if s.dir == "" {
		return nil
	}
	if err := verifyPrivateSnapshotDirectory(s.dir, s.lock); err != nil {
		return err
	}
	info, err := os.Lstat(s.dir)
	if err != nil || !os.SameFile(info, s.identity) {
		return ErrUnsafeRuleSetSnapshot
	}
	uid, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(uid.Uid) != os.Getuid() {
		return ErrUnsafeRuleSetSnapshot
	}
	return nil
}

// Verify checks the copied inode identity and bytes independently of any
// later changes to the shared original pathname.
func (s *RuleSetSnapshot) Verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s != nil && !s.closed && s.dir == "" {
		return nil // no rule resources; no filesystem side effects
	}
	if err := s.verifyDirectory(); err != nil {
		return err
	}
	for _, entry := range s.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(s.dir, entry.name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() ||
			!os.SameFile(entry.identity, info) || info.Size() != entry.size ||
			info.Mode().Perm() != 0o400 {
			return ErrUnsafeRuleSetSnapshot
		}
		if err := VerifyRuleSet(path, entry.hash); err != nil {
			return ErrUnsafeRuleSetSnapshot
		}
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil || len(entries) != len(s.files) {
		return ErrUnsafeRuleSetSnapshot
	}
	return nil
}

// Close removes ONLY the directory and files created by this snapshot, after
// verifying identity. Unexpected files or path replacement cause a hard error
// rather than broad recursive deletion. A missing file also fails closed.
func (s *RuleSetSnapshot) Close() (err error) {
	if s == nil || s.closed {
		return nil
	}
	if s.dir == "" {
		s.closed = true
		return nil
	}
	// Never leak a directory lock on an unsafe/unrecognized snapshot.
	// If cleanup cannot prove ownership, leave files intact and return an
	// error; later recovery will refuse unknown entries too.
	defer func() {
		if s.lock != nil {
			err = errors.Join(err, s.lock.Close())
			s.lock = nil
		}
	}()
	if err := s.verifyDirectory(); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil || len(entries) != len(s.files) {
		return ErrUnsafeRuleSetSnapshot
	}
	allowed := make(map[string]snapshotFile, len(s.files))
	for _, item := range s.files {
		allowed[item.name] = item
	}
	for _, item := range entries {
		expected, ok := allowed[item.Name()]
		if !ok {
			return ErrUnsafeRuleSetSnapshot
		}
		info, err := os.Lstat(filepath.Join(s.dir, item.Name()))
		if err != nil || !info.Mode().IsRegular() ||
			!os.SameFile(info, expected.identity) {
			return ErrUnsafeRuleSetSnapshot
		}
	}
	for _, item := range s.files {
		if err := os.Remove(filepath.Join(s.dir, item.name)); err != nil {
			return err
		}
	}
	if err := os.Remove(s.dir); err != nil {
		return err
	}
	if err := syncDir(s.parent); err != nil {
		return err
	}
	s.closed = true
	return nil
}
