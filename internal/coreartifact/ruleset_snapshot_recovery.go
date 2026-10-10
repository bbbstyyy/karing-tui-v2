package coreartifact

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const MaxRuleSetSnapshotRecoveryScopes = 32

var ErrRuleSetSnapshotActive = errors.New("historical rule-set snapshot is owned by an active check")

type RuleSetSnapshotRecoveryReport struct {
	Reclaimed int
	Active    int
}

// lockSnapshotDirectory uses a process-lifetime Linux flock on a private,
// no-follow directory descriptor, not a PID file. The lock survives rename,
// is released on process termination, and is independent between processes.
func lockSnapshotDirectory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|
		syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open snapshot directory", ErrUnsafeRuleSetSnapshot)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafeRuleSetSnapshot
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrRuleSetSnapshotActive
		}
		return nil, fmt.Errorf("%w: lock snapshot scope", ErrUnsafeRuleSetSnapshot)
	}
	if err := verifyPrivateSnapshotDirectory(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func verifyPrivateSnapshotDirectory(path string, opened *os.File) error {
	if opened == nil || path == "" {
		return ErrUnsafeRuleSetSnapshot
	}
	fdInfo, err := opened.Stat()
	if err != nil {
		return ErrUnsafeRuleSetSnapshot
	}
	atPath, err := os.Lstat(path)
	if err != nil || atPath.Mode()&os.ModeSymlink != 0 ||
		!atPath.IsDir() || !os.SameFile(fdInfo, atPath) ||
		atPath.Mode().Perm()&0o077 != 0 {
		return ErrUnsafeRuleSetSnapshot
	}
	stat, ok := fdInfo.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return ErrUnsafeRuleSetSnapshot
	}
	return nil
}

func isSnapshotScopeName(name string) bool {
	const prefix = ".check-"
	if !strings.HasPrefix(name, prefix) || len(name) <= len(prefix) {
		return false
	}
	for _, ch := range name[len(prefix):] {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') &&
			!(ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

func isSnapshotRuleFileName(name string) bool {
	if len(name) != 64+len(".json") && len(name) != 64+len(".srs") {
		return false
	}
	ext := filepath.Ext(name)
	if ext != ".json" && ext != ".srs" {
		return false
	}
	digest := strings.TrimSuffix(name, ext)
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32 &&
		hex.EncodeToString(decoded) == digest
}

type snapshotRecoverableEntry struct {
	name     string
	identity os.FileInfo
}

func inspectRecoverableSnapshot(
	ctx context.Context, dir string, lock *os.File,
) ([]snapshotRecoverableEntry, error) {
	if err := verifyPrivateSnapshotDirectory(dir, lock); err != nil {
		return nil, err
	}
	// File.ReadDir(n) never materializes an unbounded directory listing.
	entries, err := lock.ReadDir(MaxRuleSetSnapshotFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrUnsafeRuleSetSnapshot
	}
	if len(entries) > MaxRuleSetSnapshotFiles {
		return nil, ErrUnsafeRuleSetSnapshot
	}
	total := int64(0)
	verified := make([]snapshotRecoverableEntry, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !isSnapshotRuleFileName(entry.Name()) {
			return nil, ErrUnsafeRuleSetSnapshot
		}
		info, err := os.Lstat(filepath.Join(dir, entry.Name()))
		if err != nil || !info.Mode().IsRegular() ||
			(info.Mode().Perm() != 0o400 && info.Mode().Perm() != 0o600) ||
			info.Size() < 0 || info.Size() > MaxRuleSetUploadBytes {
			return nil, ErrUnsafeRuleSetSnapshot
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 {
			return nil, ErrUnsafeRuleSetSnapshot
		}
		total += info.Size()
		if total > MaxRuleSetSnapshotBytes {
			return nil, ErrUnsafeRuleSetSnapshot
		}
		verified = append(verified, snapshotRecoverableEntry{name: entry.Name(), identity: info})
	}
	return verified, nil
}

// ReclaimOrphanedRuleSetSnapshots is a bounded, opt-in recovery operation.
// The caller must never invoke it as a reason to stop a healthy core. A scope
// currently locked by another process is skipped, not treated as stale.
// Only the known private .check-* scopes and SHA-256.json/.srs files are
// deleted. Unexpected entries fail closed without recursive deletion.
func ReclaimOrphanedRuleSetSnapshots(
	ctx context.Context, coreRoot string,
) (RuleSetSnapshotRecoveryReport, error) {
	var result RuleSetSnapshotRecoveryReport
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if coreRoot == "" || !filepath.IsAbs(coreRoot) ||
		filepath.Clean(coreRoot) != coreRoot {
		return result, ErrUnsafeRuleSetSnapshot
	}
	parent := filepath.Join(coreRoot, "historical-check-snapshots")
	if _, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) {
		return result, nil
	} else if err != nil {
		return result, ErrUnsafeRuleSetSnapshot
	}
	// Refuse a symlink or unsafe parent even when only probing for stale
	// snapshots. Never create directories during a recovery-only operation.
	for _, dir := range []string{coreRoot, parent} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 {
			return result, ErrUnsafeRuleSetSnapshot
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Getuid() {
			return result, ErrUnsafeRuleSetSnapshot
		}
	}
	parentFD, err := syscall.Open(parent, syscall.O_RDONLY|
		syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return result, ErrUnsafeRuleSetSnapshot
	}
	parentFile := os.NewFile(uintptr(parentFD), parent)
	defer parentFile.Close()
	if err := verifyPrivateSnapshotDirectory(parent, parentFile); err != nil {
		return result, err
	}
	scopes, err := parentFile.ReadDir(MaxRuleSetSnapshotRecoveryScopes + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return result, ErrUnsafeRuleSetSnapshot
	}
	if len(scopes) > MaxRuleSetSnapshotRecoveryScopes {
		return result, ErrUnsafeRuleSetSnapshot
	}
	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !isSnapshotScopeName(scope.Name()) {
			return result, ErrUnsafeRuleSetSnapshot
		}
		dir := filepath.Join(parent, scope.Name())
		lock, lockErr := lockSnapshotDirectory(dir)
		if errors.Is(lockErr, ErrRuleSetSnapshotActive) {
			result.Active++
			continue
		}
		if lockErr != nil {
			return result, lockErr
		}
		// Explicitly release the lock even when a corrupt directory needs
		// operator inspection. It cannot be deleted in the unsafe case.
		entries, scanErr := inspectRecoverableSnapshot(ctx, dir, lock)
		if scanErr == nil {
			for _, entry := range entries {
				if err := ctx.Err(); err != nil {
					scanErr = err
					break
				}
				if err := verifyPrivateSnapshotDirectory(dir, lock); err != nil {
					scanErr = err
					break
				}
				current, err := os.Lstat(filepath.Join(dir, entry.name))
				if err != nil || !os.SameFile(current, entry.identity) {
					scanErr = ErrUnsafeRuleSetSnapshot
					break
				}
				if err := syscall.Unlinkat(int(lock.Fd()), entry.name); err != nil {
					scanErr = fmt.Errorf("%w: remove stale snapshot file", ErrUnsafeRuleSetSnapshot)
					break
				}
			}
			if scanErr == nil {
				if err := verifyPrivateSnapshotDirectory(dir, lock); err != nil {
					scanErr = err
				} else if err := os.Remove(dir); err != nil {
					scanErr = fmt.Errorf("%w: remove stale snapshot directory", ErrUnsafeRuleSetSnapshot)
				} else if err := syncDir(parent); err != nil {
					scanErr = err
				} else {
					result.Reclaimed++
				}
			}
		}
		closeErr := lock.Close()
		if scanErr != nil {
			return result, errors.Join(scanErr, closeErr)
		}
		if closeErr != nil {
			return result, closeErr
		}
	}
	return result, nil
}
