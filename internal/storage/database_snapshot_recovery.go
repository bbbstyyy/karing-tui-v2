package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const MaxDatabaseSnapshotRecoveryScopes = 32

var ErrDatabaseSnapshotActive = errors.New("database snapshot scope is active")

// DatabaseSnapshotRecoveryReport counts only known private snapshot scopes.
// An active scope is skipped, never classified as abandoned.
type DatabaseSnapshotRecoveryReport struct {
	Reclaimed int
	Active    int
}

// DatabaseSnapshot's directory lock is held throughout SQLite VACUUM, file
// verification and cleanup. Linux flock releases the lease on process death.
// Open a new descriptor for each lock attempt: flock locks open-file
// descriptions, not PIDs or advisory marker files.
func lockDatabaseSnapshotDirectory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|
		syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafeDatabaseSnapshot
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrDatabaseSnapshotActive
		}
		return nil, ErrUnsafeDatabaseSnapshot
	}
	if err := verifyLockedDatabaseSnapshotDirectory(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func verifyLockedDatabaseSnapshotDirectory(path string, lock *os.File) error {
	if path == "" || lock == nil {
		return ErrUnsafeDatabaseSnapshot
	}
	opened, err := lock.Stat()
	if err != nil || !opened.IsDir() || opened.Mode().Perm()&0o077 != 0 {
		return ErrUnsafeDatabaseSnapshot
	}
	atPath, err := os.Lstat(path)
	if err != nil || !atPath.IsDir() || atPath.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, atPath) || atPath.Mode().Perm()&0o077 != 0 {
		return ErrUnsafeDatabaseSnapshot
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return ErrUnsafeDatabaseSnapshot
	}
	return nil
}

// Parent flock serializes the creation-to-child-lock gap with scavenging.
// Reclamation holds it only for the bounded scan, never during VACUUM.
func lockDatabaseSnapshotParent(ctx context.Context, path string) (*os.File, error) {
	if err := verifyPrivateSnapshotParent(path); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 40; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lock, err := lockDatabaseSnapshotDirectory(path)
		if !errors.Is(err, ErrDatabaseSnapshotActive) {
			return lock, err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, ErrDatabaseSnapshotActive
}

func newLockedDatabaseSnapshotScope(ctx context.Context, parent string) (_ *DatabaseSnapshot, err error) {
	parentLock, err := lockDatabaseSnapshotParent(ctx, parent)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, parentLock.Close())
	}()
	dir, err := os.MkdirTemp(parent, ".sqlite-snapshot-v2-")
	if err != nil {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	scopeLock, err := lockDatabaseSnapshotDirectory(dir)
	if err != nil {
		return nil, errors.Join(ErrUnsafeDatabaseSnapshot, os.Remove(dir))
	}
	identity, err := scopeLock.Stat()
	if err != nil {
		_ = scopeLock.Close()
		return nil, errors.Join(ErrUnsafeDatabaseSnapshot, os.Remove(dir))
	}
	return &DatabaseSnapshot{
		Path: filepath.Join(dir, "state.db"), directory: dir,
		parent: parent, directoryIdentity: identity, lock: scopeLock,
	}, nil
}

func isDatabaseSnapshotScopeName(name string) bool {
	const prefix = ".sqlite-snapshot-v2-"
	if !strings.HasPrefix(name, prefix) || len(name) <= len(prefix) {
		return false
	}
	for _, character := range name[len(prefix):] {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func inspectOrphanDatabaseSnapshot(ctx context.Context, dir string, lock *os.File) (os.FileInfo, error) {
	if err := verifyLockedDatabaseSnapshotDirectory(dir, lock); err != nil {
		return nil, err
	}
	scope, err := lock.Stat()
	if err != nil || scope.Mode().Perm() != 0o700 {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	entries, err := lock.ReadDir(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	if len(entries) > 1 || (len(entries) == 1 && entries[0].Name() != "state.db") {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	if len(entries) == 0 {
		return nil, nil // process died after MkdirTemp, before pre-create
	}
	info, err := os.Lstat(filepath.Join(dir, "state.db"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() < 0 || info.Size() > MaxDatabaseSnapshotBytes {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return info, nil
}

// ReclaimOrphanedDatabaseSnapshots deletes only abandoned, bounded, recognized
// scopes in a caller-owned private staging parent. It never scans outside the
// supplied parent, creates directories, follows symlinks, or uses RemoveAll.
// Unknown entries fail closed, and a locked active scope is skipped.
func ReclaimOrphanedDatabaseSnapshots(
	ctx context.Context, parent string,
) (report DatabaseSnapshotRecoveryReport, err error) {
	if ctx == nil || parent == "" || !filepath.IsAbs(parent) ||
		filepath.Clean(parent) != parent {
		return report, ErrUnsafeDatabaseSnapshot
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if _, statErr := os.Lstat(parent); errors.Is(statErr, os.ErrNotExist) {
		return report, nil
	} else if statErr != nil {
		return report, ErrUnsafeDatabaseSnapshot
	}
	if err := verifyPrivateSnapshotParent(parent); err != nil {
		return report, err
	}
	parentLock, err := lockDatabaseSnapshotParent(ctx, parent)
	if err != nil {
		return report, err
	}
	defer func() {
		err = errors.Join(err, parentLock.Close())
	}()
	scopes, readErr := parentLock.ReadDir(MaxDatabaseSnapshotRecoveryScopes + 1)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return report, ErrUnsafeDatabaseSnapshot
	}
	if len(scopes) > MaxDatabaseSnapshotRecoveryScopes {
		return report, ErrUnsafeDatabaseSnapshot
	}
	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if !isDatabaseSnapshotScopeName(scope.Name()) || !scope.IsDir() {
			return report, ErrUnsafeDatabaseSnapshot
		}
		path := filepath.Join(parent, scope.Name())
		lock, lockErr := lockDatabaseSnapshotDirectory(path)
		if errors.Is(lockErr, ErrDatabaseSnapshotActive) {
			report.Active++
			continue
		}
		if lockErr != nil {
			return report, lockErr
		}
		// Close the child lock on every path, including an unsafe scope.
		fileInfo, inspectErr := inspectOrphanDatabaseSnapshot(ctx, path, lock)
		if inspectErr == nil {
			inspectErr = verifyLockedDatabaseSnapshotDirectory(path, lock)
		}
		if inspectErr == nil && fileInfo != nil {
			current, fileErr := os.Lstat(filepath.Join(path, "state.db"))
			if fileErr != nil || !os.SameFile(current, fileInfo) {
				inspectErr = ErrUnsafeDatabaseSnapshot
			} else if err := syscall.Unlinkat(int(lock.Fd()), "state.db"); err != nil {
				inspectErr = ErrUnsafeDatabaseSnapshot
			}
		}
		if inspectErr == nil {
			if err := verifyLockedDatabaseSnapshotDirectory(path, lock); err != nil {
				inspectErr = err
			} else if err := os.Remove(path); err != nil {
				inspectErr = ErrUnsafeDatabaseSnapshot
			} else if err := syncDatabaseSnapshotDir(parent); err != nil {
				inspectErr = err
			} else {
				report.Reclaimed++
			}
		}
		closeErr := lock.Close()
		if inspectErr != nil {
			return report, errors.Join(inspectErr, closeErr)
		}
		if closeErr != nil {
			return report, closeErr
		}
	}
	return report, nil
}
