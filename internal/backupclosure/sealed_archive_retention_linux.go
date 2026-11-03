//go:build linux

package backupclosure

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

const (
	MaxRetainedSealedArchives      = 8
	MaxSealedArchiveTemporaryFiles = 32
	MaxRetainedSealedArchiveBytes  = int64(MaxRetainedSealedArchives) * MaxSealedArchiveBytes
	sealedArchiveTemporaryPrefix   = ".ktui-sealed-v2-"
)

// SealedArchiveRetentionReport only counts directory entries; it does not
// authenticate an archive or authorize restore, replacement, or deletion.
// Completed archives are NEVER pruned by this package.
type SealedArchiveRetentionReport struct {
	Completed      int
	CompletedBytes int64
	Temporary      int
	Active         int
	Reclaimed      int
	AtCapacity     bool
}

type abandonedSealedArchive struct {
	name     string
	file     *os.File
	identity os.FileInfo
}

func closeAbandonedSealedArchives(files []abandonedSealedArchive) error {
	var problems []error
	for _, item := range files {
		if err := item.file.Close(); err != nil {
			problems = append(problems, ErrUnsafeSealedArchive)
		}
	}
	return errors.Join(problems...)
}

// The parent directory flock closes the gap between CreateTemp and locking
// the new temporary FILE. This is separate from a writer's file flock, which
// stays held until the temporary name has been removed after publication.
func lockSealedArchiveParent(ctx context.Context, path string) (*os.File, error) {
	if ctx == nil || verifySealedArchiveParent(path) != nil {
		return nil, ErrUnsafeSealedArchive
	}
	for attempt := 0; attempt < 40; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|
			syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, ErrUnsafeSealedArchive
		}
		dir := os.NewFile(uintptr(fd), path)
		if dir == nil {
			_ = syscall.Close(fd)
			return nil, ErrUnsafeSealedArchive
		}
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			opened, statErr := dir.Stat()
			onPath, pathErr := os.Lstat(path)
			if statErr != nil || pathErr != nil || !os.SameFile(opened, onPath) ||
				verifySealedArchiveParent(path) != nil {
				_ = dir.Close()
				return nil, ErrUnsafeSealedArchive
			}
			return dir, nil
		}
		_ = dir.Close()
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return nil, ErrUnsafeSealedArchive
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, ErrUnsafeSealedArchive
}

// sameLeasedSealedArchiveParent requires the canonical pathname to still
// identify the exact directory inode protected by the existing parent flock.
// A same-UID process can ignore advisory flock and rename the parent during
// retention inspection, so never fsync an unrelated replacement pathname.
func sameLeasedSealedArchiveParent(path string, lock *os.File) bool {
	if lock == nil || verifySealedArchiveParent(path) != nil {
		return false
	}
	opened, err := lock.Stat()
	if err != nil || !opened.IsDir() || opened.Mode().Perm() != 0o700 {
		return false
	}
	atPath, err := os.Lstat(path)
	return err == nil && os.SameFile(opened, atPath)
}

func recognizedSealedArchiveTemporary(name string) bool {
	if !strings.HasPrefix(name, sealedArchiveTemporaryPrefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, sealedArchiveTemporaryPrefix)
	if len(suffix) < 6 || len(suffix) > 32 {
		return false
	}
	for _, character := range suffix {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

// openLeasedSealedRetentionInventoryReader opens an independent directory
// stream from the already-flocked parent inode. Scanning the flock descriptor
// directly would permanently advance its directory offset, so a repeated
// inventory could otherwise incorrectly report an empty parent.
func openLeasedSealedRetentionInventoryReader(parent *os.File) (*os.File, error) {
	if parent == nil || !sameLeasedSealedArchiveParent(parent.Name(), parent) {
		return nil, ErrUnsafeSealedArchive
	}
	original, err := parent.Stat()
	if err != nil || !original.IsDir() || original.Mode().Perm() != 0o700 {
		return nil, ErrUnsafeSealedArchive
	}
	fd, err := syscall.Openat(int(parent.Fd()), ".",
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeSealedArchive
	}
	reader := os.NewFile(uintptr(fd), parent.Name())
	if reader == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafeSealedArchive
	}
	info, err := reader.Stat()
	if err != nil || !os.SameFile(original, info) ||
		!sameLeasedSealedArchiveParent(parent.Name(), parent) {
		_ = reader.Close()
		return nil, ErrUnsafeSealedArchive
	}
	return reader, nil
}

// Called only with the exclusive flock on an original private parent inode.
// Entries are opened via openat on the same parent, then independently
// compared with their current pathname. Active writers remain protected by
// their own file flocks; neither published nor unknown files are deleted.
func inspectSealedArchiveDirectory(
	ctx context.Context, parent *os.File,
) (SealedArchiveRetentionReport, []abandonedSealedArchive, error) {
	return inspectSealedArchiveDirectoryProbed(ctx, parent, nil)
}

// afterInventory is a package-private Linux fault injection checkpoint
// after ReadDir but before any child lookup. Production passes nil.
func inspectSealedArchiveDirectoryProbed(
	ctx context.Context, parent *os.File, afterInventory func(),
) (report SealedArchiveRetentionReport, candidates []abandonedSealedArchive, err error) {
	if ctx == nil || parent == nil ||
		!sameLeasedSealedArchiveParent(parent.Name(), parent) {
		return report, nil, ErrUnsafeSealedArchive
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, closeAbandonedSealedArchives(candidates))
			candidates = nil
		}
	}()
	reader, err := openLeasedSealedRetentionInventoryReader(parent)
	if err != nil {
		return report, nil, ErrUnsafeSealedArchive
	}
	entries, readErr := reader.ReadDir(MaxRetainedSealedArchives + MaxSealedArchiveTemporaryFiles + 1)
	closeErr := reader.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil ||
		len(entries) > MaxRetainedSealedArchives+MaxSealedArchiveTemporaryFiles {
		return report, candidates, ErrUnsafeSealedArchive
	}
	if afterInventory != nil {
		afterInventory()
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return report, candidates, ctx.Err()
		}
		if !sameLeasedSealedArchiveParent(parent.Name(), parent) {
			return report, candidates, ErrUnsafeSealedArchive
		}
		name := entry.Name()
		path := filepath.Join(parent.Name(), name)
		temporary := recognizedSealedArchiveTemporary(name)
		completed := validSealedArchivePath(path)
		if (!temporary && !completed) || !entry.Type().IsRegular() {
			// Reject unknown entries, directories, symlinks and legacy
			// staging names. No fallback to another namespace.
			return report, candidates, ErrUnsafeSealedArchive
		}
		// Open by dirfd, never by the mutable parent pathname. NONBLOCK
		// prevents a substituted FIFO from blocking while fstat rejects it.
		fd, openErr := syscall.Openat(int(parent.Fd()), name,
			syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			return report, candidates, ErrUnsafeSealedArchive
		}
		file := os.NewFile(uintptr(fd), path)
		if file == nil {
			_ = syscall.Close(fd)
			return report, candidates, ErrUnsafeSealedArchive
		}
		info, statErr := file.Stat()
		atPath, pathErr := os.Lstat(path)
		if statErr != nil || pathErr != nil || !os.SameFile(info, atPath) ||
			!info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
			info.Size() < 0 || info.Size() > MaxSealedArchiveBytes {
			_ = file.Close()
			return report, candidates, ErrUnsafeSealedArchive
		}
		ownership, valid := info.Sys().(*syscall.Stat_t)
		if !valid || int(ownership.Uid) != os.Getuid() ||
			ownership.Nlink < 1 || ownership.Nlink > 2 {
			_ = file.Close()
			return report, candidates, ErrUnsafeSealedArchive
		}
		if completed {
			closeErr := file.Close()
			if closeErr != nil ||
				info.Size() <= int64(sealedArchiveHeaderBytes+sealedArchiveTagBytes+4) ||
				!singleOwnedSealedFile(info) {
				return report, candidates, ErrUnsafeSealedArchive
			}
			report.Completed++
			report.CompletedBytes += info.Size()
			if report.Completed > MaxRetainedSealedArchives ||
				report.CompletedBytes > MaxRetainedSealedArchiveBytes {
				return report, candidates, ErrUnsafeSealedArchive
			}
			continue
		}
		report.Temporary++
		if report.Temporary > MaxSealedArchiveTemporaryFiles {
			_ = file.Close()
			return report, candidates, ErrUnsafeSealedArchive
		}
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			_ = file.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
				report.Active++
				continue
			}
			return report, candidates, ErrUnsafeSealedArchive
		}
		// Crash between hard-link publication and temp name removal is
		// ambiguous. Never reclaim a two-link temp, even if unlocked.
		if !singleOwnedSealedFile(info) {
			_ = file.Close()
			return report, candidates, ErrUnsafeSealedArchive
		}
		candidates = append(candidates, abandonedSealedArchive{
			name: name, file: file, identity: info,
		})
	}
	if !sameLeasedSealedArchiveParent(parent.Name(), parent) {
		return report, candidates, ErrUnsafeSealedArchive
	}
	report.AtCapacity = report.Completed >= MaxRetainedSealedArchives ||
		report.CompletedBytes >= MaxRetainedSealedArchiveBytes
	return report, candidates, nil
}

// InspectSealedArchiveRetention returns ONLY bounded metadata; it never
// removes any file. Published archives are counted, not decrypted or trusted.
func InspectSealedArchiveRetention(
	ctx context.Context, parent string,
) (report SealedArchiveRetentionReport, err error) {
	lock, err := lockSealedArchiveParent(ctx, parent)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	report, candidates, err := inspectSealedArchiveDirectory(ctx, lock)
	err = errors.Join(err, closeAbandonedSealedArchives(candidates))
	return report, err
}

// ReclaimAbandonedSealedArchives removes ONLY v2 temporary ciphertext files
// proven unlocked, current-UID-owned, single-linked, ordinary 0600 and bounded.
// A full directory scan completes before any unlink; known completed archives
// are never touched. Unknown entries fail closed, without recursive deletion.
func ReclaimAbandonedSealedArchives(
	ctx context.Context, parent string,
) (SealedArchiveRetentionReport, error) {
	return reclaimAbandonedSealedArchivesProbed(ctx, parent, nil)
}

// The private beforeParentSync checkpoint makes a deterministic rename
// regression possible after a successful unlink. Production passes nil;
// this callback never leaves the backupclosure package.
func reclaimAbandonedSealedArchivesProbed(
	ctx context.Context, parent string, beforeParentSync func(),
) (report SealedArchiveRetentionReport, err error) {
	lock, err := lockSealedArchiveParent(ctx, parent)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	report, candidates, err := inspectSealedArchiveDirectory(ctx, lock)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, closeAbandonedSealedArchives(candidates)) }()
	for _, item := range candidates {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if !sameLeasedSealedArchiveParent(parent, lock) {
			return report, ErrUnsafeSealedArchive
		}
		opened, statErr := item.file.Stat()
		atPath, pathErr := os.Lstat(filepath.Join(parent, item.name))
		if statErr != nil || pathErr != nil ||
			!os.SameFile(item.identity, opened) || !os.SameFile(opened, atPath) ||
			opened.Mode().Perm() != 0o600 || !singleOwnedSealedFile(opened) ||
			opened.Size() > MaxSealedArchiveBytes {
			return report, ErrUnsafeSealedArchive
		}
		if err := syscall.Unlinkat(int(lock.Fd()), item.name); err != nil {
			return report, ErrUnsafeSealedArchive
		}
		report.Reclaimed++
	}
	if report.Reclaimed != 0 {
		if beforeParentSync != nil {
			beforeParentSync()
		}
		// Persistence must target the original flocked parent inode, not
		// whatever now occupies parent after the destructive unlink.
		if !sameLeasedSealedArchiveParent(parent, lock) ||
			lock.Sync() != nil ||
			!sameLeasedSealedArchiveParent(parent, lock) {
			return report, ErrUnsafeSealedArchive
		}
	}
	if !sameLeasedSealedArchiveParent(parent, lock) {
		return report, ErrUnsafeSealedArchive
	}
	return report, nil
}

// createLeasedSealedArchiveTemp coordinates inventory capacity and the
// creation-to-file-flock gap under the same parent flock as the scavenger.
func createLeasedSealedArchiveTemp(
	ctx context.Context, parent string, requestedBytes int64,
) (file *os.File, err error) {
	if requestedBytes <= 0 || requestedBytes > MaxSealedArchiveBytes {
		return nil, ErrUnsafeSealedArchive
	}
	lock, err := lockSealedArchiveParent(ctx, parent)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			if file != nil {
				name := file.Name()
				info, _ := file.Stat()
				_ = file.Close()
				if atPath, statErr := os.Lstat(name); statErr == nil &&
					info != nil && os.SameFile(atPath, info) {
					_ = os.Remove(name)
				}
				file = nil
			}
			err = errors.Join(err, ErrUnsafeSealedArchive)
		}
	}()
	report, candidates, err := inspectSealedArchiveDirectory(ctx, lock)
	closeErr := closeAbandonedSealedArchives(candidates)
	// Every active v2 temporary reserves one eventual published slot and
	// its worst-case full archive bytes. Otherwise two parallel writers can
	// both observe seven published files, pass, and publish a ninth.
	if err != nil || closeErr != nil || report.AtCapacity ||
		report.Temporary >= MaxSealedArchiveTemporaryFiles ||
		report.Completed+report.Temporary >= MaxRetainedSealedArchives ||
		report.CompletedBytes+int64(report.Temporary)*MaxSealedArchiveBytes >
			MaxRetainedSealedArchiveBytes-requestedBytes {
		return nil, ErrUnsafeSealedArchive
	}
	file, err = os.CreateTemp(parent, sealedArchiveTemporaryPrefix)
	if err != nil {
		return nil, ErrUnsafeSealedArchive
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		name := file.Name()
		_ = file.Close()
		_ = os.Remove(name)
		return nil, ErrUnsafeSealedArchive
	}
	return file, nil
}
