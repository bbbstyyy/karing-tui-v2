//go:build linux

package backupclosure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	MaxInertRestoreCandidates   = 8
	inertRestoreCandidatePrefix = ".ktui-restore-v1-"
	inertRestoreCipherName      = "candidate.ktbackup"
)

var (
	ErrUnsafeInertRestoreCandidate = errors.New("inert encrypted restore candidate refused")
	ErrInertRestoreCandidateBusy   = errors.New("inert encrypted restore candidate has an active lease")
)

// InertRestoreCandidate represents an EXCLUSIVE, cross-process Linux flock
// on a private directory containing exactly one independently copied,
// authenticated encrypted archive. Nothing plaintext or executable is staged.
// The lock expires on process death; the encrypted candidate does not.
//
// The owner must bring the symmetric key again after restart and pass the
// full authentication and SQLite/domain preflight before re-adoption. This
// is NOT a durable activation lease, a restore permit, or a backup index.
type InertRestoreCandidate struct {
	mu                sync.Mutex
	directory         string
	parent            string
	archive           string
	dir               *os.File
	directoryIdentity os.FileInfo
	receipt           InertArchivePreflight
}

func validInertRestoreCandidateDir(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	name := filepath.Base(path)
	if !strings.HasPrefix(name, inertRestoreCandidatePrefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, inertRestoreCandidatePrefix)
	if len(suffix) < 6 || len(suffix) > 32 {
		return false
	}
	for _, r := range suffix {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func verifyCandidateDirLock(path string, lock *os.File) (os.FileInfo, error) {
	if !validInertRestoreCandidateDir(path) || lock == nil ||
		verifySealedArchiveParent(path) != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	opened, err := lock.Stat()
	if err != nil || !opened.IsDir() || opened.Mode().Perm() != 0o700 {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	onPath, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, onPath) ||
		!onPath.IsDir() || onPath.Mode().Perm() != 0o700 {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	return opened, nil
}

func openLockedInertRestoreCandidate(path string) (*InertRestoreCandidate, error) {
	if !validInertRestoreCandidateDir(path) || verifySealedArchiveParent(path) != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|
		syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	lock := os.NewFile(uintptr(fd), path)
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrInertRestoreCandidateBusy
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	identity, err := verifyCandidateDirLock(path, lock)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	return &InertRestoreCandidate{
		directory:         path,
		parent:            filepath.Dir(path),
		archive:           filepath.Join(path, inertRestoreCipherName),
		dir:               lock,
		directoryIdentity: identity,
	}, nil
}

// inspectCandidateParent uses the locked parent fd to refuse unknown entries,
// symlinks and quota overruns. It never removes a completed/incomplete scope.
func inspectCandidateParent(ctx context.Context, lock *os.File) (int, error) {
	if ctx == nil || lock == nil {
		return 0, ErrUnsafeInertRestoreCandidate
	}
	entries, err := lock.ReadDir(MaxInertRestoreCandidates + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, ErrUnsafeInertRestoreCandidate
	}
	if len(entries) > MaxInertRestoreCandidates {
		return 0, ErrUnsafeInertRestoreCandidate
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		path := filepath.Join(lock.Name(), entry.Name())
		if !validInertRestoreCandidateDir(path) || !entry.IsDir() ||
			verifySealedArchiveParent(path) != nil {
			return 0, ErrUnsafeInertRestoreCandidate
		}
	}
	return len(entries), nil
}

func inspectInertCandidateFile(candidate *InertRestoreCandidate, allowAbsent bool) (os.FileInfo, error) {
	if candidate == nil || candidate.dir == nil ||
		candidate.directoryIdentity == nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	opened, err := verifyCandidateDirLock(candidate.directory, candidate.dir)
	if err != nil || !os.SameFile(candidate.directoryIdentity, opened) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Use a fresh directory fd on every inspection. ReadDir on the
	// long-lived lock descriptor would advance its offset and silently hide
	// entries on the second Verify/Discard.
	fd, err := syscall.Open(candidate.directory, syscall.O_RDONLY|
		syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	reader := os.NewFile(uintptr(fd), candidate.directory)
	onFD, err := reader.Stat()
	if err != nil || !os.SameFile(candidate.directoryIdentity, onFD) {
		_ = reader.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	entries, err := reader.ReadDir(2)
	closeErr := reader.Close()
	if (err != nil && !errors.Is(err, io.EOF)) || closeErr != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if len(entries) == 0 && allowAbsent {
		return nil, nil
	}
	if len(entries) != 1 || entries[0].Name() != inertRestoreCipherName ||
		!entries[0].Type().IsRegular() {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	source, err := openSealedArchiveNoFollow(candidate.archive)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	defer source.Close()
	identity, err := source.Stat()
	if err != nil || !identity.Mode().IsRegular() ||
		identity.Mode().Perm() != 0o600 ||
		!singleOwnedSealedFile(identity) ||
		identity.Size() < 0 || identity.Size() > MaxSealedArchiveBytes {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	atPath, err := os.Lstat(candidate.archive)
	if err != nil || !os.SameFile(identity, atPath) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	return identity, nil
}

// StageInertRestoreCandidate copies ONLY the ciphertext from an already
// authenticated, fully SQLite-audited source archive to an independently
// UID-owned encrypted candidate scope. The separate 0700 parent must exist.
//
// Directory flock + count limit enforce at most eight persistent candidates.
// New scopes survive Close/process death, but cannot be re-adopted without
// supplying the original key and re-running the full read-only preflight.
// No daemon state, selection, SQLite file or running core is touched.
func StageInertRestoreCandidate(
	ctx context.Context, sourceArchive, candidateParent string, key [32]byte,
) (result *InertRestoreCandidate, err error) {
	if ctx == nil || key == ([32]byte{}) ||
		!validSealedArchivePath(sourceArchive) ||
		verifySealedArchiveParent(candidateParent) != nil ||
		filepath.Dir(sourceArchive) == candidateParent {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*sealedArchiveTimeout)
	defer cancel()
	report, err := PreflightInertArchive(ctx, sourceArchive, key, nil)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.RestoreReady || report.RestoreSupported ||
		!validLowerSHA(report.ArchiveSHA256) || report.ArchiveBytes <= 0 {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if requireSealedArchiveSpace(candidateParent, report.ArchiveBytes) != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Parent flock serializes slot reservations with other stage operations,
	// and closes the new-dir -> child-lock gap against other adopters.
	parentLock, err := lockSealedArchiveParent(ctx, candidateParent)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	var candidate *InertRestoreCandidate
	func() {
		defer parentLock.Close()
		var count int
		count, err = inspectCandidateParent(ctx, parentLock)
		if err != nil || count >= MaxInertRestoreCandidates {
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		var directory string
		directory, err = os.MkdirTemp(candidateParent, inertRestoreCandidatePrefix)
		if err != nil {
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		candidate, err = openLockedInertRestoreCandidate(directory)
		if err != nil {
			// Only remove an empty, specifically named directory created by
			// this call. Never recursively remove an unknown scope.
			_ = os.Remove(directory)
			return
		}
		if syncSealedArchiveDir(candidateParent) != nil {
			err = ErrUnsafeInertRestoreCandidate
		}
	}()
	if err != nil || candidate == nil {
		if candidate != nil {
			_ = candidate.discardLocked(false)
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, candidate.discardLocked(false))
		}
	}()
	if err = copyInertCandidateCipher(ctx, sourceArchive, candidate.archive, report); err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if err = syncSealedArchiveDir(candidate.directory); err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if err = syncSealedArchiveDir(candidateParent); err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	var checked InertArchivePreflight
	checked, err = PreflightInertArchive(ctx, candidate.archive, key, nil)
	if err != nil || !sameInertPreflightEvidence(report, checked) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	candidate.receipt = checked
	return candidate, nil
}

func sameInertPreflightEvidence(a, b InertArchivePreflight) bool {
	return a.ArchiveSHA256 == b.ArchiveSHA256 &&
		a.InventorySHA256 == b.InventorySHA256 &&
		a.ArchiveBytes == b.ArchiveBytes &&
		a.Format == b.Format && a.StorageSchema == b.StorageSchema &&
		a.SchemaCatalogVerified && b.SchemaCatalogVerified &&
		a.SQLiteLogicalVerified && b.SQLiteLogicalVerified &&
		!a.RestoreReady && !b.RestoreReady &&
		!a.RestoreSupported && !b.RestoreSupported
}

func copyInertCandidateCipher(
	ctx context.Context, sourcePath, targetPath string, expected InertArchivePreflight,
) error {
	file, err := openSealedArchiveNoFollow(sourcePath)
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || verifySealedFile(file, sourcePath, info, expected.ArchiveBytes, true) != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	fd, err := syscall.Open(targetPath, syscall.O_WRONLY|syscall.O_CREAT|
		syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	target := os.NewFile(uintptr(fd), targetPath)
	if target == nil {
		_ = syscall.Close(fd)
		return ErrUnsafeInertRestoreCandidate
	}
	defer target.Close()
	hasher := sha256.New()
	n, err := io.CopyN(io.MultiWriter(target, hasher),
		sealedContextReader{ctx: ctx, src: file}, expected.ArchiveBytes)
	if err != nil || n != expected.ArchiveBytes ||
		hex.EncodeToString(hasher.Sum(nil)) != expected.ArchiveSHA256 {
		return ErrUnsafeInertRestoreCandidate
	}
	var trailing [1]byte
	if _, err := file.Read(trailing[:]); !errors.Is(err, io.EOF) {
		return ErrUnsafeInertRestoreCandidate
	}
	atSource, err := os.Lstat(sourcePath)
	after, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(info, atSource) ||
		!os.SameFile(info, after) || info.Size() != after.Size() ||
		!info.ModTime().Equal(after.ModTime()) ||
		verifySealedFile(file, sourcePath, info, expected.ArchiveBytes, true) != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	targetInfo, err := target.Stat()
	if err != nil || verifySealedFile(target, targetPath, targetInfo, n, true) != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	if target.Sync() != nil || ctx.Err() != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	return nil
}

// ReopenInertRestoreCandidate reacquires the directory lease after Close or
// process death. It performs a NEW complete cryptographic and logical
// preflight using the explicitly re-supplied key. Stale report data from a
// former process is never sufficient to reclaim a lease.
func ReopenInertRestoreCandidate(
	ctx context.Context, directory string, key [32]byte,
) (_ *InertRestoreCandidate, err error) {
	if ctx == nil || key == ([32]byte{}) ||
		!validInertRestoreCandidateDir(directory) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parent, err := lockSealedArchiveParent(ctx, filepath.Dir(directory))
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	var candidate *InertRestoreCandidate
	func() {
		defer parent.Close()
		if _, err = inspectCandidateParent(ctx, parent); err == nil {
			candidate, err = openLockedInertRestoreCandidate(directory)
		}
	}()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = candidate.Close()
		}
	}()
	if _, err = inspectInertCandidateFile(candidate, false); err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	var report InertArchivePreflight
	report, err = PreflightInertArchive(ctx, candidate.archive, key, nil)
	if err != nil || !report.SchemaCatalogVerified ||
		!report.SQLiteLogicalVerified || report.RestoreReady ||
		report.RestoreSupported {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	candidate.receipt = report
	return candidate, nil
}

// Directory is an opaque internal, private ciphertext scope locator, not a
// public share link or authorization token.
func (c *InertRestoreCandidate) Directory() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.directory
}

// Verify always reruns complete authentication on the retained ciphertext,
// including SQLite domain checks, while holding the exclusive directory lock.
func (c *InertRestoreCandidate) Verify(
	ctx context.Context, key [32]byte,
) (InertArchivePreflight, error) {
	var none InertArchivePreflight
	if c == nil || ctx == nil || key == ([32]byte{}) {
		return none, ErrUnsafeInertRestoreCandidate
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dir == nil {
		return none, ErrUnsafeInertRestoreCandidate
	}
	before, err := inspectInertCandidateFile(c, false)
	if err != nil {
		return none, ErrUnsafeInertRestoreCandidate
	}
	report, err := PreflightInertArchive(ctx, c.archive, key, nil)
	if err != nil || !sameInertPreflightEvidence(c.receipt, report) {
		return none, ErrUnsafeInertRestoreCandidate
	}
	after, err := inspectInertCandidateFile(c, false)
	if err != nil || !os.SameFile(before, after) ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return none, ErrUnsafeInertRestoreCandidate
	}
	return report, nil
}

// Close RELEASES the current process lease but deliberately retains the
// independently encrypted candidate across restarts. It does not delete the
// candidate, mark it restorable, or update any live database/core state.
func (c *InertRestoreCandidate) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dir == nil {
		return nil
	}
	err := c.dir.Close()
	c.dir = nil
	return err
}

// Discard is an explicit INTERNAL lifecycle action, not an automated GC.
// Only one locked, known encrypted file can be unlinked; unknown siblings,
// link ambiguity, symlinks and mismatched directory inode fail closed.
func (c *InertRestoreCandidate) Discard(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrUnsafeInertRestoreCandidate
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dir == nil {
		return ErrUnsafeInertRestoreCandidate
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.discardLocked(true)
}

func (c *InertRestoreCandidate) discardLocked(requireFile bool) error {
	if c == nil || c.dir == nil {
		return ErrUnsafeInertRestoreCandidate
	}
	defer func() {
		_ = c.dir.Close()
		c.dir = nil
	}()
	file, err := inspectInertCandidateFile(c, !requireFile)
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	if file != nil {
		// unlinkat under the locked candidate directory, never RemoveAll.
		if err := syscall.Unlinkat(int(c.dir.Fd()), inertRestoreCipherName); err != nil {
			return ErrUnsafeInertRestoreCandidate
		}
	}
	if syncSealedArchiveDir(c.directory) != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	atDir, err := os.Lstat(c.directory)
	if err != nil || !os.SameFile(c.directoryIdentity, atDir) {
		return ErrUnsafeInertRestoreCandidate
	}
	if err := os.Remove(c.directory); err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	if syncSealedArchiveDir(c.parent) != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	return nil
}
