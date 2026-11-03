//go:build linux

package backupclosure

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
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

// inertCandidateErrnoClass converts syscall failures to a bounded vocabulary.
// Only the private test probe receives these labels. The exported API still
// returns the same fail-closed sentinel without filenames or OS error text.
func inertCandidateErrnoClass(err error) string {
	switch {
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return "storage_capacity"
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE):
		return "descriptor_pressure"
	case errors.Is(err, syscall.EWOULDBLOCK), errors.Is(err, syscall.EAGAIN):
		return "lock_contention"
	case errors.Is(err, syscall.EINTR):
		return "interrupted"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "permission"
	case errors.Is(err, syscall.ENOENT):
		return "missing_path"
	case errors.Is(err, syscall.ELOOP):
		return "symlink"
	case errors.Is(err, syscall.EIO):
		return "io_error"
	default:
		return "other"
	}
}

func recordInertCandidateSyscallFailure(
	probe func(string) bool, operation string, err error,
) {
	if probe != nil {
		// Callers pass fixed operation constants. The class cannot contain
		// private paths, arbitrary error strings, archive content or keys.
		_ = probe(operation + "_failed_" + inertCandidateErrnoClass(err))
	}
}

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
	parentIdentity    os.FileInfo
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

// sameInertCandidateParentIdentity rejects a candidate whose parent directory
// has been replaced even if the identical leased child inode and ciphertext
// have been moved back to the original absolute path. The parent is a trust
// boundary distinct from the child directory flock.
func sameInertCandidateParentIdentity(path string, original os.FileInfo) bool {
	if original == nil || !original.IsDir() || original.Mode().Perm() != 0o700 ||
		verifySealedArchiveParent(path) != nil {
		return false
	}
	onPath, err := os.Lstat(path)
	return err == nil && os.SameFile(original, onPath)
}

func openLockedInertRestoreCandidate(path string) (*InertRestoreCandidate, error) {
	return openLockedInertRestoreCandidateProbed(path, nil)
}

// The private probe only receives bounded constant stage identifiers.
// Production opens a candidate with a nil probe and identical safety checks.
// Failed probe checkpoints close all acquired descriptors before returning.
func openLockedInertRestoreCandidateProbed(
	path string, probe func(string) bool,
) (*InertRestoreCandidate, error) {
	return openLockedInertRestoreCandidateAtParentProbed(path, nil, probe)
}

// openLockedInertRestoreCandidateAtParentProbed anchors the child directory
// open to an already flocked parent inode when one is available. A pathname
// open could acquire a flock on an unrelated child if the parent is renamed
// after inventory. Direct test helpers without a parent retain their original
// pathname behavior and all call paths still check the canonical identity.
func openLockedInertRestoreCandidateAtParentProbed(
	path string, parent *os.File, probe func(string) bool,
) (*InertRestoreCandidate, error) {
	checkpoint := func(stage string) bool {
		return probe == nil || probe(stage)
	}
	if !validInertRestoreCandidateDir(path) || verifySealedArchiveParent(path) != nil ||
		(parent != nil && !sameInertCandidateParentLease(filepath.Dir(path), parent)) {
		if probe != nil {
			_ = probe("scope_child_precheck_refused")
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("scope_child_open") {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY |
		syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	var fd int
	var err error
	if parent != nil {
		fd, err = syscall.Openat(int(parent.Fd()), filepath.Base(path), flags, 0)
	} else {
		fd, err = syscall.Open(path, flags, 0)
	}
	if err != nil {
		recordInertCandidateSyscallFailure(probe, "scope_child_open", err)
		return nil, ErrUnsafeInertRestoreCandidate
	}
	lock := os.NewFile(uintptr(fd), path)
	if !checkpoint("scope_child_fd_opened") || !checkpoint("scope_child_flock") {
		_ = lock.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		recordInertCandidateSyscallFailure(probe, "scope_child_flock", err)
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrInertRestoreCandidateBusy
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("scope_child_lock_held") || !checkpoint("scope_child_identity") {
		_ = lock.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	identity, err := verifyCandidateDirLock(path, lock)
	if err != nil ||
		(parent != nil && !sameInertCandidateParentLease(filepath.Dir(path), parent)) {
		if probe != nil {
			_ = probe("scope_child_identity_refused")
		}
		_ = lock.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("scope_child_identity_verified") {
		_ = lock.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	parentPath := filepath.Dir(path)
	var parentIdentity os.FileInfo
	if parent != nil {
		parentIdentity, err = parent.Stat()
	} else {
		parentIdentity, err = os.Lstat(parentPath)
	}
	if err != nil || !sameInertCandidateParentIdentity(parentPath, parentIdentity) {
		_ = lock.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	return &InertRestoreCandidate{
		directory:         path,
		parent:            parentPath,
		archive:           filepath.Join(path, inertRestoreCipherName),
		dir:               lock,
		directoryIdentity: identity,
		parentIdentity:    parentIdentity,
	}, nil
}

// createInertScopeAtLeasedParent uses the already-flocked parent DIRECTORY
// inode instead of resolving its mutable pathname during creation. The
// returned identity comes from a child fd opened relative to that same
// parent. The caller must separately check the parent and child's canonical
// path identities before adoption. After a hostile rename, refusing to
// remove an unreachable empty scope is safer than unlinking a foreign path.
func createInertScopeAtLeasedParent(
	parent *os.File, parentPath string,
) (string, os.FileInfo, error) {
	if parent == nil || !filepath.IsAbs(parentPath) ||
		filepath.Clean(parentPath) != parentPath {
		return "", nil, ErrUnsafeInertRestoreCandidate
	}
	opened, err := parent.Stat()
	if err != nil || !opened.IsDir() || opened.Mode().Perm() != 0o700 {
		return "", nil, ErrUnsafeInertRestoreCandidate
	}
	owner, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Getuid() {
		return "", nil, ErrUnsafeInertRestoreCandidate
	}
	// 96 bits of cryptographic randomness; 24 lowercase hex characters
	// satisfy the existing candidate scope name validator. Collisions are
	// retried only a bounded number of times, never by falling back to a
	// path-based MkdirTemp.
	for attempt := 0; attempt < 8; attempt++ {
		var randomName [12]byte
		if _, err := rand.Read(randomName[:]); err != nil {
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		name := inertRestoreCandidatePrefix + hex.EncodeToString(randomName[:])
		if err := syscall.Mkdirat(int(parent.Fd()), name, 0o700); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			return "", nil, err
		}
		fd, err := syscall.Openat(int(parent.Fd()), name,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		directory := filepath.Join(parentPath, name)
		child := os.NewFile(uintptr(fd), directory)
		if child == nil {
			_ = syscall.Close(fd)
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		created, statErr := child.Stat()
		closeErr := child.Close()
		if statErr != nil || closeErr != nil || !created.IsDir() ||
			created.Mode().Perm() != 0o700 {
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		return directory, created, nil
	}
	return "", nil, ErrUnsafeInertRestoreCandidate
}

// sameInertCandidateParentLease checks that the pathname still refers
// to the same private directory inode holding the parent flock.
func sameInertCandidateParentLease(path string, parent *os.File) bool {
	if parent == nil || verifySealedArchiveParent(path) != nil {
		return false
	}
	opened, err := parent.Stat()
	if err != nil || !opened.IsDir() || opened.Mode().Perm() != 0o700 {
		return false
	}
	onPath, err := os.Lstat(path)
	return err == nil && os.SameFile(opened, onPath)
}

// syncPinnedInertCandidateParent persists the original leased parent inode
// without reopening a mutable pathname after a potentially lengthy ciphertext
// copy. A freshly substituted owner-private parent cannot be fsynced or
// mistaken for the parent that reserved the candidate slot.
func syncPinnedInertCandidateParent(path string, pinned *os.File) error {
	if !sameInertCandidateParentLease(path, pinned) {
		return ErrUnsafeInertRestoreCandidate
	}
	if err := pinned.Sync(); err != nil ||
		!sameInertCandidateParentLease(path, pinned) {
		return ErrUnsafeInertRestoreCandidate
	}
	return nil
}

// sameNewInertScopeIdentity checks whether the path still names the exact
// private inode captured immediately after creation. A path-only cleanup is
// unsafe after a test hook or another same-UID actor replaces that pathname.
// This is a best-effort identity guard, not an atomic compare-and-unlink.
func sameNewInertScopeIdentity(path string, created os.FileInfo) bool {
	if created == nil || !created.IsDir() || created.Mode().Perm() != 0o700 ||
		!validInertRestoreCandidateDir(path) || verifySealedArchiveParent(path) != nil {
		return false
	}
	current, err := os.Lstat(path)
	return err == nil && current.IsDir() && current.Mode().Perm() == 0o700 &&
		os.SameFile(created, current)
}

// removeNewEmptyInertScopeIfIdentical is ONLY for failed Stage cleanup
// before candidate adoption. The parent must still be the exact flocked
// inode under which mkdirat created the child. Never fall back to os.Remove
// on a mutable absolute path, including when the same child inode has been
// moved under a substituted private parent.
func removeNewEmptyInertScopeIfIdentical(
	parent *os.File, path string, created os.FileInfo,
) error {
	if parent == nil ||
		!sameInertCandidateParentLease(filepath.Dir(path), parent) ||
		!sameNewInertScopeIdentity(path, created) {
		return ErrUnsafeInertRestoreCandidate
	}
	name := filepath.Base(path)
	fd, err := syscall.Openat(int(parent.Fd()), name,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	child := os.NewFile(uintptr(fd), path)
	if child == nil {
		_ = syscall.Close(fd)
		return ErrUnsafeInertRestoreCandidate
	}
	defer child.Close()
	onFD, err := child.Stat()
	if err != nil || !onFD.IsDir() || onFD.Mode().Perm() != 0o700 ||
		!os.SameFile(created, onFD) {
		return ErrUnsafeInertRestoreCandidate
	}
	// AT_REMOVEDIR itself refuses nonempty directories; never recursively
	// delete ciphertext, symlinks, or unknown files during failed staging.
	if !sameInertCandidateParentLease(filepath.Dir(path), parent) ||
		!sameNewInertScopeIdentity(path, created) {
		return ErrUnsafeInertRestoreCandidate
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	// Durability must persist against the same leased parent inode, never
	// a path reopened after removal.
	if parent.Sync() != nil ||
		!sameInertCandidateParentLease(filepath.Dir(path), parent) {
		return ErrUnsafeInertRestoreCandidate
	}
	return nil
}

// openLockedInertCandidateInventoryReader obtains an independent directory
// stream from the already leased inode. Reopening candidate.directory by name
// would let a same-UID actor redirect the inventory scan between the initial
// identity check and ReadDir. A fresh openat(".", ...) avoids sharing the
// long-lived flock fd's directory offset across Verify and Discard.
func openLockedInertCandidateInventoryReader(
	candidate *InertRestoreCandidate,
) (*os.File, error) {
	if candidate == nil || candidate.dir == nil ||
		candidate.directoryIdentity == nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	fd, err := syscall.Openat(int(candidate.dir.Fd()), ".",
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	reader := os.NewFile(uintptr(fd), candidate.directory)
	if reader == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafeInertRestoreCandidate
	}
	onFD, err := reader.Stat()
	if err != nil || !onFD.IsDir() || onFD.Mode().Perm() != 0o700 ||
		!os.SameFile(candidate.directoryIdentity, onFD) {
		_ = reader.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	return reader, nil
}

// openLockedInertCandidateParentInventoryReader obtains a fresh directory
// stream from the flocked parent inode. ReadDir on the lock fd would consume
// its persistent directory offset; reopening the parent by pathname would
// select a substituted directory if a same-UID actor ignores the flock.
func openLockedInertCandidateParentInventoryReader(lock *os.File) (*os.File, error) {
	if lock == nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	identity, err := lock.Stat()
	if err != nil || !identity.IsDir() || identity.Mode().Perm() != 0o700 {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	owner, ok := identity.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Getuid() {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	fd, err := syscall.Openat(int(lock.Fd()), ".",
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	reader := os.NewFile(uintptr(fd), lock.Name())
	if reader == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafeInertRestoreCandidate
	}
	opened, err := reader.Stat()
	if err != nil || !opened.IsDir() || opened.Mode().Perm() != 0o700 ||
		!os.SameFile(identity, opened) {
		_ = reader.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	return reader, nil
}

// inspectCandidateParent rejects unknown entries, symlinks, non-private
// directories and quota overruns. The inventory stream and each child open
// are anchored to the same leased parent inode. No files are removed.
func inspectCandidateParent(ctx context.Context, lock *os.File) (int, error) {
	return inspectCandidateParentProbed(ctx, lock, nil)
}

// The private afterInventory hook permits deterministic post-ReadDir
// substitution regressions; production always passes nil.
func inspectCandidateParentProbed(
	ctx context.Context, lock *os.File, afterInventory func(),
) (int, error) {
	if ctx == nil || lock == nil ||
		!sameInertCandidateParentLease(lock.Name(), lock) {
		return 0, ErrUnsafeInertRestoreCandidate
	}
	reader, err := openLockedInertCandidateParentInventoryReader(lock)
	if err != nil {
		return 0, err
	}
	entries, readErr := reader.ReadDir(MaxInertRestoreCandidates + 1)
	closeErr := reader.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) ||
		closeErr != nil || len(entries) > MaxInertRestoreCandidates {
		return 0, ErrUnsafeInertRestoreCandidate
	}
	if afterInventory != nil {
		afterInventory()
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		path := filepath.Join(lock.Name(), entry.Name())
		if !validInertRestoreCandidateDir(path) || !entry.IsDir() {
			return 0, ErrUnsafeInertRestoreCandidate
		}
		fd, err := syscall.Openat(int(lock.Fd()), entry.Name(),
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return 0, ErrUnsafeInertRestoreCandidate
		}
		child := os.NewFile(uintptr(fd), path)
		if child == nil {
			_ = syscall.Close(fd)
			return 0, ErrUnsafeInertRestoreCandidate
		}
		onFD, statErr := child.Stat()
		closeErr := child.Close()
		if statErr != nil || closeErr != nil || !onFD.IsDir() ||
			onFD.Mode().Perm() != 0o700 {
			return 0, ErrUnsafeInertRestoreCandidate
		}
		owner, ok := onFD.Sys().(*syscall.Stat_t)
		if !ok || int(owner.Uid) != os.Getuid() {
			return 0, ErrUnsafeInertRestoreCandidate
		}
		onPath, pathErr := os.Lstat(path)
		if pathErr != nil || !os.SameFile(onFD, onPath) ||
			verifySealedArchiveParent(path) != nil {
			return 0, ErrUnsafeInertRestoreCandidate
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !sameInertCandidateParentLease(lock.Name(), lock) {
		return 0, ErrUnsafeInertRestoreCandidate
	}
	return len(entries), nil
}

func inspectInertCandidateFile(candidate *InertRestoreCandidate, allowAbsent bool) (os.FileInfo, error) {
	return inspectInertCandidateFileProbed(candidate, allowAbsent, nil)
}

// inspectInertCandidateFileProbed provides a test-only boundary between
// scanning the locked child and opening its single ciphertext leaf.
// Production always uses a nil hook.
func inspectInertCandidateFileProbed(
	candidate *InertRestoreCandidate, allowAbsent bool, beforeArchiveOpen func() bool,
) (os.FileInfo, error) {
	if candidate == nil || candidate.dir == nil ||
		candidate.directoryIdentity == nil ||
		!sameInertCandidateParentIdentity(candidate.parent, candidate.parentIdentity) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	opened, err := verifyCandidateDirLock(candidate.directory, candidate.dir)
	if err != nil || !os.SameFile(candidate.directoryIdentity, opened) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// The inventory reader and the subsequent ciphertext openat are
	// anchored to the same leased inode. Only the reader has its own offset.
	reader, err := openLockedInertCandidateInventoryReader(candidate)
	if err != nil {
		return nil, err
	}
	entries, err := reader.ReadDir(2)
	closeErr := reader.Close()
	if (err != nil && !errors.Is(err, io.EOF)) || closeErr != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// The inventory can be empty during failed-stage cleanup. Even in that
	// case, its path must still identify the leased directory: a same-UID
	// actor can rename the scope after the first lock identity check.
	// The private hook makes the inventory/return boundary testable.
	if beforeArchiveOpen != nil && !beforeArchiveOpen() {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if len(entries) == 0 && allowAbsent {
		locked, lockErr := verifyCandidateDirLock(candidate.directory, candidate.dir)
		if lockErr != nil || !os.SameFile(candidate.directoryIdentity, locked) ||
			!sameInertCandidateParentIdentity(candidate.parent, candidate.parentIdentity) {
			return nil, ErrUnsafeInertRestoreCandidate
		}
		return nil, nil
	}
	if len(entries) != 1 || entries[0].Name() != inertRestoreCipherName ||
		!entries[0].Type().IsRegular() {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// The long-lived flock fd pins the ciphertext source directory inode.
	fd, err := syscall.Openat(int(candidate.dir.Fd()), inertRestoreCipherName,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	source := os.NewFile(uintptr(fd), candidate.archive)
	if source == nil {
		_ = syscall.Close(fd)
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
	locked, err := verifyCandidateDirLock(candidate.directory, candidate.dir)
	if err != nil || !os.SameFile(candidate.directoryIdentity, locked) ||
		!sameInertCandidateParentIdentity(candidate.parent, candidate.parentIdentity) {
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
	return stageInertRestoreCandidate(ctx, sourceArchive, candidateParent, key, nil)
}

// stageInertRestoreCandidate has a test-only, fixed-label phase probe. Production
// always passes nil: no user-facing diagnostics, error detail, retries, or
// additional files are introduced. Returning false in a test forces exactly
// the same fail-closed cleanup path as an admission refusal.
func stageInertRestoreCandidate(
	ctx context.Context, sourceArchive, candidateParent string, key [32]byte,
	probe func(string) bool,
) (result *InertRestoreCandidate, err error) {
	checkpoint := func(phase string) bool {
		return probe == nil || probe(phase)
	}
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
	if !checkpoint("source_preflight") {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	report, err := PreflightInertArchive(ctx, sourceArchive, key, nil)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.RestoreReady || report.RestoreSupported ||
		!validLowerSHA(report.ArchiveSHA256) || report.ArchiveBytes <= 0 {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("disk_reserve") ||
		requireSealedArchiveSpace(candidateParent, report.ArchiveBytes) != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Parent flock serializes slot reservations with other stage operations,
	// and closes the new-dir -> child-lock gap against other adopters.
	if !checkpoint("parent_lock") {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	parentLock, err := lockSealedArchiveParent(ctx, candidateParent)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	var candidate *InertRestoreCandidate
	// An independent, non-flocked fd keeps the admitted parent inode
	// available for durability sync after its short exclusive flock ends.
	// It never prolongs the parent reservation lock across ciphertext IO.
	var parentSync *os.File
	defer func() {
		if parentSync != nil {
			_ = parentSync.Close()
		}
	}()
	func() {
		defer parentLock.Close()
		if !checkpoint("parent_inventory") {
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		var count int
		count, err = inspectCandidateParent(ctx, parentLock)
		if err != nil || count >= MaxInertRestoreCandidates {
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		if !checkpoint("create_scope") {
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		if !checkpoint("scope_before_mkdirat") {
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		// Create only inside the leased parent inode, not the mutable
		// candidateParent path. The new child's identity must likewise be
		// collected through that fd, before any pathname-based adoption.
		var directory string
		var created os.FileInfo
		directory, created, err = createInertScopeAtLeasedParent(parentLock, candidateParent)
		if err != nil {
			recordInertCandidateSyscallFailure(probe, "scope_mkdir", err)
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		if !sameInertCandidateParentLease(candidateParent, parentLock) ||
			!sameNewInertScopeIdentity(directory, created) {
			// A path swap is ambiguous; do not attempt pathname deletion
			// of an unrelated directory, even if an empty scope remains
			// in the original parent inode after it was moved.
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		if !checkpoint("scope_created") {
			_ = removeNewEmptyInertScopeIfIdentical(parentLock, directory, created)
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		candidate, err = openLockedInertRestoreCandidateAtParentProbed(
			directory, parentLock, probe)
		if err != nil {
			// An untrusted actor could have replaced the empty scope while
			// this process held the parent advisory flock. Never unlink
			// the replacement merely because it occupies our old name.
			_ = removeNewEmptyInertScopeIfIdentical(parentLock, directory, created)
			return
		}
		if candidate == nil || candidate.directoryIdentity == nil ||
			!os.SameFile(created, candidate.directoryIdentity) ||
			!sameNewInertScopeIdentity(directory, created) {
			if candidate != nil {
				// The opened fd may belong to a replaced scope. Release its
				// lock only; never discard or unlink that foreign inode.
				_ = candidate.Close()
			}
			candidate = nil
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		if !checkpoint("scope_locked") ||
			!sameInertCandidateParentLease(candidateParent, parentLock) ||
			parentLock.Sync() != nil {
			// Fsync the leased parent inode, not a replacement path.
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		// The independent stream fd is opened relative to the same leased
		// inode and validated before the short parent flock is released.
		parentSync, err = openLockedInertCandidateParentInventoryReader(parentLock)
		if err != nil || !sameInertCandidateParentLease(candidateParent, parentSync) {
			err = ErrUnsafeInertRestoreCandidate
			return
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
	if !checkpoint("cipher_copy") {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if err = copyInertCandidateCipher(ctx, sourceArchive, candidate, report, probe); err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("scope_sync") {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Fsync the same directory inode used for the ciphertext openat, not
	// a pathname that may have been replaced by an uncooperative actor.
	if err = candidate.dir.Sync(); err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("parent_sync") {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Do not reopen candidateParent by name: its inode may have been
	// exchanged after the short parent flock was released.
	if err = syncPinnedInertCandidateParent(candidateParent, parentSync); err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("candidate_revalidation") {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	var checked InertArchivePreflight
	checked, err = PreflightInertArchive(ctx, candidate.archive, key, nil)
	if err != nil || !sameInertPreflightEvidence(report, checked) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// The final authenticated path still has to refer to the original
	// locked inode, not merely contain matching ciphertext.
	locked, lockErr := verifyCandidateDirLock(candidate.directory, candidate.dir)
	if lockErr != nil || !os.SameFile(candidate.directoryIdentity, locked) ||
		!sameInertCandidateParentLease(candidateParent, parentSync) {
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

// copyInertCandidateCipher creates the ciphertext relative to the LOCKED
// directory fd, not a pathname whose intermediate components a same-UID actor
// could replace after admission. A path-based post-write check is still
// required: the fd anchor prevents foreign writes, but cannot authorize a
// renamed or unlinked candidate directory.
func copyInertCandidateCipher(
	ctx context.Context, sourcePath string, candidate *InertRestoreCandidate,
	expected InertArchivePreflight, probe func(string) bool,
) error {
	if candidate == nil || candidate.dir == nil ||
		candidate.directoryIdentity == nil {
		return ErrUnsafeInertRestoreCandidate
	}
	locked, lockErr := verifyCandidateDirLock(candidate.directory, candidate.dir)
	if lockErr != nil || !os.SameFile(candidate.directoryIdentity, locked) {
		return ErrUnsafeInertRestoreCandidate
	}
	file, err := openSealedArchiveNoFollow(sourcePath)
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || verifySealedFile(file, sourcePath, info, expected.ArchiveBytes, true) != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	// A test probe may replace candidate.directory right here. Openat must
	// still create only inside the inode whose exclusive lease we hold.
	if probe != nil && !probe("cipher_before_openat") {
		return ErrUnsafeInertRestoreCandidate
	}
	fd, err := syscall.Openat(int(candidate.dir.Fd()), inertRestoreCipherName,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|
			syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		recordInertCandidateSyscallFailure(probe, "cipher_openat", err)
		return ErrUnsafeInertRestoreCandidate
	}
	targetPath := candidate.archive
	target := os.NewFile(uintptr(fd), targetPath)
	if target == nil {
		_ = syscall.Close(fd)
		return ErrUnsafeInertRestoreCandidate
	}
	defer target.Close()
	if probe != nil && !probe("cipher_target_fd_opened") {
		return ErrUnsafeInertRestoreCandidate
	}
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
	locked, lockErr = verifyCandidateDirLock(candidate.directory, candidate.dir)
	if lockErr != nil || !os.SameFile(candidate.directoryIdentity, locked) {
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
	return reopenInertRestoreCandidateProbed(ctx, directory, key, nil)
}

// The private afterPreflight hook permits deterministic Linux path-swap
// regressions. No caller outside this package can supply it to production.
func reopenInertRestoreCandidateProbed(
	ctx context.Context, directory string, key [32]byte, afterPreflight func(),
) (_ *InertRestoreCandidate, err error) {
	return reopenInertRestoreCandidateAtParentProbed(ctx, directory, key, nil, afterPreflight)
}

// The additional private beforeChildOpen checkpoint tests a parent pathname
// substitution after the parent inventory but before the child lease open.
// Production passes nil; no public API admits an external callback.
func reopenInertRestoreCandidateAtParentProbed(
	ctx context.Context, directory string, key [32]byte,
	beforeChildOpen, afterPreflight func(),
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
			if beforeChildOpen != nil {
				beforeChildOpen()
			}
			candidate, err = openLockedInertRestoreCandidateAtParentProbed(
				directory, parent, nil)
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
	before, err := inspectInertCandidateFile(candidate, false)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	var report InertArchivePreflight
	report, err = PreflightInertArchive(ctx, candidate.archive, key, nil)
	if err != nil || !report.SchemaCatalogVerified ||
		!report.SQLiteLogicalVerified || report.RestoreReady ||
		report.RestoreSupported {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if afterPreflight != nil {
		afterPreflight()
	}
	after, inspectErr := inspectInertCandidateFile(candidate, false)
	if inspectErr != nil || !os.SameFile(before, after) ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
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

// openInertCandidateParentForDiscard pins the ORIGINAL parent inode
// independently of the candidate child lease before any irreversible unlink.
// It must never resolve to a same-UID replacement parent at the old path.
func openInertCandidateParentForDiscard(path string, original os.FileInfo) (*os.File, error) {
	if !sameInertCandidateParentIdentity(path, original) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|
		syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	parent := os.NewFile(uintptr(fd), path)
	if parent == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafeInertRestoreCandidate
	}
	info, err := parent.Stat()
	if err != nil || !os.SameFile(original, info) ||
		!sameInertCandidateParentLease(path, parent) {
		_ = parent.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	return parent, nil
}

func (c *InertRestoreCandidate) discardLocked(requireFile bool) error {
	return c.discardLockedProbed(requireFile, nil)
}

// The internal pre-directory-unlink hook tests an uncooperative same-UID
// namespace replacement after the ciphertext leaf is removed. Production
// always passes nil; external code cannot obtain this callback.
func (c *InertRestoreCandidate) discardLockedProbed(
	requireFile bool, beforeDirectoryUnlink func(),
) error {
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
	// Pin the admitted parent before deleting even the ciphertext. Opening
	// by pathname is read-only; its inode must match the parent captured
	// at child-lease admission before any irreversible operation.
	parent, err := openInertCandidateParentForDiscard(c.parent, c.parentIdentity)
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	defer parent.Close()
	if file != nil {
		// Never remove unknown sibling files or follow a ciphertext symlink.
		if err := syscall.Unlinkat(int(c.dir.Fd()), inertRestoreCipherName); err != nil {
			return ErrUnsafeInertRestoreCandidate
		}
	}
	// Durability is tied to the original child directory inode.
	if c.dir.Sync() != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	if beforeDirectoryUnlink != nil {
		beforeDirectoryUnlink()
	}
	if !sameInertCandidateParentLease(c.parent, parent) ||
		!sameInertCandidateParentIdentity(c.parent, c.parentIdentity) {
		return ErrUnsafeInertRestoreCandidate
	}
	// Re-check the LOCKED child inode after the irreversible ciphertext
	// unlink. The directory entry can only be unlinked relative to the
	// independently pinned, original parent inode.
	atDir, err := verifyCandidateDirLock(c.directory, c.dir)
	if err != nil || !os.SameFile(c.directoryIdentity, atDir) {
		return ErrUnsafeInertRestoreCandidate
	}
	if err := unix.Unlinkat(int(parent.Fd()), filepath.Base(c.directory),
		unix.AT_REMOVEDIR); err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	// Fsync the parent inode in which unlinkat actually removed the leaf;
	// never fsync an unrelated replacement at the same absolute pathname.
	if parent.Sync() != nil || !sameInertCandidateParentLease(c.parent, parent) {
		return ErrUnsafeInertRestoreCandidate
	}
	return nil
}
