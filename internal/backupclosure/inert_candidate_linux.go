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
	case errors.Is(err, syscall.ENOTDIR):
		return "not_directory"
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
	return openLockedInertRestoreCandidateAtParentContextProbed(
		context.Background(), path, parent, probe)
}

// Reopen supplies its bounded context to the independent O_DIRECTORY open
// and exclusive flock. On cancellation every newly acquired child fd is
// closed, while the borrowed parent lease stays owned by the caller.
// The legacy helper above deliberately keeps its existing signature.
func openLockedInertRestoreCandidateAtParentContextProbed(
	ctx context.Context, path string, parent *os.File, probe func(string) bool,
) (*InertRestoreCandidate, error) {
	checkpoint := func(stage string) bool {
		return probe == nil || probe(stage)
	}
	cancelled := func() bool {
		if ctx != nil && ctx.Err() == nil {
			return false
		}
		if probe != nil {
			_ = probe("scope_reopen_context_cancelled")
		}
		return true
	}
	if cancelled() {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !validInertRestoreCandidateDir(path) || verifySealedArchiveParent(path) != nil ||
		(parent != nil && !sameInertCandidateParentLease(filepath.Dir(path), parent)) {
		if probe != nil {
			_ = probe("scope_child_precheck_refused")
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("scope_child_open") || cancelled() {
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
	if !checkpoint("scope_child_fd_opened") || cancelled() ||
		!checkpoint("scope_child_flock") || cancelled() {
		_ = lock.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Cancellation is checked adjacent to flock; it cannot be atomic
	// with the syscall, but any refusal closes this newly opened fd.
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		recordInertCandidateSyscallFailure(probe, "scope_child_flock", err)
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrInertRestoreCandidateBusy
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("scope_child_lock_held") || cancelled() ||
		!checkpoint("scope_child_identity") || cancelled() {
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
	if !checkpoint("scope_child_identity_verified") || cancelled() {
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
		if probe != nil {
			_ = probe("scope_child_parent_identity_refused")
		}
		_ = lock.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if cancelled() {
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

// lockCreatedInertRestoreCandidateAtParentProbed transfers the SAME
// O_DIRECTORY|O_NOFOLLOW file descriptor opened during mkdirat receipt
// verification into Stage's exclusive child flock. The caller retains
// ownership on failure and MUST close it; ownership transfers only after
// every lock, child identity and original parent identity check succeeds.
// Reopen and standalone test helpers continue to open a new fd as before.
func lockCreatedInertRestoreCandidateAtParentProbed(
	path string, parent, createdFD *os.File, created os.FileInfo,
	probe func(string) bool,
) (*InertRestoreCandidate, error) {
	return lockCreatedInertRestoreCandidateAtParentContextProbed(
		context.Background(), path, parent, createdFD, created, probe)
}

// Stage supplies its bounded context to prevent a cancelled operation
// from obtaining a new child flock or issuing more pathname checks.
// The older private wrapper remains available for direct lease tests.
// The original created FD ALWAYS remains caller-owned on refusal.
func lockCreatedInertRestoreCandidateAtParentContextProbed(
	ctx context.Context, path string, parent, createdFD *os.File,
	created os.FileInfo, probe func(string) bool,
) (*InertRestoreCandidate, error) {
	checkpoint := func(stage string) bool { return probe == nil || probe(stage) }
	cancelled := func() bool {
		if ctx != nil && ctx.Err() == nil {
			return false
		}
		if probe != nil {
			_ = probe("scope_child_context_cancelled")
		}
		return true
	}
	if cancelled() {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if createdFD == nil || created == nil || parent == nil ||
		createdFD.Name() != path ||
		!validInertRestoreCandidateDir(path) ||
		verifySealedArchiveParent(path) != nil ||
		!sameInertCandidateParentLease(filepath.Dir(path), parent) {
		if probe != nil {
			_ = probe("scope_child_precheck_refused")
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	onFD, err := createdFD.Stat()
	if err != nil || !onFD.IsDir() || !os.SameFile(onFD, created) ||
		onFD.Mode().Perm() != 0o700 ||
		!singleOwnedSealedFileDirectory(onFD) {
		if probe != nil {
			_ = probe("scope_child_created_inode_refused")
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// These existing boundaries remain test-injectable. No second
	// openat is allowed between receipt validation and flock.
	if !checkpoint("scope_child_open") || cancelled() ||
		!checkpoint("scope_child_fd_reused") || cancelled() ||
		!checkpoint("scope_child_fd_opened") || cancelled() ||
		!checkpoint("scope_child_flock") || cancelled() {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// The final cancellation check above is adjacent to flock(2).
	// Context cancellation and flock cannot be atomic: Stage still owns
	// the fd, so any later refusal releases this lock by closing it.
	if err := syscall.Flock(int(createdFD.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		recordInertCandidateSyscallFailure(probe, "scope_child_flock", err)
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrInertRestoreCandidateBusy
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("scope_child_lock_held") || cancelled() ||
		!checkpoint("scope_child_identity") || cancelled() {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	identity, err := verifyCandidateDirLock(path, createdFD)
	if err != nil || !os.SameFile(created, identity) ||
		!sameInertCandidateParentLease(filepath.Dir(path), parent) {
		if probe != nil {
			_ = probe("scope_child_identity_refused")
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("scope_child_identity_verified") || cancelled() {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	parentPath := filepath.Dir(path)
	parentIdentity, err := parent.Stat()
	if err != nil || !sameInertCandidateParentIdentity(parentPath, parentIdentity) {
		if probe != nil {
			_ = probe("scope_child_parent_identity_refused")
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if cancelled() {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	return &InertRestoreCandidate{
		directory:         path,
		parent:            parentPath,
		archive:           filepath.Join(path, inertRestoreCipherName),
		dir:               createdFD,
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
	return createInertScopeAtLeasedParentProbed(parent, parentPath, nil)
}

// createInertScopeAtLeasedParentProbed records only fixed private test
// checkpoints/errno CLASSES. It is never exposed to users or logs. The
// post-mkdirat fstatat receipt precedes child openat, so a persistent child
// inode replacement between these calls cannot become Stage's own scope.
// This cannot make mkdirat+fstatat+openat atomic against hostile same-UID
// directory entry replacement; the later path/lease checks still apply.
func createInertScopeAtLeasedParentProbed(
	parent *os.File, parentPath string, probe func(string) bool,
) (string, os.FileInfo, error) {
	return createInertScopeAtLeasedParentRetainedProbed(parent, parentPath, probe, nil)
}

// The optional retained descriptor was opened from the original parent fd
// and validated against the earlier fstatat creation receipt. On success
// Stage takes ownership of it through the child flock and encrypted copy.
// All failure exits close it; direct callers still receive only FileInfo.
func createInertScopeAtLeasedParentRetainedProbed(
	parent *os.File, parentPath string, probe func(string) bool, retained **os.File,
) (string, os.FileInfo, error) {
	if retained != nil {
		*retained = nil
	}
	checkpoint := func(stage string) bool { return probe == nil || probe(stage) }
	refusal := func(stage string) {
		if probe != nil {
			_ = probe(stage)
		}
	}
	if parent == nil || !filepath.IsAbs(parentPath) ||
		filepath.Clean(parentPath) != parentPath {
		refusal("scope_create_parent_path_refused")
		return "", nil, ErrUnsafeInertRestoreCandidate
	}
	opened, err := parent.Stat()
	if err != nil {
		recordInertCandidateSyscallFailure(probe, "scope_create_parent_fstat", err)
		return "", nil, ErrUnsafeInertRestoreCandidate
	}
	if !opened.IsDir() || opened.Mode().Perm() != 0o700 {
		refusal("scope_create_parent_mode_refused")
		return "", nil, ErrUnsafeInertRestoreCandidate
	}
	owner, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Getuid() {
		refusal("scope_create_parent_owner_refused")
		return "", nil, ErrUnsafeInertRestoreCandidate
	}
	// Each attempted name has 96 bits of cryptographic randomness. Only a
	// genuine EEXIST can advance the bounded collision loop; all other
	// creation failures remain fail-closed without a production retry.
	for attempt := 0; attempt < 8; attempt++ {
		var randomName [12]byte
		if _, err := rand.Read(randomName[:]); err != nil {
			recordInertCandidateSyscallFailure(probe, "scope_random", err)
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		name := inertRestoreCandidatePrefix + hex.EncodeToString(randomName[:])
		if err := syscall.Mkdirat(int(parent.Fd()), name, 0o700); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			recordInertCandidateSyscallFailure(probe, "scope_mkdirat", err)
			return "", nil, err
		}
		// A test-only callback can replace the name here, before the first
		// metadata receipt. Production has no callback.
		if !checkpoint("scope_mkdirat_created") {
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		var createdName unix.Stat_t
		if err := unix.Fstatat(int(parent.Fd()), name, &createdName, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			recordInertCandidateSyscallFailure(probe, "scope_created_fstatat", err)
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		if createdName.Mode&unix.S_IFMT != unix.S_IFDIR ||
			createdName.Mode&0o777 != 0o700 ||
			int(createdName.Uid) != os.Getuid() {
			refusal("scope_created_receipt_refused")
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		// Capturing dev+ino BEFORE openat provides a concrete identity
		// receipt; a later replacement directory may be equally private
		// but may not be adopted as the newly created scope.
		if !checkpoint("scope_created_inode_receipt") {
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		fd, err := syscall.Openat(int(parent.Fd()), name,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			recordInertCandidateSyscallFailure(probe, "scope_created_openat", err)
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		directory := filepath.Join(parentPath, name)
		child := os.NewFile(uintptr(fd), directory)
		if child == nil {
			_ = syscall.Close(fd)
			refusal("scope_created_newfile_refused")
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		keepChild := false
		defer func() {
			if !keepChild {
				_ = child.Close()
			}
		}()
		created, statErr := child.Stat()
		if statErr != nil {
			recordInertCandidateSyscallFailure(probe, "scope_created_fstat", statErr)
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		if !created.IsDir() || created.Mode().Perm() != 0o700 ||
			!singleOwnedSealedFileDirectory(created) {
			refusal("scope_created_child_mode_refused")
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		childStat, ok := created.Sys().(*syscall.Stat_t)
		if !ok || uint64(childStat.Dev) != uint64(createdName.Dev) ||
			childStat.Ino != createdName.Ino ||
			childStat.Uid != createdName.Uid {
			refusal("scope_created_inode_changed")
			return "", nil, ErrUnsafeInertRestoreCandidate
		}
		if retained != nil {
			*retained = child
			keepChild = true
		} else {
			closeErr := child.Close()
			keepChild = true
			if closeErr != nil {
				recordInertCandidateSyscallFailure(probe, "scope_created_close", closeErr)
				return "", nil, ErrUnsafeInertRestoreCandidate
			}
		}
		return directory, created, nil
	}
	refusal("scope_mkdirat_collisions_exhausted")
	return "", nil, ErrUnsafeInertRestoreCandidate
}

// The temporary receipt checks the child inode's owner without imposing
// the single-link rule for directories (their link count includes "..").
func singleOwnedSealedFileDirectory(info os.FileInfo) bool {
	if info == nil || !info.IsDir() {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
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

// pinInspectedInertCandidateCipher upgrades a metadata-only candidate
// inspection to a caller-owned read-only file descriptor for the SAME
// ciphertext inode. A same-UID process must not switch the first HMAC read
// to another byte-identical file after the locked directory was inspected.
// The caller closes this fd; no directory flock or source offset is consumed.
func pinInspectedInertCandidateCipher(
	candidate *InertRestoreCandidate, original os.FileInfo,
) (*os.File, error) {
	if candidate == nil || candidate.dir == nil ||
		candidate.directoryIdentity == nil || original == nil ||
		!sameInertCandidateParentIdentity(candidate.parent, candidate.parentIdentity) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	directory, err := verifyCandidateDirLock(candidate.directory, candidate.dir)
	if err != nil || !os.SameFile(candidate.directoryIdentity, directory) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	file, err := openSealedArchiveAtPinnedParent(candidate.archive, candidate.dir)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	atFD, err := file.Stat()
	if err != nil || !os.SameFile(original, atFD) ||
		original.Size() != atFD.Size() || original.Mode() != atFD.Mode() ||
		!original.ModTime().Equal(atFD.ModTime()) ||
		verifySealedFile(file, candidate.archive, original, original.Size(), true) != nil ||
		!sameInertCandidateParentIdentity(candidate.parent, candidate.parentIdentity) {
		_ = file.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	directory, err = verifyCandidateDirLock(candidate.directory, candidate.dir)
	if err != nil || !os.SameFile(candidate.directoryIdentity, directory) {
		_ = file.Close()
		return nil, ErrUnsafeInertRestoreCandidate
	}
	return file, nil
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
	if !checkpoint("source_preflight") || ctx.Err() != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Pin the source's ORIGINAL private parent and exact archive inode
	// before authentication. Retain both read-only descriptors through
	// inventory, candidate reservation, ciphertext copy and final checks:
	// a same-UID actor must not redirect a later copy to a replacement
	// parent or an identically authenticated but different file inode.
	sourceParent, err := pinSealedArchiveReadParent(sourceArchive)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	defer sourceParent.Close()
	sourceFile, err := openSealedArchiveAtPinnedParent(sourceArchive, sourceParent)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	defer sourceFile.Close()
	sourceIdentity, err := sourceFile.Stat()
	if err != nil || !samePinnedInertStageSource(sourceArchive, sourceParent, sourceFile,
		sourceIdentity, sourceIdentity.Size()) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Test-only checkpoint after the ORIGINAL source parent and child are
	// pinned, before any complete Preflight read may begin.
	if !checkpoint("source_inode_pinned") || ctx.Err() != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	report, err := preflightInertArchiveAtParentExpectedFile(
		ctx, sourceArchive, key, nil, sourceParent, sourceFile)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.RestoreReady || report.RestoreSupported ||
		!validLowerSHA(report.ArchiveSHA256) || report.ArchiveBytes <= 0 ||
		!samePinnedInertStageSource(sourceArchive, sourceParent, sourceFile,
			sourceIdentity, report.ArchiveBytes) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("disk_reserve") || ctx.Err() != nil ||
		requireSealedArchiveSpace(candidateParent, report.ArchiveBytes) != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Parent flock serializes slot reservations with other stage operations,
	// and closes the new-dir -> child-lock gap against other adopters.
	if !checkpoint("parent_lock") || ctx.Err() != nil {
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
		if !checkpoint("parent_inventory") || ctx.Err() != nil {
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		var count int
		count, err = inspectCandidateParent(ctx, parentLock)
		if err != nil || count >= MaxInertRestoreCandidates {
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		// A timed-out or cancelled Stage is not permitted to allocate a
		// new persistent private scope after the parent reservation.
		if !checkpoint("create_scope") || ctx.Err() != nil {
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		if !checkpoint("scope_before_mkdirat") || ctx.Err() != nil {
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		// Create only inside the leased parent inode, not the mutable
		// candidateParent path. The new child's identity must likewise be
		// collected through that fd, before any pathname-based adoption.
		var directory string
		var created os.FileInfo
		var pinnedChild *os.File
		defer func() {
			if pinnedChild != nil {
				_ = pinnedChild.Close()
			}
		}()
		directory, created, err = createInertScopeAtLeasedParentRetainedProbed(
			parentLock, candidateParent, probe, &pinnedChild)
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
		// A cancellation during mkdirat/fstatat/openat cannot publish a
		// candidate; release the exact created child fd, then attempt only
		// owner-verified empty scope cleanup using the original parent fd.
		if !checkpoint("scope_created") || ctx.Err() != nil {
			_ = pinnedChild.Close()
			pinnedChild = nil
			_ = removeNewEmptyInertScopeIfIdentical(parentLock, directory, created)
			err = ErrUnsafeInertRestoreCandidate
			return
		}
		// Reuse the fd from mkdirat + fstatat + openat receipt verification:
		// do not close it and re-open the mutable child pathname for flock.
		candidate, err = lockCreatedInertRestoreCandidateAtParentContextProbed(
			ctx, directory, parentLock, pinnedChild, created, probe)
		if err != nil {
			_ = pinnedChild.Close()
			pinnedChild = nil
			// A foreign scope may occupy the same path: cleanup is guarded
			// by exact original inode and the original parent lease.
			_ = removeNewEmptyInertScopeIfIdentical(parentLock, directory, created)
			return
		}
		pinnedChild = nil // Exclusive child flock ownership moved to candidate.
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
		// If cancellation occurred during the child flock checkpoints,
		// fail before parent fsync/lease publication. The outer Stage
		// cleanup discards only the exact known empty candidate scope.
		if !checkpoint("scope_locked") || ctx.Err() != nil ||
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
			_ = candidate.discardStageLocked(nil)
		}
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// The exact ciphertext fd originally CREATED with O_EXCL remains open
	// through final HMAC/inventory/SQLite and also through failed-Stage
	// cleanup. Its inode alone authorizes deletion of this Stage's bytes.
	var ownedTarget *os.File
	defer func() {
		if ownedTarget != nil {
			_ = ownedTarget.Close()
		}
	}()
	defer func() {
		if err != nil {
			err = errors.Join(err, candidate.discardStageLocked(ownedTarget))
		}
	}()
	if !checkpoint("cipher_copy") || ctx.Err() != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if err = copyInertCandidateCipherAtPinnedSourceRetained(ctx, sourceArchive,
		sourceParent, sourceFile, sourceIdentity, candidate, report, probe,
		&ownedTarget); err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("scope_sync") || ctx.Err() != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Fsync the same directory inode used for the ciphertext openat, not
	// a pathname that may have been replaced by an uncooperative actor.
	if err = candidate.dir.Sync(); err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("parent_sync") || ctx.Err() != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Do not reopen candidateParent by name: its inode may have been
	// exchanged after the short parent flock was released.
	if err = syncPinnedInertCandidateParent(candidateParent, parentSync); err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if !checkpoint("candidate_revalidation") || ctx.Err() != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	var checked InertArchivePreflight
	checked, err = preflightInertArchiveAtParentExpectedFile(
		ctx, candidate.archive, key, nil, candidate.dir, ownedTarget)
	if err != nil || !sameInertPreflightEvidence(report, checked) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Read-only authentication may have completed after cancellation.
	// Do not publish a validated candidate on a stale request; failed
	// Stage still cleans up only the original O_EXCL-created target inode.
	if !checkpoint("candidate_authenticated") || ctx.Err() != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// The final authenticated path still has to refer to the original
	// locked inode, not merely contain matching ciphertext.
	locked, lockErr := verifyCandidateDirLock(candidate.directory, candidate.dir)
	if lockErr != nil || !os.SameFile(candidate.directoryIdentity, locked) ||
		!sameInertCandidateParentLease(candidateParent, parentSync) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// Final successful receipt publication is not an atomic cancellation
	// boundary. Check immediately before ownership can leave Stage.
	if !checkpoint("candidate_receipt") || ctx.Err() != nil {
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

// samePinnedInertStageSource proves that both the private parent inode and
// the exact sealed archive file inode first opened by Stage remain the
// source. Copying authenticated bytes from an unrelated replacement path
// would be a failed custody check even when its SHA/HMAC match exactly.
func samePinnedInertStageSource(
	path string, parent, file *os.File, original os.FileInfo, size int64,
) bool {
	if parent == nil || file == nil || original == nil ||
		parent.Name() != filepath.Dir(path) || file.Name() != path ||
		!validSealedArchivePath(path) ||
		!sameLeasedSealedArchiveParent(parent.Name(), parent) {
		return false
	}
	atFD, err := file.Stat()
	if err != nil || !os.SameFile(original, atFD) ||
		original.Size() != size || atFD.Size() != size ||
		original.Mode() != atFD.Mode() ||
		!original.ModTime().Equal(atFD.ModTime()) ||
		verifySealedFile(file, path, original, size, true) != nil {
		return false
	}
	return sameLeasedSealedArchiveParent(parent.Name(), parent)
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
	// Preserve this existing package-private test entry point. Actual
	// Stage calls the pinned variant with descriptors opened BEFORE its
	// first full authenticated source preflight, not new path opens.
	parent, err := pinSealedArchiveReadParent(sourcePath)
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	defer parent.Close()
	file, err := openSealedArchiveAtPinnedParent(sourcePath, parent)
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	return copyInertCandidateCipherAtPinnedSource(
		ctx, sourcePath, parent, file, info, candidate, expected, probe)
}

// copyInertCandidateCipherAtPinnedSource writes only into the existing
// leased candidate child fd, and reads only from the original source
// descriptor obtained relative to its original private parent inode.
func copyInertCandidateCipherAtPinnedSource(
	ctx context.Context, sourcePath string, parent, file *os.File,
	info os.FileInfo, candidate *InertRestoreCandidate,
	expected InertArchivePreflight, probe func(string) bool,
) error {
	return copyInertCandidateCipherAtPinnedSourceRetained(
		ctx, sourcePath, parent, file, info, candidate, expected, probe, nil)
}

// Stage can retain ownership of the EXACT ciphertext inode it creates.
// The new target fd transfers to Stage immediately after O_EXCL succeeds,
// even if the subsequent copy fails, so cleanup can verify custody of
// partial bytes. Direct package-private callers keep closing it locally.
func copyInertCandidateCipherAtPinnedSourceRetained(
	ctx context.Context, sourcePath string, parent, file *os.File,
	info os.FileInfo, candidate *InertRestoreCandidate,
	expected InertArchivePreflight, probe func(string) bool,
	retained **os.File,
) error {
	if retained != nil {
		*retained = nil
	}
	if candidate == nil || candidate.dir == nil ||
		candidate.directoryIdentity == nil ||
		!samePinnedInertStageSource(sourcePath, parent, file, info,
			expected.ArchiveBytes) {
		return ErrUnsafeInertRestoreCandidate
	}
	locked, lockErr := verifyCandidateDirLock(candidate.directory, candidate.dir)
	if lockErr != nil || !os.SameFile(candidate.directoryIdentity, locked) {
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
	if retained != nil {
		*retained = target
	} else {
		defer target.Close()
	}
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
	if !samePinnedInertStageSource(sourcePath, parent, file, info,
		expected.ArchiveBytes) {
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
) (*InertRestoreCandidate, error) {
	return reopenInertRestoreCandidateAtFileProbed(
		ctx, directory, key, beforeChildOpen, nil, afterPreflight)
}

// This strictly internal hook runs after the exact candidate file fd is
// pinned and before the first HMAC opens its own read descriptor. Production
// always passes nil, including the public Reopen API.
func reopenInertRestoreCandidateAtFileProbed(
	ctx context.Context, directory string, key [32]byte,
	beforeChildOpen, beforePreflight, afterPreflight func(),
) (_ *InertRestoreCandidate, err error) {
	return reopenInertRestoreCandidateAtFinalIdentityProbed(
		ctx, directory, key, beforeChildOpen, beforePreflight, afterPreflight, nil)
}

// Reopen must not publish a newly acquired candidate lease after cancellation
// at the last successful identity check. This nil-in-production checkpoint is
// strictly package-private and does not change any public API or lease policy.
// Unlike Verify, Reopen OWNS the new flock and closes it on refusal.
func reopenInertRestoreCandidateAtFinalIdentityProbed(
	ctx context.Context, directory string, key [32]byte,
	beforeChildOpen, beforePreflight, afterPreflight, afterIdentity func(),
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
			candidate, err = openLockedInertRestoreCandidateAtParentContextProbed(
				ctx, directory, parent, nil)
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
	if ctx.Err() != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	before, err := inspectInertCandidateFile(candidate, false)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	// The previously inspected exact ciphertext inode stays open through
	// all three authenticated passes; a same-name byte-identical replacement
	// cannot be selected for the FIRST HMAC read.
	expectedFile, err := pinInspectedInertCandidateCipher(candidate, before)
	if err != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	defer expectedFile.Close()
	if beforePreflight != nil {
		beforePreflight()
	}
	if ctx.Err() != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	var report InertArchivePreflight
	report, err = preflightInertArchiveAtParentExpectedFile(
		ctx, candidate.archive, key, nil, candidate.dir, expectedFile)
	if err != nil || !report.SchemaCatalogVerified ||
		!report.SQLiteLogicalVerified || report.RestoreReady ||
		report.RestoreSupported {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if afterPreflight != nil {
		afterPreflight()
	}
	if ctx.Err() != nil {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	after, inspectErr := inspectInertCandidateFile(candidate, false)
	if inspectErr != nil || !os.SameFile(before, after) ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, ErrUnsafeInertRestoreCandidate
	}
	if afterIdentity != nil {
		afterIdentity()
	}
	// A full HMAC/SQLite preflight and final inode inspection cannot justify
	// returning a successful lease for a request already cancelled. The
	// deferred failure path closes Reopen's newly acquired directory flock.
	// The last check and return are not atomic with cancellation.
	if ctx.Err() != nil {
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
	return c.verifyInertRestoreCandidateProbed(ctx, key, nil)
}

// The legacy package-private checkpoint remains for same-directory inode
// replacement tests. Verify borrows the candidate's existing exclusive flock;
// it must never release that caller-owned lease on cancellation or failure.
func (c *InertRestoreCandidate) verifyInertRestoreCandidateProbed(
	ctx context.Context, key [32]byte, beforePreflight func(),
) (InertArchivePreflight, error) {
	return c.verifyInertRestoreCandidateCancellationProbed(
		ctx, key, nil, beforePreflight, nil, nil)
}

// Test-only checkpoints cover cancellation before inventory, before the
// authenticated preflight, after it, and after the final identity inspection.
// Production passes nil hooks. No extra public API, cleanup authority or
// cancellation-dependent deletion is introduced.
func (c *InertRestoreCandidate) verifyInertRestoreCandidateCancellationProbed(
	ctx context.Context, key [32]byte,
	beforeInventory, beforePreflight, afterPreflight, afterIdentity func(),
) (InertArchivePreflight, error) {
	var none InertArchivePreflight
	if c == nil || ctx == nil || key == ([32]byte{}) {
		return none, ErrUnsafeInertRestoreCandidate
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dir == nil || ctx.Err() != nil {
		return none, ErrUnsafeInertRestoreCandidate
	}
	if beforeInventory != nil {
		beforeInventory()
	}
	if ctx.Err() != nil {
		return none, ErrUnsafeInertRestoreCandidate
	}
	before, err := inspectInertCandidateFile(c, false)
	if err != nil {
		return none, ErrUnsafeInertRestoreCandidate
	}
	expectedFile, err := pinInspectedInertCandidateCipher(c, before)
	if err != nil {
		return none, ErrUnsafeInertRestoreCandidate
	}
	defer expectedFile.Close()
	if beforePreflight != nil {
		beforePreflight()
	}
	if ctx.Err() != nil {
		return none, ErrUnsafeInertRestoreCandidate
	}
	report, err := preflightInertArchiveAtParentExpectedFile(
		ctx, c.archive, key, nil, c.dir, expectedFile)
	if err != nil || !sameInertPreflightEvidence(c.receipt, report) {
		return none, ErrUnsafeInertRestoreCandidate
	}
	if afterPreflight != nil {
		afterPreflight()
	}
	if ctx.Err() != nil {
		return none, ErrUnsafeInertRestoreCandidate
	}
	after, err := inspectInertCandidateFile(c, false)
	if err != nil || !os.SameFile(before, after) ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return none, ErrUnsafeInertRestoreCandidate
	}
	if afterIdentity != nil {
		afterIdentity()
	}
	// A cancelled verification must never publish a preflight receipt,
	// even when cancellation arrives after all HMAC/SQLite checks passed.
	// Checking the context and returning the report cannot be atomic.
	if ctx.Err() != nil {
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
	return c.discardLockedWithLeafContextProbed(
		ctx, true, nil, false, nil, nil)
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

// sameStageCreatedCipherForCleanup refuses to delete an encrypted file
// unless it is the same one the current Stage created using O_EXCL. It also
// refuses any file when Stage never successfully opened its target. Empty
// scopes may still be safely reclaimed. This is a fail-closed admission
// check, not atomic protection against a hostile same-UID entry swap.
func sameStageCreatedCipherForCleanup(
	c *InertRestoreCandidate, createdTarget *os.File, scanned os.FileInfo,
) bool {
	if c == nil || c.dir == nil {
		return false
	}
	if createdTarget == nil {
		return scanned == nil
	}
	if scanned == nil || createdTarget.Name() != c.archive {
		return false
	}
	onFD, err := createdTarget.Stat()
	if err != nil || !os.SameFile(onFD, scanned) ||
		onFD.Size() != scanned.Size() || onFD.Mode() != scanned.Mode() ||
		!onFD.ModTime().Equal(scanned.ModTime()) ||
		verifySealedFile(createdTarget, c.archive, onFD, onFD.Size(), true) != nil {
		return false
	}
	dir, err := verifyCandidateDirLock(c.directory, c.dir)
	return err == nil && os.SameFile(dir, c.directoryIdentity) &&
		sameInertCandidateParentIdentity(c.parent, c.parentIdentity)
}

// Failed Stage may unlink only its own newly O_EXCL-created ciphertext fd.
// Before target creation, the only safe cleanup is an EMPTY candidate scope.
// A different same-name file (even valid, identical ciphertext) is foreign.
func (c *InertRestoreCandidate) discardStageLocked(createdTarget *os.File) error {
	return c.discardLockedWithStageOwnership(false, createdTarget, true, nil)
}

// The internal pre-directory-unlink hook tests an uncooperative same-UID
// namespace replacement after the ciphertext leaf is removed. Production
// always passes nil; external code cannot obtain this callback.
func (c *InertRestoreCandidate) discardLockedProbed(
	requireFile bool, beforeDirectoryUnlink func(),
) error {
	return c.discardLockedWithStageOwnership(
		requireFile, nil, false, beforeDirectoryUnlink)
}

// Explicit Discard keeps the exact file inode inspected for deletion open
// until immediately before unlinkat, rather than trusting the same filename
// after an uncooperative same-UID actor has changed that directory entry.
func sameInspectedInertCipherForDiscard(
	c *InertRestoreCandidate, inspected *os.File, first os.FileInfo,
) bool {
	if c == nil || c.dir == nil || inspected == nil || first == nil ||
		inspected.Name() != c.archive || !validSealedArchivePath(c.archive) {
		return false
	}
	atFD, err := inspected.Stat()
	if err != nil || !os.SameFile(first, atFD) ||
		atFD.Size() != first.Size() || atFD.Mode() != first.Mode() ||
		!atFD.ModTime().Equal(first.ModTime()) ||
		verifySealedFile(inspected, c.archive, first, first.Size(), true) != nil ||
		!sameInertCandidateParentIdentity(c.parent, c.parentIdentity) {
		return false
	}
	locked, err := verifyCandidateDirLock(c.directory, c.dir)
	return err == nil && os.SameFile(locked, c.directoryIdentity)
}

// The private checkpoint runs after the exact cipher fd is pinned and the
// original parent is pinned, but BEFORE an irreversible ciphertext unlink.
// All production Discard paths pass nil; no external hook is exposed.
func (c *InertRestoreCandidate) discardLockedBeforeCipherUnlinkProbed(
	requireFile bool, beforeCipherUnlink func(),
) error {
	return c.discardLockedWithLeafProbe(
		requireFile, nil, false, beforeCipherUnlink, nil)
}

// Preserve the internal caller contract used by failed-Stage cleanup and
// the existing post-ciphertext, pre-directory-unlink regression tests.
func (c *InertRestoreCandidate) discardLockedWithStageOwnership(
	requireFile bool, createdTarget *os.File, stageOnly bool, beforeDirectoryUnlink func(),
) error {
	return c.discardLockedWithLeafProbe(
		requireFile, createdTarget, stageOnly, nil, beforeDirectoryUnlink)
}

// User-invoked Discard and failed-Stage cleanup share inode-anchored parent
// deletion. Explicit Discard borrows the exact inspected file descriptor;
// Stage instead validates its independently held O_EXCL-created file fd.
func (c *InertRestoreCandidate) discardLockedWithLeafProbe(
	requireFile bool, createdTarget *os.File, stageOnly bool,
	beforeCipherUnlink, beforeDirectoryUnlink func(),
) error {
	// Failed Stage cleanup must always attempt safe cleanup even if its
	// original request was cancelled. Existing private callers remain intact.
	return c.discardLockedWithLeafContextProbed(
		context.Background(), requireFile, createdTarget, stageOnly,
		beforeCipherUnlink, beforeDirectoryUnlink)
}

// Only the explicit user-invoked Discard supplies a cancellable context.
// Refuse before the FIRST irreversible unlink. Once ciphertext has been
// unlinked, finish directory sync/unlink regardless of cancellation: the
// original data cannot be restored and partial cleanup is less safe.
func (c *InertRestoreCandidate) discardLockedWithLeafContextProbed(
	ctx context.Context, requireFile bool, createdTarget *os.File, stageOnly bool,
	beforeCipherUnlink, beforeDirectoryUnlink func(),
) error {
	if c == nil || c.dir == nil || ctx == nil {
		return ErrUnsafeInertRestoreCandidate
	}
	defer func() {
		_ = c.dir.Close()
		c.dir = nil
	}()
	if ctx.Err() != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	file, err := inspectInertCandidateFile(c, !requireFile)
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	if stageOnly && !sameStageCreatedCipherForCleanup(c, createdTarget, file) {
		return ErrUnsafeInertRestoreCandidate
	}
	// The inventory inspection only returns FileInfo. Borrow a new exact
	// read-only fd from the already locked child inode, then compare to the
	// inspected snapshot. Never follow a substitute pathname. The fd remains
	// owned by this operation until every deletion is finished.
	var inspected *os.File
	if !stageOnly && file != nil {
		inspected, err = pinInspectedInertCandidateCipher(c, file)
		if err != nil {
			return ErrUnsafeInertRestoreCandidate
		}
		defer inspected.Close()
	}
	// Pin the admitted parent before deleting even the ciphertext. Opening
	// by pathname is read-only; its inode must match the parent captured
	// at child-lease admission before any irreversible operation.
	parent, err := openInertCandidateParentForDiscard(c.parent, c.parentIdentity)
	if err != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	defer parent.Close()
	// This is the last read-only admission step before any deletion.
	if ctx.Err() != nil {
		return ErrUnsafeInertRestoreCandidate
	}
	if file != nil {
		if beforeCipherUnlink != nil {
			beforeCipherUnlink()
		}
		if ctx.Err() != nil {
			return ErrUnsafeInertRestoreCandidate
		}
		// Re-evaluate exact file custody immediately before irreversible
		// fd-relative unlink. Explicit Discard uses the inode inspected on
		// entry; failed Stage uses only its own created target. This is not
		// atomic against continuously racing same-UID directory swaps.
		if stageOnly {
			if !sameStageCreatedCipherForCleanup(c, createdTarget, file) {
				return ErrUnsafeInertRestoreCandidate
			}
		} else if !sameInspectedInertCipherForDiscard(c, inspected, file) {
			return ErrUnsafeInertRestoreCandidate
		}
		// Cancellation and unlinkat are not atomic, but do not knowingly
		// delete a valid candidate after the operator cancels Discard.
		if ctx.Err() != nil {
			return ErrUnsafeInertRestoreCandidate
		}
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
