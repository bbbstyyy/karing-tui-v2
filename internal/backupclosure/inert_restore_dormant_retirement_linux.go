//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const dormantRuleRetiredPrefix = ".ktui-inert-rules-retired-v1-"

var ErrDormantRuleRetirement = errors.New("inactive authenticated rule retirement refused")

// DormantRuleRetirementReceipt proves only a completed in-place namespace
// retirement. The rule bytes are still on disk, private and UNTRUSTED for
// future use. This is not garbage collection or a restore authorization.
type DormantRuleRetirementReceipt struct {
	ArchiveSHA256        string
	InventorySHA256      string
	RetiredScopeSHA256   string
	RuleCount            int
	RuleBytes            int64
	Quarantined          bool
	RequiresManualReview bool
	RestoreSupported     bool
	RestoreReady         bool
}

// QuarantineDormantRuleBundle is an explicitly requested internal operation.
// The caller supplies a prior read-only ADR 0116 report as an EXPECTATION,
// never as an authorization. It independently reauthenticates the encrypted
// candidate, exact journal, live CAS, filesystem namespace and every rule
// before an atomic no-replace rename to an inactive, unrecognized namespace.
//
// No resources are unlinked, imported or activated. A crash after rename can
// leave a retired scope that blocks the ordinary staging/audit paths until a
// separate, explicitly designed physical-reclamation procedure exists.
func (l *InertRestoreResourceLease) QuarantineDormantRuleBundle(
	ctx context.Context, key [32]byte, expected AuthenticatedDormantRuleReport,
) (DormantRuleRetirementReceipt, error) {
	return l.quarantineDormantRuleBundle(ctx, key, expected, nil, nil)
}

// Both hooks are internal fault boundaries; the second intentionally models
// a crash between atomic rename and durable parent fsync.
func (l *InertRestoreResourceLease) quarantineDormantRuleBundle(
	ctx context.Context, key [32]byte, expected AuthenticatedDormantRuleReport,
	beforeRename, afterRename func() error,
) (DormantRuleRetirementReceipt, error) {
	var empty DormantRuleRetirementReceipt
	if l == nil || ctx == nil || key == ([32]byte{}) ||
		!validLowerSHA(expected.ArchiveSHA256) ||
		!validLowerSHA(expected.InventorySHA256) ||
		expected.RuleCount <= 0 || expected.RuleCount > MaxClosureRuleSets ||
		expected.RuleBytes <= 0 || expected.RuleBytes > MaxClosureRuleBytes ||
		!expected.RuleBytesVerified || !expected.Inactive ||
		!expected.RequiresRevalidation || expected.RestoreSupported ||
		expected.RestoreReady ||
		expected.ScopeSHA256 != shaHex([]byte(dormantRuleBundlePrefix+expected.ArchiveSHA256)) {
		return empty, ErrDormantRuleRetirement
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()

	// Fixed lock order: candidate -> private stage root. This uses no
	// unlocked preflight receipt as a durable file or transaction lease.
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revalidateLocked(bounded, key) != nil ||
		expected.ArchiveSHA256 != l.record.ArchiveSHA256 ||
		expected.InventorySHA256 != l.record.InventorySHA256 {
		return empty, ErrDormantRuleRetirement
	}
	dbPath := l.live.Path()
	if !filepath.IsAbs(dbPath) || filepath.Clean(dbPath) != dbPath {
		return empty, ErrDormantRuleRetirement
	}
	rootPath := filepath.Join(filepath.Dir(dbPath), dormantRuleRootName)
	if !validPortablePreviewRoot(rootPath) ||
		rootPath == l.candidate.parent || rootPath == l.candidate.directory ||
		strings.HasPrefix(rootPath, l.candidate.parent+string(os.PathSeparator)) ||
		strings.HasPrefix(l.candidate.parent, rootPath+string(os.PathSeparator)) {
		return empty, ErrDormantRuleRetirement
	}
	receipt := SealedArchiveReceipt{
		ArchiveSHA256:   l.record.ArchiveSHA256,
		InventorySHA256: l.record.InventorySHA256,
		Bytes:           l.record.ArchiveBytes,
		Format:          l.candidate.receipt.Format,
	}
	inventory, err := readAuthenticatedInventory(
		bounded, l.candidate.archive, key, receipt)
	if err != nil || len(inventory.RuleSets) != expected.RuleCount {
		return empty, ErrDormantRuleRetirement
	}
	var total int64
	for _, rule := range inventory.RuleSets {
		if rule.Size <= 0 || rule.Size > MaxClosureRuleBytes ||
			total > MaxClosureRuleBytes-rule.Size {
			return empty, ErrDormantRuleRetirement
		}
		total += rule.Size
	}
	if total != expected.RuleBytes {
		return empty, ErrDormantRuleRetirement
	}
	finalName := dormantRuleBundlePrefix + receipt.ArchiveSHA256
	retiredName := dormantRuleRetiredPrefix + receipt.ArchiveSHA256
	root, err := lockSealedArchiveParent(bounded, rootPath)
	if err != nil {
		return empty, ErrDormantRuleRetirement
	}
	defer root.Close()
	rootBefore, err := root.Stat()
	if err != nil || !privatePortableDirectory(rootBefore) {
		return empty, ErrDormantRuleRetirement
	}
	first, err := scanDormantRuleScopeEntries(bounded, root)
	if err != nil || len(first) > MaxDormantRuleBundles {
		return empty, ErrDormantRuleRetirement
	}
	var target *dormantRuleScopeObservation
	for i := range first {
		if first[i].phase != "published_untrusted" {
			return empty, ErrDormantRuleRetirement
		}
		if first[i].name == finalName {
			target = &first[i]
		}
	}
	if target == nil || len(target.files) != len(inventory.RuleSets) ||
		target.bytes != total {
		return empty, ErrDormantRuleRetirement
	}
	// The existing target basename cannot be replaced; an interrupted
	// earlier retirement is always refused, never adopted or overwritten.
	if _, statErr := os.Lstat(filepath.Join(rootPath, retiredName)); statErr == nil ||
		!errors.Is(statErr, os.ErrNotExist) {
		return empty, ErrDormantRuleRetirement
	}
	fd, err := unix.Openat(int(root.Fd()), finalName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, ErrDormantRuleRetirement
	}
	dir := os.NewFile(uintptr(fd), "inert-retiring-rules")
	if dir == nil {
		_ = unix.Close(fd)
		return empty, ErrDormantRuleRetirement
	}
	defer dir.Close()
	dirIdentity, err := dir.Stat()
	if err != nil || !sameLeasedFile(dirIdentity, target.info) ||
		verifyDormantRuleScope(root, finalName, dir, dirIdentity) != nil {
		return empty, ErrDormantRuleRetirement
	}
	pinnedNames := make(map[string]os.FileInfo, len(target.files))
	for _, observed := range target.files {
		pinnedNames[observed.name] = observed.info
	}
	if len(pinnedNames) != len(inventory.RuleSets) ||
		verifyDormantRulePayload(bounded, root, finalName, dir,
			dirIdentity, inventory.RuleSets, pinnedNames) != nil {
		return empty, ErrDormantRuleRetirement
	}
	if beforeRename != nil && beforeRename() != nil {
		return empty, ErrDormantRuleRetirement
	}
	second, err := scanDormantRuleScopeEntries(bounded, root)
	if err != nil || !sameDormantRuleScopes(first, second) ||
		verifyDormantRulePayload(bounded, root, finalName, dir,
			dirIdentity, inventory.RuleSets, pinnedNames) != nil ||
		l.revalidateLocked(bounded, key) != nil ||
		verifyDormantRuleScope(root, finalName, dir, dirIdentity) != nil ||
		bounded.Err() != nil {
		return empty, ErrDormantRuleRetirement
	}
	// RENAME_NOREPLACE is the sole atomic namespace mutation. No unknown
	// inode is ever unlinked, and no final-looking scope survives this commit.
	if err := unix.Renameat2(int(root.Fd()), finalName, int(root.Fd()),
		retiredName, unix.RENAME_NOREPLACE); err != nil {
		return empty, ErrDormantRuleRetirement
	}
	// From here an error is an UNCERTAIN COMMIT, never an excuse to rename
	// back, recursively clean a scope, or claim it remains published.
	if afterRename != nil && afterRename() != nil {
		return empty, ErrDormantRuleRetirement
	}
	var old unix.Stat_t
	if err := unix.Fstatat(int(root.Fd()), finalName, &old,
		unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return empty, ErrDormantRuleRetirement
	}
	if verifyDormantRulePayload(bounded, root, retiredName, dir,
		dirIdentity, inventory.RuleSets, pinnedNames) != nil ||
		dir.Sync() != nil || root.Sync() != nil ||
		verifyDormantRulePayload(bounded, root, retiredName, dir,
			dirIdentity, inventory.RuleSets, pinnedNames) != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return empty, ErrDormantRuleRetirement
	}
	rootAfter, rootErr := root.Stat()
	atPath, pathErr := os.Lstat(rootPath)
	if rootErr != nil || pathErr != nil ||
		!sameLeasedFile(rootBefore, rootAfter) ||
		!os.SameFile(rootAfter, atPath) ||
		verifySealedArchiveParent(rootPath) != nil ||
		bounded.Err() != nil {
		return empty, ErrDormantRuleRetirement
	}
	return DormantRuleRetirementReceipt{
		ArchiveSHA256:        receipt.ArchiveSHA256,
		InventorySHA256:      receipt.InventorySHA256,
		RetiredScopeSHA256:   shaHex([]byte(retiredName)),
		RuleCount:            len(inventory.RuleSets),
		RuleBytes:            total,
		Quarantined:          true,
		RequiresManualReview: true,
		RestoreSupported:     false,
		RestoreReady:         false,
	}, nil
}
