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

var ErrDormantRuleAuthentication = errors.New("dormant rule bundle authentication refused")

// AuthenticatedDormantRuleReport certifies one in-process, read-only
// comparison of a dormant rules directory with a journal-bound, authenticated
// ciphertext inventory. It is never a durable file lease or restore permit.
// No file path, plaintext rule, archived Core or SQLite payload is returned.
type AuthenticatedDormantRuleReport struct {
	ArchiveSHA256        string
	InventorySHA256      string
	ScopeSHA256          string
	RuleCount            int
	RuleBytes            int64
	RuleBytesVerified    bool
	Inactive             bool
	RequiresRevalidation bool
	RestoreSupported     bool
	RestoreReady         bool
}

// AuthenticateDormantRuleBundle works after the original stage process,
// anonymous O_TMPFILE pins and staging receipts are gone. The caller must
// independently reacquire a ciphertext lease with an explicit key and exact
// pending journal ID. No target directory is supplied by the caller.
// All observations expire at return; no Core or live resource path is changed.
func (l *InertRestoreResourceLease) AuthenticateDormantRuleBundle(
	ctx context.Context, key [32]byte,
) (AuthenticatedDormantRuleReport, error) {
	return l.authenticateDormantRuleBundle(ctx, key, nil)
}

// afterHash is package-private fault injection, not an import/cleanup hook.
func (l *InertRestoreResourceLease) authenticateDormantRuleBundle(
	ctx context.Context, key [32]byte, afterHash func() error,
) (AuthenticatedDormantRuleReport, error) {
	var empty AuthenticatedDormantRuleReport
	if l == nil || ctx == nil || key == ([32]byte{}) {
		return empty, ErrDormantRuleAuthentication
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()

	// Same lock order as ADR 0114: ciphertext lease, then dormant root.
	// The cipher lease is acquired anew after a process restart; the old
	// anonymous staging FDs and receipt are never used as trust evidence.
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revalidateLocked(bounded, key) != nil {
		return empty, ErrDormantRuleAuthentication
	}
	statePath := l.live.Path()
	if !filepath.IsAbs(statePath) || filepath.Clean(statePath) != statePath {
		return empty, ErrDormantRuleAuthentication
	}
	rootPath := filepath.Join(filepath.Dir(statePath), dormantRuleRootName)
	if !validPortablePreviewRoot(rootPath) ||
		rootPath == l.candidate.parent ||
		rootPath == l.candidate.directory ||
		strings.HasPrefix(rootPath, l.candidate.parent+string(os.PathSeparator)) ||
		strings.HasPrefix(l.candidate.parent, rootPath+string(os.PathSeparator)) {
		return empty, ErrDormantRuleAuthentication
	}
	receipt := SealedArchiveReceipt{
		ArchiveSHA256:   l.record.ArchiveSHA256,
		InventorySHA256: l.record.InventorySHA256,
		Bytes:           l.record.ArchiveBytes,
		Format:          l.candidate.receipt.Format,
	}
	inventory, err := readAuthenticatedInventory(
		bounded, l.candidate.archive, key, receipt)
	if err != nil || len(inventory.RuleSets) == 0 ||
		len(inventory.RuleSets) > MaxClosureRuleSets {
		return empty, ErrDormantRuleAuthentication
	}
	var total int64
	for _, rule := range inventory.RuleSets {
		if rule.Size <= 0 || rule.Size > MaxClosureRuleBytes ||
			total > MaxClosureRuleBytes-rule.Size {
			return empty, ErrDormantRuleAuthentication
		}
		total += rule.Size
	}
	if receipt.ArchiveSHA256 == "" || !validLowerSHA(receipt.ArchiveSHA256) {
		return empty, ErrDormantRuleAuthentication
	}
	finalName := dormantRuleBundlePrefix + receipt.ArchiveSHA256

	root, err := lockSealedArchiveParent(bounded, rootPath)
	if err != nil {
		return empty, ErrDormantRuleAuthentication
	}
	defer root.Close()
	rootIdentity, err := root.Stat()
	if err != nil || !privatePortableDirectory(rootIdentity) {
		return empty, ErrDormantRuleAuthentication
	}
	first, err := scanDormantRuleScopeEntries(bounded, root)
	if err != nil {
		return empty, ErrDormantRuleAuthentication
	}
	var target *dormantRuleScopeObservation
	finalCount := 0
	for i := range first {
		if first[i].phase != "published_untrusted" {
			// An interrupted stage is explicitly unresolved, never adopted.
			return empty, ErrDormantRuleAuthentication
		}
		finalCount++
		if first[i].name == finalName {
			target = &first[i]
		}
	}
	if target == nil || finalCount > MaxDormantRuleBundles ||
		len(target.files) != len(inventory.RuleSets) ||
		target.bytes != total {
		return empty, ErrDormantRuleAuthentication
	}

	fd, err := unix.Openat(int(root.Fd()), finalName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, ErrDormantRuleAuthentication
	}
	dir := os.NewFile(uintptr(fd), "authenticated-inert-rule-scope")
	if dir == nil {
		_ = unix.Close(fd)
		return empty, ErrDormantRuleAuthentication
	}
	defer dir.Close()
	identity, err := dir.Stat()
	if err != nil || !sameLeasedFile(identity, target.info) ||
		verifyDormantRuleScope(root, finalName, dir, identity) != nil {
		return empty, ErrDormantRuleAuthentication
	}
	// The first scan pins the directory/file inode identities only within
	// this call. Recreate no file and accept no extra or noncanonical name.
	expectedFiles := make(map[string]os.FileInfo, len(target.files))
	for _, observed := range target.files {
		expectedFiles[observed.name] = observed.info
	}
	if len(expectedFiles) != len(inventory.RuleSets) ||
		verifyDormantRulePayload(bounded, root, finalName, dir, identity,
			inventory.RuleSets, expectedFiles) != nil {
		return empty, ErrDormantRuleAuthentication
	}
	if afterHash != nil && afterHash() != nil {
		return empty, ErrDormantRuleAuthentication
	}
	second, err := scanDormantRuleScopeEntries(bounded, root)
	if err != nil || !sameDormantRuleScopes(first, second) {
		return empty, ErrDormantRuleAuthentication
	}
	// Re-authenticate the COMPLETE source ciphertext, the exact pending
	// journal and all applied/LKG/declaration/selection/Core CAS once more,
	// then independently hash each named rule again through no-follow FDs.
	if l.revalidateLocked(bounded, key) != nil ||
		verifyDormantRulePayload(bounded, root, finalName, dir, identity,
			inventory.RuleSets, expectedFiles) != nil {
		return empty, ErrDormantRuleAuthentication
	}
	third, err := scanDormantRuleScopeEntries(bounded, root)
	rootAfter, rootErr := root.Stat()
	atPath, pathErr := os.Lstat(rootPath)
	if err != nil || !sameDormantRuleScopes(first, third) ||
		rootErr != nil || pathErr != nil ||
		!sameLeasedFile(rootIdentity, rootAfter) ||
		!os.SameFile(rootAfter, atPath) ||
		verifySealedArchiveParent(rootPath) != nil ||
		verifyDormantRuleScope(root, finalName, dir, identity) != nil ||
		bounded.Err() != nil {
		return empty, ErrDormantRuleAuthentication
	}
	return AuthenticatedDormantRuleReport{
		ArchiveSHA256:        receipt.ArchiveSHA256,
		InventorySHA256:      receipt.InventorySHA256,
		ScopeSHA256:          shaHex([]byte(finalName)),
		RuleCount:            len(inventory.RuleSets),
		RuleBytes:            total,
		RuleBytesVerified:    true,
		Inactive:             true,
		RequiresRevalidation: true,
		RestoreSupported:     false,
		RestoreReady:         false,
	}, nil
}
