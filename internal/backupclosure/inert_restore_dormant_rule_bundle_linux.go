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
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	MaxDormantRuleBundles    = 8
	dormantRuleRootName      = "inert-rule-bundles"
	dormantRuleBundlePrefix  = ".ktui-inert-rules-v1-"
	dormantRulePendingPrefix = ".ktui-inert-rules-pending-"
)

var ErrDormantRuleBundle = errors.New("dormant encrypted-restore rules bundle refused")

// DormantRuleBundleReceipt is an AUDIT ONLY. It is not a ruleset lease, a
// recoverable generation, a path usable by sing-box, or restore authority.
// In particular neither stage location nor rule bytes are returned.
type DormantRuleBundleReceipt struct {
	ArchiveSHA256    string
	InventorySHA256  string
	RuleCount        int
	RuleBytes        int64
	ScopeSHA256      string
	Inactive         bool
	RestoreSupported bool
	RestoreReady     bool
}

// StageDormantRuleBundle publishes RULES ONLY into a separate, already owned
// and private 0700 directory. It does not write the live core/rule-sets tree,
// publish a historical executable, stage credential SQLite or touch live
// daemon state. A whole directory is published by RENAME_NOREPLACE, never by
// incrementally replacing live file paths. Each on-disk rule stays 0400.
//
// This is intentionally a one-way, inert preparation primitive. No caller can
// activate, import, or link any staged resource using its receipt. An
// interrupted stage leaves a recognizable private pending directory for
// operator review; it is NEVER automatically adopted or recursively pruned.
func (p *InertPinnedRestoreResources) StageDormantRuleBundle(
	ctx context.Context, stageParent string, key [32]byte,
) (DormantRuleBundleReceipt, error) {
	return p.stageDormantRuleBundle(ctx, stageParent, key, nil)
}

// beforePublish is a package-private fault injection boundary. It runs after
// each rule has been fsynced, privately named, and reverified, but BEFORE the
// single no-replace publication. It has no daemon/CLI/TUI exposure.
func (p *InertPinnedRestoreResources) stageDormantRuleBundle(
	ctx context.Context, stageParent string, key [32]byte,
	beforePublish func() error,
) (report DormantRuleBundleReceipt, err error) {
	if p == nil || ctx == nil || key == ([32]byte{}) ||
		!validPortablePreviewRoot(stageParent) ||
		verifySealedArchiveParent(stageParent) != nil {
		return report, ErrDormantRuleBundle
	}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()

	// Lock order: child bundle -> ciphertext parent -> dormant root. Holding
	// the source's existing flock and write-CAS verification until after
	// fsync/rename prevents Close from racing this publication.
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parent == nil || p.scratch == nil || p.identity == nil ||
		!p.registered || len(p.rules) == 0 ||
		len(p.rules) > MaxClosureRuleSets {
		return report, ErrDormantRuleBundle
	}
	l := p.parent
	l.mu.Lock()
	defer l.mu.Unlock()
	// Refuse arbitrary owned directories, including an empty live rule
	// tree. This inactive directory is reserved directly beside the
	// authoritative state DB, not within the active Core artifact layout.
	if l.candidate == nil || l.live == nil || !l.pinnedResourcesActive ||
		stageParent != filepath.Join(filepath.Dir(l.live.Path()), dormantRuleRootName) ||
		stageParent == l.candidate.directory ||
		stageParent == l.candidate.parent ||
		stageParent == filepath.Dir(l.candidate.parent) ||
		strings.HasPrefix(stageParent, l.candidate.parent+string(os.PathSeparator)) ||
		stageParent == p.scratchPath ||
		strings.HasPrefix(stageParent, p.scratchPath+string(os.PathSeparator)) ||
		strings.HasPrefix(p.scratchPath, stageParent+string(os.PathSeparator)) {
		return report, ErrDormantRuleBundle
	}
	if l.revalidateLocked(ctx, key) != nil ||
		verifyAnonymousScratchParent(p.scratchPath, p.scratch, p.identity) != nil ||
		p.verifyPinnedFiles(ctx) != nil {
		return report, ErrDormantRuleBundle
	}
	root, err := lockSealedArchiveParent(ctx, stageParent)
	if err != nil {
		return report, ErrDormantRuleBundle
	}
	defer root.Close()
	if err := inspectDormantRuleBundleRoot(ctx, root); err != nil {
		return report, ErrDormantRuleBundle
	}
	receipt := SealedArchiveReceipt{
		ArchiveSHA256:   l.record.ArchiveSHA256,
		InventorySHA256: l.record.InventorySHA256,
		Bytes:           l.record.ArchiveBytes,
		Format:          l.candidate.receipt.Format,
	}
	inventory, err := readAuthenticatedInventory(ctx, l.candidate.archive, key, receipt)
	if err != nil || len(inventory.RuleSets) != len(p.rules) ||
		len(inventory.RuleSets) > MaxClosureRuleSets {
		return report, ErrDormantRuleBundle
	}
	var total int64
	for i, rule := range inventory.RuleSets {
		if p.rules[i].sha != rule.SHA256 || p.rules[i].size != rule.Size {
			return report, ErrDormantRuleBundle
		}
		total += rule.Size
	}
	if total <= 0 || total > MaxClosureRuleBytes ||
		requireSealedArchiveSpace(stageParent, total) != nil {
		return report, ErrDormantRuleBundle
	}

	// A deterministic final scope prevents silently creating repeated
	// unbounded copies of one archive, and refuses any existing collision.
	finalName := dormantRuleBundlePrefix + receipt.ArchiveSHA256
	if _, statErr := os.Lstat(filepath.Join(stageParent, finalName)); statErr == nil ||
		!errors.Is(statErr, os.ErrNotExist) {
		return report, ErrDormantRuleBundle
	}
	tempPath, err := os.MkdirTemp(stageParent, dormantRulePendingPrefix)
	if err != nil {
		return report, ErrDormantRuleBundle
	}
	tempName := filepath.Base(tempPath)
	// No unknown entry is ever removed. A SIGKILL after mkdir leaves an
	// intentionally non-authoritative pending directory for manual review.
	var temp *os.File
	var initial os.FileInfo
	created := make(map[string]os.FileInfo, len(inventory.RuleSets))
	published := false
	defer func() {
		if !published {
			cleanupOwnedDormantRuleTemp(root, temp, tempName, initial, created)
		}
		if temp != nil {
			if temp.Close() != nil {
				err = errors.Join(err, ErrDormantRuleBundle)
			}
		}
	}()
	temp, initial, err = openOwnedDormantRuleScope(root, tempName)
	if err != nil {
		return DormantRuleBundleReceipt{}, ErrDormantRuleBundle
	}
	for i, rule := range inventory.RuleSets {
		if ctx.Err() != nil {
			return DormantRuleBundleReceipt{}, ctx.Err()
		}
		// Source remains anonymous (nlink=0). Only the isolated,
		// unpublished 0700 directory contains a named plaintext rule;
		// historical Core and credential-bearing SQLite stay untouched.
		if _, err = p.rules[i].file.Seek(0, io.SeekStart); err != nil {
			return DormantRuleBundleReceipt{}, ErrDormantRuleBundle
		}
		name := strings.TrimPrefix(rule.RelativePath, "rule-sets/sha256/")
		if name == rule.RelativePath || name != filepath.Base(name) ||
			(name != rule.SHA256+".json" && name != rule.SHA256+".srs") {
			return DormantRuleBundleReceipt{}, ErrDormantRuleBundle
		}
		owned, copyErr := writeDormantPrivateRule(ctx, temp, name,
			p.rules[i].file, rule.Size, rule.SHA256)
		if owned != nil {
			created[name] = owned
		}
		if copyErr != nil {
			return DormantRuleBundleReceipt{}, ErrDormantRuleBundle
		}
		observed, checkErr := inspectTargetRule(ctx, temp, rule)
		if checkErr != nil || !observed.exists || owned == nil ||
			!os.SameFile(owned, observed.info) {
			// Keep the original inode in the cleanup map; a path replaced
			// after its exclusive creation is not ours to delete.
			return DormantRuleBundleReceipt{}, ErrDormantRuleBundle
		}
	}
	if temp.Sync() != nil ||
		verifyDormantRulePayload(ctx, root, tempName, temp, initial,
			inventory.RuleSets, created) != nil {
		return DormantRuleBundleReceipt{}, ErrDormantRuleBundle
	}
	if beforePublish != nil && beforePublish() != nil {
		return DormantRuleBundleReceipt{}, ErrDormantRuleBundle
	}
	// Untrusted same-UID writes at the injection boundary, late additions,
	// and even byte-identical inode replacements must be refused before
	// committing this private directory as a single inactive bundle.
	if verifyDormantRulePayload(ctx, root, tempName, temp, initial,
		inventory.RuleSets, created) != nil ||
		p.verifyPinnedFiles(ctx) != nil ||
		l.revalidateLocked(ctx, key) != nil ||
		verifyDormantRuleScope(root, tempName, temp, initial) != nil ||
		ctx.Err() != nil {
		return DormantRuleBundleReceipt{}, ErrDormantRuleBundle
	}
	if err = unix.Renameat2(int(root.Fd()), tempName,
		int(root.Fd()), finalName, unix.RENAME_NOREPLACE); err != nil {
		return DormantRuleBundleReceipt{}, ErrDormantRuleBundle
	}
	// Publication is atomic at the DIRECTORY level. A power loss after
	// rename but before parent fsync may leave either outcome: never report
	// success without fsync and never delete a potentially published bundle.
	published = true
	if temp.Sync() != nil || root.Sync() != nil ||
		verifyDormantRuleScope(root, finalName, temp, initial) != nil {
		return DormantRuleBundleReceipt{}, ErrDormantRuleBundle
	}
	return DormantRuleBundleReceipt{
		ArchiveSHA256:    receipt.ArchiveSHA256,
		InventorySHA256:  receipt.InventorySHA256,
		RuleCount:        len(inventory.RuleSets),
		RuleBytes:        total,
		ScopeSHA256:      shaHex([]byte(finalName)),
		Inactive:         true,
		RestoreSupported: false,
		RestoreReady:     false,
	}, nil
}

// Re-open a fresh descriptor: ReadDir on the original staging directory
// would retain an offset across validations. Require EXACTLY the expected
// content-addressed files, not merely successful hashes for known names.
func verifyDormantRulePayload(
	ctx context.Context, root *os.File, name string, dir *os.File,
	original os.FileInfo, rules []RuleDigest, created map[string]os.FileInfo,
) error {
	if ctx == nil || ctx.Err() != nil ||
		verifyDormantRuleScope(root, name, dir, original) != nil ||
		len(rules) == 0 || len(rules) != len(created) {
		return ErrDormantRuleBundle
	}
	fd, err := unix.Openat(int(root.Fd()), name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrDormantRuleBundle
	}
	reader := os.NewFile(uintptr(fd), "inert-stage-check")
	if reader == nil {
		_ = unix.Close(fd)
		return ErrDormantRuleBundle
	}
	info, statErr := reader.Stat()
	if statErr != nil || !os.SameFile(info, original) {
		_ = reader.Close()
		return ErrDormantRuleBundle
	}
	entries, readErr := reader.ReadDir(len(rules) + 1)
	closeErr := reader.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) ||
		closeErr != nil || len(entries) != len(rules) {
		return ErrDormantRuleBundle
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || created[entry.Name()] == nil {
			return ErrDormantRuleBundle
		}
	}
	for _, rule := range rules {
		leaf := strings.TrimPrefix(rule.RelativePath, "rule-sets/sha256/")
		observed, err := inspectTargetRule(ctx, dir, rule)
		if err != nil || !observed.exists || created[leaf] == nil ||
			!os.SameFile(created[leaf], observed.info) {
			return ErrDormantRuleBundle
		}
	}
	if verifyDormantRuleScope(root, name, dir, original) != nil {
		return ErrDormantRuleBundle
	}
	return nil
}

// Files are named ONLY inside the private, not-yet-published staging
// directory. O_EXCL and parent-relative O_NOFOLLOW prevent overwrites.
// A crash can leave an incomplete pending scope, never an active rules tree.
func writeDormantPrivateRule(
	ctx context.Context, dir *os.File, name string, source *os.File,
	size int64, wantSHA string,
) (identity os.FileInfo, err error) {
	if ctx == nil || dir == nil || source == nil || size <= 0 ||
		!validLowerSHA(wantSHA) || filepath.Base(name) != name ||
		(name != wantSHA+".json" && name != wantSHA+".srs") {
		return nil, ErrDormantRuleBundle
	}
	fd, err := unix.Openat(int(dir.Fd()), name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, ErrDormantRuleBundle
	}
	file := os.NewFile(uintptr(fd), "inert-pending-rule")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrDormantRuleBundle
	}
	defer func() {
		if file.Close() != nil {
			err = ErrDormantRuleBundle
		}
	}()
	// Return the inode identity even on a copy failure; the caller can then
	// remove ONLY this exact file, not any user-controlled replacement.
	identity, err = file.Stat()
	if err != nil || !identity.Mode().IsRegular() ||
		identity.Mode().Perm() != 0o600 {
		return nil, ErrDormantRuleBundle
	}
	hash := sha256.New()
	n, err := io.CopyN(io.MultiWriter(file, hash),
		sealedContextReader{ctx: ctx, src: source}, size)
	if err != nil || n != size ||
		hex.EncodeToString(hash.Sum(nil)) != wantSHA ||
		file.Chmod(0o400) != nil || file.Sync() != nil || ctx.Err() != nil {
		return identity, ErrDormantRuleBundle
	}
	return identity, nil
}

// Scan ONLY a dedicated, existing 0700 root while holding its exclusive
// flock. No automatic deletion/adoption. An incomplete scope blocks another
// writer until a separate explicit, authenticated recovery procedure exists.
func inspectDormantRuleBundleRoot(ctx context.Context, root *os.File) error {
	if ctx == nil || root == nil {
		return ErrDormantRuleBundle
	}
	entries, err := root.ReadDir(MaxDormantRuleBundles + 2)
	if err != nil && !errors.Is(err, io.EOF) {
		return ErrDormantRuleBundle
	}
	if len(entries) >= MaxDormantRuleBundles {
		return ErrDormantRuleBundle
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := entry.Name()
		if strings.HasPrefix(name, dormantRulePendingPrefix) {
			return ErrDormantRuleBundle
		}
		if !strings.HasPrefix(name, dormantRuleBundlePrefix) ||
			!validLowerSHA(strings.TrimPrefix(name, dormantRuleBundlePrefix)) ||
			!entry.IsDir() {
			return ErrDormantRuleBundle
		}
		path := filepath.Join(root.Name(), name)
		info, statErr := os.Lstat(path)
		if statErr != nil || !privatePortableDirectory(info) {
			return ErrDormantRuleBundle
		}
	}
	return nil
}

func openOwnedDormantRuleScope(root *os.File, name string) (*os.File, os.FileInfo, error) {
	if root == nil || !strings.HasPrefix(name, dormantRulePendingPrefix) ||
		filepath.Base(name) != name {
		return nil, nil, ErrDormantRuleBundle
	}
	fd, err := unix.Openat(int(root.Fd()), name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, ErrDormantRuleBundle
	}
	dir := os.NewFile(uintptr(fd), name)
	if dir == nil {
		_ = unix.Close(fd)
		return nil, nil, ErrDormantRuleBundle
	}
	info, statErr := dir.Stat()
	if statErr != nil || !privatePortableDirectory(info) ||
		verifyDormantRuleScope(root, name, dir, info) != nil {
		_ = dir.Close()
		return nil, nil, ErrDormantRuleBundle
	}
	return dir, info, nil
}

func verifyDormantRuleScope(root *os.File, name string, dir *os.File, original os.FileInfo) error {
	if root == nil || dir == nil || original == nil ||
		filepath.Base(name) != name {
		return ErrDormantRuleBundle
	}
	var st unix.Stat_t
	if unix.Fstatat(int(root.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrDormantRuleBundle
	}
	info, err := dir.Stat()
	if err != nil || !privatePortableDirectory(info) ||
		!os.SameFile(original, info) {
		return ErrDormantRuleBundle
	}
	current, ok := info.Sys().(*syscall.Stat_t)
	if !ok || current.Dev != uint64(st.Dev) || current.Ino != st.Ino {
		return ErrDormantRuleBundle
	}
	return nil
}

// Best effort ONLY for entries provably created by this call. If anything
// has been replaced or the scope gained an unknown entry, leave it untouched
// for later explicit operator review. Never use recursive RemoveAll.
func cleanupOwnedDormantRuleTemp(
	root, dir *os.File, name string, identity os.FileInfo,
	files map[string]os.FileInfo,
) {
	if root == nil || dir == nil || identity == nil ||
		verifyDormantRuleScope(root, name, dir, identity) != nil {
		return
	}
	for leaf, original := range files {
		if original == nil || filepath.Base(leaf) != leaf {
			return
		}
		var st unix.Stat_t
		if unix.Fstatat(int(dir.Fd()), leaf, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return
		}
		before, ok := original.Sys().(*syscall.Stat_t)
		if !ok || before.Ino != st.Ino || before.Dev != uint64(st.Dev) ||
			st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
			return
		}
	}
	for leaf := range files {
		if unix.Unlinkat(int(dir.Fd()), leaf, 0) != nil {
			return
		}
	}
	if unix.Unlinkat(int(root.Fd()), name, unix.AT_REMOVEDIR) == nil {
		_ = root.Sync()
	}
}
