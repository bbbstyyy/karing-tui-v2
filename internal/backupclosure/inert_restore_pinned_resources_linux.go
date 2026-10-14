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

	"golang.org/x/sys/unix"
)

var ErrInertPinnedRestoreResources = errors.New("inert restore pinned resources refused")

// InertPinnedResourceEvidence is intentionally non-secret and non-authorizing.
// An open descriptor does NOT grant a permission to import, link, activate or
// execute any archived resource; restore permission flags always remain false.
type InertPinnedResourceEvidence struct {
	ArchiveSHA256    string
	InventorySHA256  string
	RuleSetCount     int
	RuleSetBytes     int64
	CoreIncluded     bool
	CoreBytes        int64
	DescriptorCount  int
	RestoreSupported bool
	RestoreReady     bool
}

type pinnedAnonymousResource struct {
	file     *os.File
	identity os.FileInfo
	sha      string
	size     int64
}

// InertPinnedRestoreResources retains a bounded set of UNLINKED Linux
// O_TMPFILE descriptors across same-process checks. This object is explicitly
// not durable across SIGKILL/restart. It has no exported resource FD or path
// accessor and it is never passed to the runtime core.
type InertPinnedRestoreResources struct {
	mu           sync.Mutex
	parent       *InertRestoreResourceLease
	scratchPath  string
	scratch      *os.File
	identity     os.FileInfo
	rules        []pinnedAnonymousResource
	core         *pinnedAnonymousResource
	evidence     InertPinnedResourceEvidence
}

// PinAnonymousRestoreResources differs from ADR 0110's one-time probe by
// retaining EVERY verified, non-executable, unlinked rule/core FD until its
// explicit Close. The caller must keep the original ciphertext journal lease
// open, and MUST call Revalidate before any future read or operation.
// There is deliberately NO publication, execution or import operation here.
func (l *InertRestoreResourceLease) PinAnonymousRestoreResources(
	ctx context.Context, scratchParent string, key [32]byte,
) (*InertPinnedRestoreResources, error) {
	return l.pinAnonymousRestoreResources(ctx, scratchParent, key, nil)
}

// afterStage is a private test-only fault boundary; no external API accepts it.
func (l *InertRestoreResourceLease) pinAnonymousRestoreResources(
	ctx context.Context, scratchParent string, key [32]byte,
	afterStage func() error,
) (result *InertPinnedRestoreResources, err error) {
	if l == nil || ctx == nil || key == ([32]byte{}) ||
		!filepath.IsAbs(scratchParent) ||
		filepath.Clean(scratchParent) != scratchParent ||
		verifySealedArchiveParent(scratchParent) != nil {
		return nil, ErrInertPinnedRestoreResources
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()

	// One lock spans archive authentication, every plaintext anonymous copy,
	// final inode checks and the last live SQLite/journal CAS. A concurrent
	// l.Close cannot drop the directory flock during this critical section.
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revalidateLocked(bounded, key) != nil {
		return nil, ErrInertPinnedRestoreResources
	}
	if scratchParent == l.candidate.directory ||
		scratchParent == l.candidate.parent ||
		scratchParent == filepath.Dir(l.candidate.parent) ||
		strings.HasPrefix(scratchParent, l.candidate.parent+string(os.PathSeparator)) {
		return nil, ErrInertPinnedRestoreResources
	}
	dir, identity, err := openAnonymousScratchParent(scratchParent)
	if err != nil {
		return nil, ErrInertPinnedRestoreResources
	}
	pins := &InertPinnedRestoreResources{
		parent: l, scratchPath: scratchParent, scratch: dir, identity: identity,
	}
	// Failed operations close EVERY FD, including partial inodes, and return
	// no object. Never leave a named or partially usable recovery artifact.
	ready := false
	defer func() {
		if !ready {
			_ = pins.Close()
			result = nil
		}
	}()
	receipt := SealedArchiveReceipt{
		ArchiveSHA256: l.record.ArchiveSHA256,
		InventorySHA256: l.record.InventorySHA256,
		Bytes: l.record.ArchiveBytes,
		Format: l.candidate.receipt.Format,
	}
	inventory, err := readAuthenticatedInventory(
		bounded, l.candidate.archive, key, receipt)
	if err != nil {
		return nil, ErrInertPinnedRestoreResources
	}
	var ruleBytes, coreBytes int64
	for _, rule := range inventory.RuleSets {
		ruleBytes += rule.Size
	}
	if inventory.Core != nil {
		coreBytes = inventory.Core.Size
	}
	if ruleBytes+coreBytes > 0 &&
		requireSealedArchiveSpace(scratchParent, ruleBytes+coreBytes) != nil {
		return nil, ErrInertPinnedRestoreResources
	}
	if err := streamAnonymousArchiveResourcesWithConsumer(
		bounded, l.candidate.archive, key, receipt, inventory, dir,
		func(ctx context.Context, input io.Reader, scratch *os.File,
			size int64, sha string, isCore bool) error {
			item, err := openPinnedAnonymousResource(ctx, input, scratch, size, sha)
			if err != nil {
				return err
			}
			if isCore {
				if pins.core != nil {
					_ = item.file.Close()
					return ErrInertPinnedRestoreResources
				}
				pins.core = &item
			} else {
				if len(pins.rules) >= MaxClosureRuleSets {
					_ = item.file.Close()
					return ErrInertPinnedRestoreResources
				}
				pins.rules = append(pins.rules, item)
			}
			return nil
		}); err != nil {
		return nil, ErrInertPinnedRestoreResources
	}
	if len(pins.rules) != len(inventory.RuleSets) ||
		(pins.core != nil) != (inventory.Core != nil) {
		return nil, ErrInertPinnedRestoreResources
	}
	if afterStage != nil && afterStage() != nil {
		return nil, ErrInertPinnedRestoreResources
	}
	if verifyAnonymousScratchParent(scratchParent, dir, identity) != nil ||
		pins.verifyPinnedFiles(bounded) != nil ||
		l.revalidateLocked(bounded, key) != nil ||
		verifyAnonymousScratchParent(scratchParent, dir, identity) != nil ||
		bounded.Err() != nil {
		return nil, ErrInertPinnedRestoreResources
	}
	pins.evidence = InertPinnedResourceEvidence{
		ArchiveSHA256: receipt.ArchiveSHA256,
		InventorySHA256: receipt.InventorySHA256,
		RuleSetCount: len(pins.rules),
		RuleSetBytes: ruleBytes,
		CoreIncluded: pins.core != nil,
		CoreBytes: coreBytes,
		DescriptorCount: len(pins.rules),
		RestoreSupported: false,
		RestoreReady: false,
	}
	if pins.core != nil {
		pins.evidence.DescriptorCount++
	}
	ready = true
	return pins, nil
}

// Evidence never publishes the descriptors or a name that could be passed to
// sing-box. After Close, it returns an all-zero report.
func (p *InertPinnedRestoreResources) Evidence() InertPinnedResourceEvidence {
	if p == nil {
		return InertPinnedResourceEvidence{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parent == nil || p.scratch == nil {
		return InertPinnedResourceEvidence{}
	}
	return p.evidence
}

// Revalidate re-authenticates the original ciphertext and all current live
// boundaries while holding both the pin and candidate locks. Every anonymous
// file is independently SHA/size/inode/mode verified, with a second scratch
// identity check. Revalidation is time-bounded and never authorizes restore.
func (p *InertPinnedRestoreResources) Revalidate(ctx context.Context, key [32]byte) error {
	if p == nil || ctx == nil || key == ([32]byte{}) {
		return ErrInertPinnedRestoreResources
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parent == nil || p.scratch == nil || p.identity == nil {
		return ErrInertPinnedRestoreResources
	}
	p.parent.mu.Lock()
	defer p.parent.mu.Unlock()
	if p.parent.revalidateLocked(bounded, key) != nil ||
		verifyAnonymousScratchParent(p.scratchPath, p.scratch, p.identity) != nil ||
		p.verifyPinnedFiles(bounded) != nil ||
		p.parent.revalidateLocked(bounded, key) != nil ||
		verifyAnonymousScratchParent(p.scratchPath, p.scratch, p.identity) != nil ||
		bounded.Err() != nil {
		return ErrInertPinnedRestoreResources
	}
	return nil
}

func (p *InertPinnedRestoreResources) verifyPinnedFiles(ctx context.Context) error {
	if p == nil || len(p.rules) > MaxClosureRuleSets ||
		p.scratch == nil || p.identity == nil {
		return ErrInertPinnedRestoreResources
	}
	for i := range p.rules {
		if verifyPinnedAnonymousResource(ctx, &p.rules[i]) != nil {
			return ErrInertPinnedRestoreResources
		}
	}
	if p.core != nil && verifyPinnedAnonymousResource(ctx, p.core) != nil {
		return ErrInertPinnedRestoreResources
	}
	return nil
}

func verifyPinnedAnonymousResource(ctx context.Context, item *pinnedAnonymousResource) error {
	if ctx == nil || item == nil || item.file == nil || item.identity == nil ||
		item.size <= 0 || !validLowerSHA(item.sha) {
		return ErrInertPinnedRestoreResources
	}
	before, err := item.file.Stat()
	if err != nil || !os.SameFile(item.identity, before) ||
		!validAnonymousResourceFile(before, item.size, 0o400) {
		item.file.Seek == nil {
		return ErrInertPinnedRestoreResources
	}
	if _, err := item.file.Seek(0, io.SeekStart); err != nil {
		return ErrInertPinnedRestoreResources
	}
	hash := sha256.New()
	n, err := io.CopyN(hash, sealedContextReader{ctx: ctx, src: item.file}, item.size)
	if err != nil || n != item.size ||
		hex.EncodeToString(hash.Sum(nil)) != item.sha {
		return ErrInertPinnedRestoreResources
	}
	var excess [1]byte
	if _, err := item.file.Read(excess[:]); !errors.Is(err, io.EOF) {
		return ErrInertPinnedRestoreResources
	}
	after, err := item.file.Stat()
	if err != nil || !sameLeasedFile(before, after) ||
		!os.SameFile(item.identity, after) ||
		!validAnonymousResourceFile(after, item.size, 0o400) || ctx.Err() != nil {
		return ErrInertPinnedRestoreResources
	}
	return nil
}

// openPinnedAnonymousResource is the only writer of the anonymous inode. It
// cannot accept an arbitrary path or export a file descriptor. If either
// copy or verification fails, Close is guaranteed via the failure defer.
func openPinnedAnonymousResource(
	ctx context.Context, input io.Reader, dir *os.File, size int64, sha string,
) (item pinnedAnonymousResource, err error) {
	if ctx == nil || input == nil || dir == nil || size <= 0 ||
		!validLowerSHA(sha) {
		return item, ErrInertPinnedRestoreResources
	}
	fd, err := unix.Openat(int(dir.Fd()), ".",
		unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return item, ErrInertPinnedRestoreResources
	}
	file := os.NewFile(uintptr(fd), "inert-pinned-anonymous")
	if file == nil {
		_ = unix.Close(fd)
		return item, ErrInertPinnedRestoreResources
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = file.Close()
		}
	}()
	before, err := file.Stat()
	if err != nil || !validAnonymousResourceFile(before, 0, 0o600) {
		return item, ErrInertPinnedRestoreResources
	}
	hash := sha256.New()
	n, err := io.CopyN(io.MultiWriter(file, hash),
		sealedContextReader{ctx: ctx, src: input}, size)
	if err != nil || n != size || hex.EncodeToString(hash.Sum(nil)) != sha {
		return item, ErrInertPinnedRestoreResources
	}
	if file.Chmod(0o400) != nil || file.Sync() != nil {
		return item, ErrInertPinnedRestoreResources
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) ||
		!validAnonymousResourceFile(after, size, 0o400) {
		return item, ErrInertPinnedRestoreResources
	}
	item = pinnedAnonymousResource{file: file, identity: after, size: size, sha: sha}
	if verifyPinnedAnonymousResource(ctx, &item) != nil {
		return pinnedAnonymousResource{}, ErrInertPinnedRestoreResources
	}
	succeeded = true
	return item, nil
}

// Close drops the only retained anonymous resource references. The source
// ciphertext/journal are deliberately left untouched. Close is idempotent
// and can be invoked after parent lease Close or a failed verification.
func (p *InertPinnedRestoreResources) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var errs []error
	for i := range p.rules {
		if p.rules[i].file != nil {
			if p.rules[i].file.Close() != nil {
				errs = append(errs, ErrInertPinnedRestoreResources)
			}
		}
	}
	p.rules = nil
	if p.core != nil {
		if p.core.file != nil && p.core.file.Close() != nil {
			errs = append(errs, ErrInertPinnedRestoreResources)
		}
		p.core = nil
	}
	if p.scratch != nil {
		if p.scratch.Close() != nil {
			errs = append(errs, ErrInertPinnedRestoreResources)
		}
		p.scratch = nil
	}
	p.parent = nil
	p.identity = nil
	p.scratchPath = ""
	p.evidence = InertPinnedResourceEvidence{}
	return errors.Join(errs...)
}
