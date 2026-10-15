//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const dormantRuleReclaimPrefix = ".ktui-inert-rules-reclaim-v1-"

var ErrRetiredRuleReclaim = errors.New("authenticated retired rule reclamation refused")

// RetiredRuleInspection is a one-call, read-only observation, not a durable
// authorization or inode lease. It includes no path, rule content or key.
type RetiredRuleInspection struct {
	ArchiveSHA256        string
	InventorySHA256      string
	RetiredScopeSHA256   string
	RuleCount            int
	RuleBytes            int64
	ContentVerified      bool
	RequiresRevalidation bool
	RestoreSupported     bool
	RestoreReady         bool
}

// RetiredRuleReclaimIntent records a successful *namespace-only* transition.
// The original 0400 rule bytes remain present: nothing has been physically
// reclaimed. A post-rename error yields NO receipt and requires manual review.
type RetiredRuleReclaimIntent struct {
	ArchiveSHA256        string
	InventorySHA256      string
	ReclaimScopeSHA256   string
	RuleCount            int
	RuleBytes            int64
	IntentPublished      bool
	BytesDeleted         bool
	RequiresManualReview bool
	RestoreSupported     bool
	RestoreReady         bool
}

// InspectRetiredDormantRuleBundle uses a freshly acquired, journal-bound
// encrypted candidate lease to independently authenticate a quarantined
// scope after process death or restart. Its result expires at return.
func (l *InertRestoreResourceLease) InspectRetiredDormantRuleBundle(
	ctx context.Context, key [32]byte,
) (RetiredRuleInspection, error) {
	return l.inspectRetiredDormantRuleBundle(ctx, key, nil)
}

func (l *InertRestoreResourceLease) inspectRetiredDormantRuleBundle(
	ctx context.Context, key [32]byte, afterFirstScan func() error,
) (RetiredRuleInspection, error) {
	var zero RetiredRuleInspection
	if l == nil || ctx == nil || key == ([32]byte{}) {
		return zero, ErrRetiredRuleReclaim
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()

	pins, err := openRetiredRuleInspection(bounded, l, key)
	if err != nil {
		return zero, ErrRetiredRuleReclaim
	}
	defer pins.Close()
	if afterFirstScan != nil && afterFirstScan() != nil {
		return zero, ErrRetiredRuleReclaim
	}
	if pins.revalidate(bounded, l, key) != nil {
		return zero, ErrRetiredRuleReclaim
	}
	return RetiredRuleInspection{
		ArchiveSHA256: pins.receipt.ArchiveSHA256,
		InventorySHA256: pins.receipt.InventorySHA256,
		RetiredScopeSHA256: shaHex([]byte(pins.retiredName)),
		RuleCount: len(pins.inventory.RuleSets),
		RuleBytes: pins.bytes,
		ContentVerified: true,
		RequiresRevalidation: true,
		RestoreSupported: false,
		RestoreReady: false,
	}, nil
}

// BeginRetiredDormantRuleReclaim requires an explicit authenticated report as
// a CAS EXPECTATION. It independently verifies everything again and atomically
// changes only the private directory basename. It deliberately never unlinks
// rule bytes; a later, independently reviewed transaction must handle that.
func (l *InertRestoreResourceLease) BeginRetiredDormantRuleReclaim(
	ctx context.Context, key [32]byte, expected RetiredRuleInspection,
) (RetiredRuleReclaimIntent, error) {
	return l.beginRetiredDormantRuleReclaim(ctx, key, expected, nil, nil)
}

// Fault hooks are package-private and never dispatched by a daemon/TUI/API.
func (l *InertRestoreResourceLease) beginRetiredDormantRuleReclaim(
	ctx context.Context, key [32]byte, expected RetiredRuleInspection,
	beforeRename, afterRename func() error,
) (RetiredRuleReclaimIntent, error) {
	var zero RetiredRuleReclaimIntent
	if l == nil || ctx == nil || key == ([32]byte{}) ||
		!validLowerSHA(expected.ArchiveSHA256) ||
		!validLowerSHA(expected.InventorySHA256) ||
		expected.RetiredScopeSHA256 != shaHex([]byte(dormantRuleRetiredPrefix+expected.ArchiveSHA256)) ||
		!expected.ContentVerified || !expected.RequiresRevalidation ||
		expected.RestoreSupported || expected.RestoreReady ||
		expected.RuleCount <= 0 || expected.RuleCount > MaxClosureRuleSets ||
		expected.RuleBytes <= 0 || expected.RuleBytes > MaxClosureRuleBytes {
		return zero, ErrRetiredRuleReclaim
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()

	pins, err := openRetiredRuleInspection(bounded, l, key)
	if err != nil {
		return zero, ErrRetiredRuleReclaim
	}
	defer pins.Close()
	if pins.receipt.ArchiveSHA256 != expected.ArchiveSHA256 ||
		pins.receipt.InventorySHA256 != expected.InventorySHA256 ||
		len(pins.inventory.RuleSets) != expected.RuleCount ||
		pins.bytes != expected.RuleBytes {
		return zero, ErrRetiredRuleReclaim
	}
	if beforeRename != nil && beforeRename() != nil {
		return zero, ErrRetiredRuleReclaim
	}
	if pins.revalidate(bounded, l, key) != nil {
		return zero, ErrRetiredRuleReclaim
	}
	newName := dormantRuleReclaimPrefix + pins.receipt.ArchiveSHA256
	var dest unix.Stat_t
	if err := unix.Fstatat(int(pins.root.Fd()), newName, &dest,
		unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return zero, ErrRetiredRuleReclaim
	}
	// This is the ONLY mutation. A failed post-rename fsync is an uncertain
	// commit; never roll back, replace, delete or silently readopt either name.
	if unix.Renameat2(int(pins.root.Fd()), pins.retiredName,
		int(pins.root.Fd()), newName, unix.RENAME_NOREPLACE) != nil {
		return zero, ErrRetiredRuleReclaim
	}
	if afterRename != nil && afterRename() != nil {
		return zero, ErrRetiredRuleReclaim
	}
	var old unix.Stat_t
	if err := unix.Fstatat(int(pins.root.Fd()), pins.retiredName,
		&old, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return zero, ErrRetiredRuleReclaim
	}
	if verifyDormantRulePayload(bounded, pins.root, newName, pins.dir,
		pins.scopeInfo, pins.inventory.RuleSets, pins.files) != nil ||
		pins.dir.Sync() != nil || pins.root.Sync() != nil ||
		verifyDormantRulePayload(bounded, pins.root, newName, pins.dir,
			pins.scopeInfo, pins.inventory.RuleSets, pins.files) != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return zero, ErrRetiredRuleReclaim
	}
	after, err := scanRetiredRuleRoot(bounded, pins.root, newName)
	if err != nil || !sameReclaimTransition(pins.scopes, after,
		pins.retiredName, newName) ||
		verifyRetiredRuleParent(pins.rootPath, pins.root, pins.rootInfo, true) != nil ||
		verifyDormantRuleScope(pins.root, newName, pins.dir, pins.scopeInfo) != nil ||
		bounded.Err() != nil {
		return zero, ErrRetiredRuleReclaim
	}
	return RetiredRuleReclaimIntent{
		ArchiveSHA256: pins.receipt.ArchiveSHA256,
		InventorySHA256: pins.receipt.InventorySHA256,
		ReclaimScopeSHA256: shaHex([]byte(newName)),
		RuleCount: len(pins.inventory.RuleSets),
		RuleBytes: pins.bytes,
		IntentPublished: true,
		BytesDeleted: false,
		RequiresManualReview: true,
		RestoreSupported: false,
		RestoreReady: false,
	}, nil
}

type retiredRulePins struct {
	root *os.File
	dir *os.File
	rootPath string
	retiredName string
	rootInfo os.FileInfo
	scopeInfo os.FileInfo
	receipt SealedArchiveReceipt
	inventory Inventory
	scopes []dormantRuleScopeObservation
	files map[string]os.FileInfo
	bytes int64
}

func (p *retiredRulePins) Close() {
	if p != nil {
		if p.dir != nil { _ = p.dir.Close(); p.dir = nil }
		if p.root != nil { _ = p.root.Close(); p.root = nil }
	}
}

// The caller MUST hold the parent ciphertext lease mutex. The original
// candidate directory flock is held by that parent until its Close.
func openRetiredRuleInspection(
	ctx context.Context, l *InertRestoreResourceLease, key [32]byte,
) (_ *retiredRulePins, err error) {
	if ctx == nil || l == nil || l.live == nil || l.candidate == nil ||
		l.revalidateLocked(ctx, key) != nil {
		return nil, ErrRetiredRuleReclaim
	}
	dbPath := l.live.Path()
	if !filepath.IsAbs(dbPath) || filepath.Clean(dbPath) != dbPath {
		return nil, ErrRetiredRuleReclaim
	}
	path := filepath.Join(filepath.Dir(dbPath), dormantRuleRootName)
	if !validPortablePreviewRoot(path) ||
		path == l.candidate.parent || path == l.candidate.directory ||
		strings.HasPrefix(path, l.candidate.parent+string(os.PathSeparator)) ||
		strings.HasPrefix(l.candidate.parent, path+string(os.PathSeparator)) {
		return nil, ErrRetiredRuleReclaim
	}
	receipt := SealedArchiveReceipt{
		ArchiveSHA256: l.record.ArchiveSHA256,
		InventorySHA256: l.record.InventorySHA256,
		Bytes: l.record.ArchiveBytes,
		Format: l.candidate.receipt.Format,
	}
	inventory, err := readAuthenticatedInventory(ctx,
		l.candidate.archive, key, receipt)
	if err != nil || !validLowerSHA(receipt.ArchiveSHA256) ||
		len(inventory.RuleSets) == 0 ||
		len(inventory.RuleSets) > MaxClosureRuleSets {
		return nil, ErrRetiredRuleReclaim
	}
	var total int64
	for _, rule := range inventory.RuleSets {
		if rule.Size <= 0 || rule.Size > MaxClosureRuleBytes ||
			total > MaxClosureRuleBytes-rule.Size {
			return nil, ErrRetiredRuleReclaim
		}
		total += rule.Size
	}
	p := &retiredRulePins{
		rootPath: path,
		retiredName: dormantRuleRetiredPrefix + receipt.ArchiveSHA256,
		receipt: receipt, inventory: inventory, bytes: total,
	}
	defer func() { if err != nil { p.Close() } }()
	p.root, err = lockSealedArchiveParent(ctx, path)
	if err != nil { return nil, ErrRetiredRuleReclaim }
	p.rootInfo, err = p.root.Stat()
	if err != nil || !privatePortableDirectory(p.rootInfo) {
		return nil, ErrRetiredRuleReclaim
	}
	p.scopes, err = scanRetiredRuleRoot(ctx, p.root, "")
	if err != nil { return nil, ErrRetiredRuleReclaim }
	var scope *dormantRuleScopeObservation
	for i := range p.scopes {
		if p.scopes[i].name == p.retiredName {
			scope = &p.scopes[i]
		}
	}
	if scope == nil || len(scope.files) != len(inventory.RuleSets) ||
		scope.bytes != total {
		return nil, ErrRetiredRuleReclaim
	}
	fd, openErr := unix.Openat(int(p.root.Fd()), p.retiredName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if openErr != nil { return nil, ErrRetiredRuleReclaim }
	p.dir = os.NewFile(uintptr(fd), "retired-rule-reauthentication")
	if p.dir == nil {
		_ = unix.Close(fd)
		return nil, ErrRetiredRuleReclaim
	}
	p.scopeInfo, err = p.dir.Stat()
	if err != nil || !sameLeasedFile(p.scopeInfo, scope.info) ||
		verifyDormantRuleScope(p.root, p.retiredName, p.dir, p.scopeInfo) != nil {
		return nil, ErrRetiredRuleReclaim
	}
	p.files = make(map[string]os.FileInfo, len(scope.files))
	for _, file := range scope.files { p.files[file.name] = file.info }
	if len(p.files) != len(inventory.RuleSets) ||
		verifyDormantRulePayload(ctx, p.root, p.retiredName, p.dir,
			p.scopeInfo, inventory.RuleSets, p.files) != nil {
		return nil, ErrRetiredRuleReclaim
	}
	return p, nil
}

func (p *retiredRulePins) revalidate(
	ctx context.Context, l *InertRestoreResourceLease, key [32]byte,
) error {
	if p == nil || l == nil || ctx == nil || ctx.Err() != nil {
		return ErrRetiredRuleReclaim
	}
	second, err := scanRetiredRuleRoot(ctx, p.root, "")
	if err != nil || !sameDormantRuleScopes(p.scopes, second) ||
		verifyDormantRulePayload(ctx, p.root, p.retiredName, p.dir,
			p.scopeInfo, p.inventory.RuleSets, p.files) != nil ||
		l.revalidateLocked(ctx, key) != nil {
		return ErrRetiredRuleReclaim
	}
	third, err := scanRetiredRuleRoot(ctx, p.root, "")
	if err != nil || !sameDormantRuleScopes(p.scopes, third) ||
		verifyDormantRulePayload(ctx, p.root, p.retiredName, p.dir,
			p.scopeInfo, p.inventory.RuleSets, p.files) != nil ||
		verifyRetiredRuleParent(p.rootPath, p.root, p.rootInfo, false) != nil ||
		ctx.Err() != nil {
		return ErrRetiredRuleReclaim
	}
	return nil
}

func verifyRetiredRuleParent(path string, root *os.File, before os.FileInfo, changed bool) error {
	if root == nil || before == nil { return ErrRetiredRuleReclaim }
	now, err := root.Stat()
	atPath, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !privatePortableDirectory(now) ||
		!os.SameFile(before, now) || !os.SameFile(now, atPath) ||
		verifySealedArchiveParent(path) != nil {
		return ErrRetiredRuleReclaim
	}
	if !changed && !sameLeasedFile(before, now) { return ErrRetiredRuleReclaim }
	return nil
}

// Deliberately separate from ADR 0115's ordinary scanner: that scanner MUST
// continue refusing retired/reclaiming entries, which never become loadable.
func scanRetiredRuleRoot(
	ctx context.Context, root *os.File, allowReclaim string,
) ([]dormantRuleScopeObservation, error) {
	if ctx == nil || root == nil || ctx.Err() != nil { return nil, ErrRetiredRuleReclaim }
	fd, err := unix.Openat(int(root.Fd()), ".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil { return nil, ErrRetiredRuleReclaim }
	reader := os.NewFile(uintptr(fd), "retired-rule-root-reader")
	if reader == nil { _ = unix.Close(fd); return nil, ErrRetiredRuleReclaim }
	defer reader.Close()
	entries, err := reader.ReadDir(MaxDormantRuleAuditScopes + 1)
	if (err != nil && !errors.Is(err, io.EOF)) ||
		len(entries) > MaxDormantRuleAuditScopes ||
		len(entries) > MaxDormantRuleBundles { return nil, ErrRetiredRuleReclaim }
	out := make([]dormantRuleScopeObservation, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		phase := ""
		switch {
		case strings.HasPrefix(name, dormantRuleBundlePrefix) &&
			validLowerSHA(strings.TrimPrefix(name, dormantRuleBundlePrefix)):
			phase = "published_untrusted"
		case strings.HasPrefix(name, dormantRuleRetiredPrefix) &&
			validLowerSHA(strings.TrimPrefix(name, dormantRuleRetiredPrefix)):
			phase = "retired_untrusted"
		case allowReclaim != "" && name == allowReclaim &&
			strings.HasPrefix(name, dormantRuleReclaimPrefix) &&
			validLowerSHA(strings.TrimPrefix(name, dormantRuleReclaimPrefix)):
			phase = "reclaiming_untrusted"
		default:
			return nil, ErrRetiredRuleReclaim
		}
		if !entry.IsDir() || ctx.Err() != nil { return nil, ErrRetiredRuleReclaim }
		// A retired rule is always private 0400. Call the existing strict
		// shape verifier in its published (nonempty, read-only) mode.
		scope, err := inspectDormantRuleScopeShape(ctx, root, name, "published_untrusted")
		if err != nil { return nil, ErrRetiredRuleReclaim }
		scope.phase = phase
		out = append(out, scope)
	}
	return out, nil
}

// The source directory's inode remains the same across a successful atomic
// rename; only the one recognized basename/phase may change.
func sameReclaimTransition(
	before, after []dormantRuleScopeObservation, oldName, newName string,
) bool {
	if len(before) != len(after) { return false }
	want := make([]dormantRuleScopeObservation, len(before))
	copy(want, before)
	changed := 0
	for i := range want {
		if want[i].name == oldName && want[i].phase == "retired_untrusted" {
			want[i].name = newName
			want[i].phase = "reclaiming_untrusted"
			changed++
		}
	}
	if changed != 1 { return false }
	sort.Slice(want, func(i, j int) bool { return want[i].name < want[j].name })
	return sameDormantRuleScopes(want, after)
}
