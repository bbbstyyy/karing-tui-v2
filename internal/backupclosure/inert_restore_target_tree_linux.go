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

var ErrInertPortableTargetTree = errors.New("inert portable target rule tree refused")

// InertPortableTargetTreeReport contains only counts and digests. This is a
// current-process, READ-ONLY inspection, not a persistent target resource
// lease, a migration plan, an import grant or a restore permit.
type InertPortableTargetTreeReport struct {
	ArchiveSHA256          string
	InventorySHA256        string
	TargetRootSHA256       string
	RuleSetCount           int
	ExistingRuleSets       int
	MissingRuleSets        int
	ExistingRuleSetBytes   int64
	DirectoriesPinned      bool
	RestoreSupported       bool
	RestoreReady           bool
}

// InspectPortableTargetRuleTree verifies an ALREADY EXISTING Linux target
// state root and, when rules are present, its core/rule-sets/sha256 tree.
// It never creates directories, opens a file for writing, stages plaintext
// resources, trusts archive paths as local paths, or changes live SQLite.
//
// Each path component is opened via a pinned parent descriptor with
// O_NOFOLLOW; the target root and rule tree must be UID-owned 0700 dirs.
// Existing content-addressed rule files must be single-linked, private,
// non-executable and exactly match authenticated archive SHA/size.
// Missing files are counted as future work, never filled in. All directory
// and file identities are checked again before returning under the held
// encrypted-candidate flock and journal/live CAS.
func (l *InertRestoreResourceLease) InspectPortableTargetRuleTree(
	ctx context.Context, targetStateRoot string, key [32]byte,
) (InertPortableTargetTreeReport, error) {
	return l.inspectPortableTargetRuleTree(ctx, targetStateRoot, key, nil)
}

// afterScan is an internal fault injection point, not an external API.
func (l *InertRestoreResourceLease) inspectPortableTargetRuleTree(
	ctx context.Context, targetStateRoot string, key [32]byte,
	afterScan func() error,
) (InertPortableTargetTreeReport, error) {
	var empty InertPortableTargetTreeReport
	if l == nil || ctx == nil || key == ([32]byte{}) ||
		!validPortablePreviewRoot(targetStateRoot) {
		return empty, ErrInertPortableTargetTree
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.revalidateLocked(bounded, key); err != nil {
		return empty, ErrInertPortableTargetTree
	}
	if targetStateRoot == l.candidate.directory ||
		targetStateRoot == l.candidate.parent ||
		strings.HasPrefix(targetStateRoot, l.candidate.parent+string(os.PathSeparator)) {
		return empty, ErrInertPortableTargetTree
	}
	receipt := SealedArchiveReceipt{
		ArchiveSHA256: l.record.ArchiveSHA256,
		InventorySHA256: l.record.InventorySHA256,
		Bytes: l.record.ArchiveBytes,
		Format: l.candidate.receipt.Format,
	}
	inventory, err := readAuthenticatedInventory(bounded, l.candidate.archive, key, receipt)
	if err != nil {
		return empty, ErrInertPortableTargetTree
	}
	tree, err := openPrivatePortableTargetTree(targetStateRoot, len(inventory.RuleSets) > 0)
	if err != nil {
		return empty, ErrInertPortableTargetTree
	}
	defer tree.Close()

	observed := make([]targetRuleObservation, 0, len(inventory.RuleSets))
	existing := 0
	var existingBytes int64
	for _, rule := range inventory.RuleSets {
		observation, err := inspectTargetRule(bounded, tree.ruleDir(), rule)
		if err != nil {
			return empty, ErrInertPortableTargetTree
		}
		observed = append(observed, observation)
		if observation.exists {
			existing++
			existingBytes += rule.Size
		}
	}
	if afterScan != nil && afterScan() != nil {
		return empty, ErrInertPortableTargetTree
	}
	if tree.verify() != nil {
		return empty, ErrInertPortableTargetTree
	}
	// Repeat each rule check so a same-byte inode replacement, newly
	// introduced symlink, hard link or late writer is not certified.
	for i, rule := range inventory.RuleSets {
		again, err := inspectTargetRule(bounded, tree.ruleDir(), rule)
		if err != nil || !sameTargetRuleObservation(observed[i], again) {
			return empty, ErrInertPortableTargetTree
		}
	}
	if tree.verify() != nil || l.revalidateLocked(bounded, key) != nil ||
		tree.verify() != nil || bounded.Err() != nil {
		return empty, ErrInertPortableTargetTree
	}
	return InertPortableTargetTreeReport{
		ArchiveSHA256: receipt.ArchiveSHA256,
		InventorySHA256: receipt.InventorySHA256,
		TargetRootSHA256: shaHex([]byte(targetStateRoot)),
		RuleSetCount: len(inventory.RuleSets),
		ExistingRuleSets: existing,
		MissingRuleSets: len(inventory.RuleSets) - existing,
		ExistingRuleSetBytes: existingBytes,
		DirectoriesPinned: true,
		RestoreSupported: false,
		RestoreReady: false,
	}, nil
}

type portableDirComponent struct {
	parent *os.File
	dir *os.File
	name string
	info os.FileInfo
	private bool
}

type privatePortableTargetTree struct {
	root *os.File
	components []portableDirComponent
	hasRules bool
}

func openPrivatePortableTargetTree(root string, hasRules bool) (_ *privatePortableTargetTree, err error) {
	if !validPortablePreviewRoot(root) {
		return nil, ErrInertPortableTargetTree
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|
		unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInertPortableTargetTree
	}
	base := os.NewFile(uintptr(fd), "/")
	if base == nil {
		_ = unix.Close(fd)
		return nil, ErrInertPortableTargetTree
	}
	tree := &privatePortableTargetTree{root: base, hasRules: hasRules}
	defer func() {
		if err != nil {
			_ = tree.Close()
		}
	}()
	parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
	privateIndex := len(parts)-1
	if hasRules {
		parts = append(parts, "core", "rule-sets", "sha256")
	}
	parent := base
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, ErrInertPortableTargetTree
		}
		dirFD, openErr := unix.Openat(int(parent.Fd()), part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, ErrInertPortableTargetTree
		}
		dir := os.NewFile(uintptr(dirFD), part)
		if dir == nil {
			_ = unix.Close(dirFD)
			return nil, ErrInertPortableTargetTree
		}
		info, statErr := dir.Stat()
		if statErr != nil || !info.IsDir() ||
			(i >= privateIndex && !privatePortableDirectory(info)) {
			_ = dir.Close()
			return nil, ErrInertPortableTargetTree
		}
		tree.components = append(tree.components, portableDirComponent{
			parent: parent, dir: dir, name: part, info: info,
			private: i >= privateIndex,
		})
		parent = dir
	}
	if tree.verify() != nil {
		return nil, ErrInertPortableTargetTree
	}
	return tree, nil
}

func privatePortableDirectory(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid() && st.Nlink >= 2
}

func (t *privatePortableTargetTree) ruleDir() *os.File {
	if t == nil || !t.hasRules || len(t.components) == 0 {
		return nil
	}
	return t.components[len(t.components)-1].dir
}

func (t *privatePortableTargetTree) verify() error {
	if t == nil || t.root == nil || len(t.components) == 0 {
		return ErrInertPortableTargetTree
	}
	for _, component := range t.components {
		var pathStat unix.Stat_t
		if unix.Fstatat(int(component.parent.Fd()), component.name,
			&pathStat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			pathStat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrInertPortableTargetTree
		}
		info, err := component.dir.Stat()
		if err != nil || !info.IsDir() ||
			(component.private && !privatePortableDirectory(info)) {
			return ErrInertPortableTargetTree
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Dev != uint64(pathStat.Dev) || st.Ino != pathStat.Ino ||
			!os.SameFile(component.info, info) {
			return ErrInertPortableTargetTree
		}
	}
	return nil
}

func (t *privatePortableTargetTree) Close() error {
	if t == nil {
		return nil
	}
	var errs []error
	for i := len(t.components)-1; i >= 0; i-- {
		if err := t.components[i].dir.Close(); err != nil {
			errs = append(errs, ErrInertPortableTargetTree)
		}
	}
	t.components = nil
	if t.root != nil {
		if err := t.root.Close(); err != nil {
			errs = append(errs, ErrInertPortableTargetTree)
		}
		t.root = nil
	}
	return errors.Join(errs...)
}

type targetRuleObservation struct {
	exists bool
	info os.FileInfo
}

func sameTargetRuleObservation(a, b targetRuleObservation) bool {
	if a.exists != b.exists {
		return false
	}
	return !a.exists || (a.info != nil && b.info != nil &&
		os.SameFile(a.info, b.info) &&
		a.info.Mode() == b.info.Mode() && a.info.Size() == b.info.Size() &&
		a.info.ModTime().Equal(b.info.ModTime()))
}

// A missing file is acceptable as a future import requirement; an existing
// file is ALWAYS independently authenticated, never overwritten or reused as
// a trusted resource handle by the caller.
func inspectTargetRule(ctx context.Context, dir *os.File, rule RuleDigest) (ob targetRuleObservation, err error) {
	if ctx == nil || dir == nil || ctx.Err() != nil ||
		!validLowerSHA(rule.SHA256) || rule.Size <= 0 ||
		rule.RelativePath == "" {
		return ob, ErrInertPortableTargetTree
	}
	name := strings.TrimPrefix(rule.RelativePath, "rule-sets/sha256/")
	if name == rule.RelativePath || filepath.Base(name) != name ||
		(name != rule.SHA256+".json" && name != rule.SHA256+".srs") {
		return ob, ErrInertPortableTargetTree
	}
	var pathStat unix.Stat_t
	if statErr := unix.Fstatat(int(dir.Fd()), name, &pathStat,
		unix.AT_SYMLINK_NOFOLLOW); errors.Is(statErr, unix.ENOENT) {
		return ob, nil
	} else if statErr != nil {
		return ob, ErrInertPortableTargetTree
	}
	if pathStat.Mode&unix.S_IFMT != unix.S_IFREG ||
		int(pathStat.Uid) != os.Getuid() || pathStat.Nlink != 1 ||
		pathStat.Mode&0o777 != 0o600 && pathStat.Mode&0o777 != 0o400 ||
		pathStat.Size != rule.Size {
		return ob, ErrInertPortableTargetTree
	}
	fd, openErr := unix.Openat(int(dir.Fd()), name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return ob, ErrInertPortableTargetTree
	}
	file := os.NewFile(uintptr(fd), "pinned-existing-rule")
	if file == nil {
		_ = unix.Close(fd)
		return ob, ErrInertPortableTargetTree
	}
	defer func() {
		if file.Close() != nil {
			err = ErrInertPortableTargetTree
		}
	}()
	before, err := file.Stat()
	if err != nil || !validTargetRuleInfo(before, pathStat, rule.Size) {
		return ob, ErrInertPortableTargetTree
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(sealedContextReader{ctx: ctx, src: file}, rule.Size+1))
	if err != nil || n != rule.Size ||
		hex.EncodeToString(h.Sum(nil)) != rule.SHA256 {
		return ob, ErrInertPortableTargetTree
	}
	after, err := file.Stat()
	var finalStat unix.Stat_t
	if err != nil || !sameLeasedFile(before, after) ||
		unix.Fstatat(int(dir.Fd()), name, &finalStat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!validTargetRuleInfo(after, finalStat, rule.Size) ||
		finalStat.Ino != pathStat.Ino || finalStat.Dev != pathStat.Dev ||
		ctx.Err() != nil {
		return ob, ErrInertPortableTargetTree
	}
	return targetRuleObservation{exists: true, info: after}, nil
}

func validTargetRuleInfo(info os.FileInfo, st unix.Stat_t, size int64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() != size ||
		(info.Mode().Perm() != 0o400 && info.Mode().Perm() != 0o600) ||
		int(st.Uid) != os.Getuid() || st.Nlink != 1 ||
		st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Size != size || st.Mode&0o777 != uint32(info.Mode().Perm()) {
		return false
	}
	actual, ok := info.Sys().(*syscall.Stat_t)
	return ok && actual.Dev == uint64(st.Dev) && actual.Ino == st.Ino
}
