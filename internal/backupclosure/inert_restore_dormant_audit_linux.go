//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
	"golang.org/x/sys/unix"
)

const MaxDormantRuleAuditScopes = 16

var ErrDormantRuleBundleAudit = errors.New("read-only dormant rules inventory refused")

// DormantRuleScopeAudit is a bounded, non-authorizing directory-shape report.
// A published-looking basename and its files are NOT authenticated archive
// material: matching the content-addressed filenames is not a digest check.
type DormantRuleScopeAudit struct {
	ScopeSHA256 string
	Phase       string // "pending" or "published_untrusted"
	RuleFiles   int
	RuleBytes   int64
}

// DormantRuleBundleAudit exposes neither local paths nor rule contents.
// Even a structurally intact published bundle still needs the original
// encrypted archive, live journal/CAS and independent content authentication.
type DormantRuleBundleAudit struct {
	Scopes               []DormantRuleScopeAudit
	PendingCount         int
	PublishedCount       int
	PreparedJournalCount int
	RequiresManualReview bool
	RuleBytesVerified    bool
	RestoreSupported     bool
	RestoreReady         bool
}

// InspectDormantRuleBundles is read-only and needs no archival encryption key.
// The target namespace is derived exclusively from the live SQLite path;
// callers cannot use this function to browse arbitrary directories. No
// automatic adoption, cleanup, restore or live Core rule publication occurs.
func InspectDormantRuleBundles(ctx context.Context, live *storage.Store) (DormantRuleBundleAudit, error) {
	return inspectDormantRuleBundles(ctx, live, nil)
}

// afterScan is an internal fault seam to test same-UID pathname/entry races.
func inspectDormantRuleBundles(
	ctx context.Context, live *storage.Store, afterScan func() error,
) (DormantRuleBundleAudit, error) {
	var empty DormantRuleBundleAudit
	if ctx == nil || live == nil {
		return empty, ErrDormantRuleBundleAudit
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	dbPath := live.Path()
	if !filepath.IsAbs(dbPath) || filepath.Clean(dbPath) != dbPath ||
		!validPortablePreviewRoot(filepath.Dir(dbPath)) {
		return empty, ErrDormantRuleBundleAudit
	}
	rootPath := filepath.Join(filepath.Dir(dbPath), dormantRuleRootName)
	if !validPortablePreviewRoot(rootPath) {
		return empty, ErrDormantRuleBundleAudit
	}
	bounded, cancel := context.WithTimeout(ctx, sealedArchiveTimeout)
	defer cancel()
	beforeRecords, err := live.InspectInertRestoreRecords(bounded)
	if err != nil {
		return empty, ErrDormantRuleBundleAudit
	}
	root, err := lockSealedArchiveParent(bounded, rootPath)
	if err != nil {
		return empty, ErrDormantRuleBundleAudit
	}
	defer root.Close()
	rootBefore, err := root.Stat()
	if err != nil || !privatePortableDirectory(rootBefore) {
		return empty, ErrDormantRuleBundleAudit
	}
	first, err := scanDormantRuleScopeEntries(bounded, root)
	if err != nil {
		return empty, ErrDormantRuleBundleAudit
	}
	if afterScan != nil && afterScan() != nil {
		return empty, ErrDormantRuleBundleAudit
	}
	second, err := scanDormantRuleScopeEntries(bounded, root)
	if err != nil || !sameDormantRuleScopes(first, second) {
		return empty, ErrDormantRuleBundleAudit
	}
	afterRecords, err := live.InspectInertRestoreRecords(bounded)
	rootAfter, statErr := root.Stat()
	atPath, pathErr := os.Lstat(rootPath)
	if err != nil || statErr != nil || pathErr != nil ||
		!reflect.DeepEqual(beforeRecords, afterRecords) ||
		!sameLeasedFile(rootBefore, rootAfter) ||
		!os.SameFile(rootAfter, atPath) ||
		verifySealedArchiveParent(rootPath) != nil || bounded.Err() != nil {
		return empty, ErrDormantRuleBundleAudit
	}
	report := DormantRuleBundleAudit{
		Scopes:               make([]DormantRuleScopeAudit, 0, len(first)),
		RequiresManualReview: len(first) != 0,
		// File contents and the ciphertext are NEVER authenticated here.
		RuleBytesVerified: false,
		RestoreSupported:  false,
		RestoreReady:      false,
	}
	for _, row := range beforeRecords {
		if row.Phase == storage.InertRestorePrepared {
			report.PreparedJournalCount++
		}
	}
	for _, observed := range first {
		report.Scopes = append(report.Scopes, DormantRuleScopeAudit{
			ScopeSHA256: shaHex([]byte(observed.name)),
			Phase: observed.phase, RuleFiles: len(observed.files),
			RuleBytes: observed.bytes,
		})
		if observed.phase == "pending" {
			report.PendingCount++
		} else {
			report.PublishedCount++
		}
	}
	return report, nil
}

type dormantRuleFileObservation struct {
	name string
	info os.FileInfo
}

type dormantRuleScopeObservation struct {
	name  string
	phase string
	info  os.FileInfo
	files []dormantRuleFileObservation
	bytes int64
}

// A fresh descriptor is essential: ReadDir retains offsets per open
// description, so reusing the root's flock FD would give a false empty scan.
func scanDormantRuleScopeEntries(ctx context.Context, root *os.File) ([]dormantRuleScopeObservation, error) {
	if ctx == nil || root == nil || ctx.Err() != nil {
		return nil, ErrDormantRuleBundleAudit
	}
	fd, err := unix.Openat(int(root.Fd()), ".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrDormantRuleBundleAudit
	}
	reader := os.NewFile(uintptr(fd), "dormant-root-readonly")
	if reader == nil {
		_ = unix.Close(fd)
		return nil, ErrDormantRuleBundleAudit
	}
	defer reader.Close()
	entries, err := reader.ReadDir(MaxDormantRuleAuditScopes + 1)
	if (err != nil && !errors.Is(err, io.EOF)) ||
		len(entries) > MaxDormantRuleAuditScopes {
		return nil, ErrDormantRuleBundleAudit
	}
	out := make([]dormantRuleScopeObservation, 0, len(entries))
	for _, entry := range entries {
		phase, ok := dormantRuleScopePhase(entry.Name())
		if !ok || !entry.IsDir() || ctx.Err() != nil {
			return nil, ErrDormantRuleBundleAudit
		}
		observed, err := inspectDormantRuleScopeShape(ctx, root, entry.Name(), phase)
		if err != nil {
			return nil, ErrDormantRuleBundleAudit
		}
		out = append(out, observed)
	}
	return out, nil
}

func dormantRuleScopePhase(name string) (string, bool) {
	if strings.HasPrefix(name, dormantRuleBundlePrefix) &&
		validLowerSHA(strings.TrimPrefix(name, dormantRuleBundlePrefix)) {
		return "published_untrusted", true
	}
	if !strings.HasPrefix(name, dormantRulePendingPrefix) {
		return "", false
	}
	suffix := strings.TrimPrefix(name, dormantRulePendingPrefix)
	if len(suffix) < 6 || len(suffix) > 32 {
		return "", false
	}
	for _, c := range suffix {
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') &&
			(c < 'A' || c > 'Z') {
			return "", false
		}
	}
	return "pending", true
}

func inspectDormantRuleScopeShape(
	ctx context.Context, root *os.File, name, phase string,
) (dormantRuleScopeObservation, error) {
	var empty dormantRuleScopeObservation
	fd, err := unix.Openat(int(root.Fd()), name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, ErrDormantRuleBundleAudit
	}
	dir := os.NewFile(uintptr(fd), "dormant-scope-readonly")
	if dir == nil {
		_ = unix.Close(fd)
		return empty, ErrDormantRuleBundleAudit
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil || !privatePortableDirectory(info) ||
		verifyDormantRuleScope(root, name, dir, info) != nil {
		return empty, ErrDormantRuleBundleAudit
	}
	entries, err := dir.ReadDir(MaxClosureRuleSets + 1)
	if (err != nil && !errors.Is(err, io.EOF)) ||
		len(entries) > MaxClosureRuleSets ||
		(phase == "published_untrusted" && len(entries) == 0) {
		return empty, ErrDormantRuleBundleAudit
	}
	found := dormantRuleScopeObservation{
		name: name, phase: phase, info: info,
		files: make([]dormantRuleFileObservation, 0, len(entries)),
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || ctx.Err() != nil {
			return empty, ErrDormantRuleBundleAudit
		}
		leaf := entry.Name()
		validName := len(leaf) > 5 &&
			(validLowerSHA(strings.TrimSuffix(leaf, ".json")) && strings.HasSuffix(leaf, ".json") ||
				validLowerSHA(strings.TrimSuffix(leaf, ".srs")) && strings.HasSuffix(leaf, ".srs"))
		if !validName {
			return empty, ErrDormantRuleBundleAudit
		}
		var atPath unix.Stat_t
		if unix.Fstatat(int(dir.Fd()), leaf, &atPath, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			atPath.Mode&unix.S_IFMT != unix.S_IFREG ||
			int(atPath.Uid) != os.Getuid() || atPath.Nlink != 1 ||
			(phase == "published_untrusted" && atPath.Mode&0o777 != 0o400) ||
			(phase == "pending" && atPath.Mode&0o777 != 0o400 &&
				atPath.Mode&0o777 != 0o600) ||
			atPath.Size < 0 || atPath.Size > MaxClosureRuleBytes ||
			found.bytes > MaxClosureRuleBytes-atPath.Size {
			return empty, ErrDormantRuleBundleAudit
		}
		ruleFD, openErr := unix.Openat(int(dir.Fd()), leaf,
			unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return empty, ErrDormantRuleBundleAudit
		}
		file := os.NewFile(uintptr(ruleFD), "dormant-rule-readonly")
		if file == nil {
			_ = unix.Close(ruleFD)
			return empty, ErrDormantRuleBundleAudit
		}
		fileInfo, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil ||
			!validTargetRuleInfo(fileInfo, atPath, atPath.Size) {
			return empty, ErrDormantRuleBundleAudit
		}
		found.bytes += atPath.Size
		found.files = append(found.files, dormantRuleFileObservation{name: leaf, info: fileInfo})
	}
	after, err := dir.Stat()
	if err != nil || !sameLeasedFile(info, after) ||
		verifyDormantRuleScope(root, name, dir, info) != nil {
		return empty, ErrDormantRuleBundleAudit
	}
	return found, nil
}

func sameDormantRuleScopes(a, b []dormantRuleScopeObservation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].name != b[i].name || a[i].phase != b[i].phase ||
			a[i].bytes != b[i].bytes || !sameLeasedFile(a[i].info, b[i].info) ||
			len(a[i].files) != len(b[i].files) {
			return false
		}
		for j := range a[i].files {
			if a[i].files[j].name != b[i].files[j].name ||
				!sameLeasedFile(a[i].files[j].info, b[i].files[j].info) {
				return false
			}
		}
	}
	return true
}

// Enforce Linux UID and link-count checks on every entry. Stateless reports
// must never be confused with an inode pin held beyond this function.
var _ = syscall.Stat_t{}
