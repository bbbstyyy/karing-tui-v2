//go:build linux

package backupclosure

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	reclaimPlanFileName = ".ktui-reclaim-plan-v1"
	reclaimIntentPrefix = ".ktui-reclaim-intent-v1-"
	reclaimPlanVersion  = "karing-tui-v2-inert-reclaim-plan-v1"
	maxReclaimPlanBytes = 96 << 10
)

var ErrDurableRuleReclaim = errors.New("durable inactive rule reclamation refused")

// DurableRuleReclaimProgress is NEVER a restore permit. UnlinkedBytes is the
// sum of file lengths absent under authenticated durable per-file intents,
// not a promise that the filesystem has already released those disk blocks.
type DurableRuleReclaimProgress struct {
	ArchiveSHA256        string
	InventorySHA256      string
	PlanSHA256           string
	ExpectedRules        int
	UnlinkedRules        int
	UnlinkedBytes        int64
	PreparedIntents      int
	AllRulesUnlinked     bool
	RequiresRevalidation bool
	RestoreSupported     bool
	RestoreReady         bool
}

type DurableRuleUnlinkResult struct {
	PlanSHA256           string
	RuleSHA256           string
	RuleBytes            int64
	RuleUnlinked         bool
	RequiresRevalidation bool
	RestoreSupported     bool
	RestoreReady         bool
}

type reclaimPlannedRule struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type reclaimPlanBody struct {
	Version         string               `json:"version"`
	ArchiveSHA256   string               `json:"archive_sha256"`
	InventorySHA256 string               `json:"inventory_sha256"`
	JournalID       int64                `json:"journal_id"`
	DirectoryDevice uint64               `json:"directory_device"`
	DirectoryInode  uint64               `json:"directory_inode"`
	Rules           []reclaimPlannedRule `json:"rules"`
}

type reclaimSignedPlan struct {
	Body reclaimPlanBody `json:"body"`
	MAC  string          `json:"mac"`
}

type reclaimRuleScope struct {
	root      *os.File
	dir       *os.File
	path      string
	name      string
	rootInfo  os.FileInfo
	dirInfo   os.FileInfo
	receipt   SealedArchiveReceipt
	inventory Inventory
}

func (p *reclaimRuleScope) close() {
	if p == nil {
		return
	}
	if p.dir != nil {
		_ = p.dir.Close()
	}
	if p.root != nil {
		_ = p.root.Close()
	}
}

// PrepareDurableRuleReclaim creates one exact, HMAC-authenticated immutable
// manifest of every still-present rule and its inode, then fsyncs the file and
// directory before returning. It does NOT unlink anything. A crash leaving
// a partial plan is refused, never silently replaced or pruned.
func (l *InertRestoreResourceLease) PrepareDurableRuleReclaim(
	ctx context.Context, key [32]byte,
) (DurableRuleReclaimProgress, error) {
	var zero DurableRuleReclaimProgress
	if ctx == nil || l == nil || key == ([32]byte{}) {
		return zero, ErrDurableRuleReclaim
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	p, err := openReclaimRuleScope(bounded, l, key)
	if err != nil {
		return zero, ErrDurableRuleReclaim
	}
	defer p.close()
	if err := verifyReclaimRoot(bounded, p); err != nil {
		return zero, ErrDurableRuleReclaim
	}
	// An existing plan (even malformed or a symlink) can NEVER be overwritten.
	var existing unix.Stat_t
	if err := unix.Fstatat(int(p.dir.Fd()), reclaimPlanFileName,
		&existing, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return zero, ErrDurableRuleReclaim
	}
	observed, err := inspectCompleteReclaimRules(bounded, p)
	if err != nil {
		return zero, ErrDurableRuleReclaim
	}
	plan, err := createReclaimPlan(bounded, p, l.record.ID, observed, key)
	if err != nil || l.revalidateLocked(bounded, key) != nil ||
		verifyReclaimRoot(bounded, p) != nil ||
		inspectCompleteReclaimRulesEqual(bounded, p, observed) != nil {
		return zero, ErrDurableRuleReclaim
	}
	payload, err := json.Marshal(plan)
	if err != nil || len(payload) > maxReclaimPlanBytes {
		return zero, ErrDurableRuleReclaim
	}
	if err := publishPrivateReclaimMarker(bounded, p.dir, reclaimPlanFileName, payload); err != nil {
		return zero, ErrDurableRuleReclaim
	}
	// From here errors are uncertain journal commits, not an invitation to
	// retry creation or to delete a partially-published journal.
	if p.dir.Sync() != nil || p.root.Sync() != nil {
		return zero, ErrDurableRuleReclaim
	}
	checked, data, err := readReclaimPlan(bounded, p, l, key)
	if err != nil || !sameReclaimPlan(plan, checked) || string(data) != string(payload) ||
		verifyReclaimRoot(bounded, p) != nil || l.revalidateLocked(bounded, key) != nil {
		return zero, ErrDurableRuleReclaim
	}
	state, err := inspectReclaimRuleState(bounded, p, checked, key)
	if err != nil || state.unlinked != 0 || state.prepared != 0 {
		return zero, ErrDurableRuleReclaim
	}
	return reclaimProgress(p, checked, data, state), nil
}

// InspectDurableRuleReclaim resumes only via an explicit new ciphertext lease,
// secret key and still-pending journal. It accepts a missing leaf ONLY if a
// separately fsynced, authenticated per-file intent was already published.
func (l *InertRestoreResourceLease) InspectDurableRuleReclaim(
	ctx context.Context, key [32]byte,
) (DurableRuleReclaimProgress, error) {
	var zero DurableRuleReclaimProgress
	if ctx == nil || l == nil || key == ([32]byte{}) {
		return zero, ErrDurableRuleReclaim
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	p, err := openReclaimRuleScope(bounded, l, key)
	if err != nil {
		return zero, ErrDurableRuleReclaim
	}
	defer p.close()
	plan, payload, err := readReclaimPlan(bounded, p, l, key)
	if err != nil {
		return zero, ErrDurableRuleReclaim
	}
	before, err := inspectReclaimRuleState(bounded, p, plan, key)
	if err != nil || verifyReclaimRoot(bounded, p) != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return zero, ErrDurableRuleReclaim
	}
	after, err := inspectReclaimRuleState(bounded, p, plan, key)
	if err != nil || !sameReclaimState(before, after) ||
		verifyReclaimRoot(bounded, p) != nil {
		return zero, ErrDurableRuleReclaim
	}
	return reclaimProgress(p, plan, payload, after), nil
}

// UnlinkNextDurableReclaimRule is an explicit one-leaf transaction. Before
// unlinkat, it publishes/fsyncs a separate HMAC intent for that exact leaf.
// SIGKILL before unlink leaves the leaf and intent; SIGKILL after unlink leaves
// an absent leaf with its durable intent. No broad GC, RemoveAll or implicit
// background retry exists. The reclaim directory/manifest remain on disk.
func (l *InertRestoreResourceLease) UnlinkNextDurableReclaimRule(
	ctx context.Context, key [32]byte, expected DurableRuleReclaimProgress,
) (DurableRuleUnlinkResult, error) {
	return l.unlinkNextDurableReclaimRule(ctx, key, expected, nil, nil)
}

// Fault hooks are internal deterministic crash seams only.
func (l *InertRestoreResourceLease) unlinkNextDurableReclaimRule(
	ctx context.Context, key [32]byte, expected DurableRuleReclaimProgress,
	beforeUnlink, afterUnlink func() error,
) (DurableRuleUnlinkResult, error) {
	var zero DurableRuleUnlinkResult
	if ctx == nil || l == nil || key == ([32]byte{}) ||
		!validLowerSHA(expected.ArchiveSHA256) ||
		!validLowerSHA(expected.InventorySHA256) ||
		!validLowerSHA(expected.PlanSHA256) ||
		!expected.RequiresRevalidation || expected.RestoreReady ||
		expected.RestoreSupported || expected.ExpectedRules <= 0 ||
		expected.ExpectedRules > MaxClosureRuleSets {
		return zero, ErrDurableRuleReclaim
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	p, err := openReclaimRuleScope(bounded, l, key)
	if err != nil {
		return zero, ErrDurableRuleReclaim
	}
	defer p.close()
	plan, payload, err := readReclaimPlan(bounded, p, l, key)
	if err != nil || expected.ArchiveSHA256 != p.receipt.ArchiveSHA256 ||
		expected.InventorySHA256 != p.receipt.InventorySHA256 ||
		expected.PlanSHA256 != shaHex(payload) ||
		expected.ExpectedRules != len(plan.Body.Rules) {
		return zero, ErrDurableRuleReclaim
	}
	state, err := inspectReclaimRuleState(bounded, p, plan, key)
	if err != nil || expected.UnlinkedRules != state.unlinked ||
		expected.UnlinkedBytes != state.bytes ||
		expected.PreparedIntents != state.prepared ||
		expected.AllRulesUnlinked || state.unlinked == len(plan.Body.Rules) {
		return zero, ErrDurableRuleReclaim
	}
	if verifyReclaimRoot(bounded, p) != nil || l.revalidateLocked(bounded, key) != nil {
		return zero, ErrDurableRuleReclaim
	}
	index := -1
	for i, rule := range plan.Body.Rules {
		if _, found := state.present[rule.Name]; found {
			index = i
			if state.intents[i] {
				break
			} // resume prepared intent first
		}
	}
	if index == -1 {
		return zero, ErrDurableRuleReclaim
	}
	rule := plan.Body.Rules[index]
	markerName := reclaimIntentPrefix + fmt.Sprintf("%03d", index)
	if !state.intents[index] {
		message := reclaimIntentMAC(key, shaHex(payload), index, rule.Name)
		if err := publishPrivateReclaimMarker(bounded, p.dir, markerName, []byte(message)); err != nil ||
			p.dir.Sync() != nil {
			return zero, ErrDurableRuleReclaim
		}
	}
	// A freshly created marker may be durable even if later validation fails.
	// It is safe to retry explicitly; no unlink has yet been attempted.
	second, err := inspectReclaimRuleState(bounded, p, plan, key)
	if err != nil || !second.intents[index] ||
		!samePresentReclaimRules(state.present, second.present) ||
		verifyReclaimRoot(bounded, p) != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return zero, ErrDurableRuleReclaim
	}
	if beforeUnlink != nil && beforeUnlink() != nil {
		return zero, ErrDurableRuleReclaim
	}
	third, err := inspectReclaimRuleState(bounded, p, plan, key)
	if err != nil || !sameReclaimState(second, third) ||
		l.revalidateLocked(bounded, key) != nil ||
		verifyReclaimRoot(bounded, p) != nil || bounded.Err() != nil {
		return zero, ErrDurableRuleReclaim
	}
	// This never unlinks an entry merely because its name matches. Reopen
	// with O_NOFOLLOW and reconfirm the original signed dev/inode and digest.
	digest := reclaimDigestForName(p.inventory.RuleSets, rule.Name)
	ob, err := inspectTargetRule(bounded, p.dir, digest)
	if err != nil || !ob.exists || !sameReclaimInode(ob.info, rule) ||
		!os.SameFile(ob.info, third.present[rule.Name]) {
		return zero, ErrDurableRuleReclaim
	}
	if unix.Unlinkat(int(p.dir.Fd()), rule.Name, 0) != nil {
		return zero, ErrDurableRuleReclaim
	}
	// After unlink, no rollback is possible. The fsynced per-file marker
	// authorizes either remaining or missing bytes after crash, never unknown
	// replacements. Error results make no false durability guarantees.
	if afterUnlink != nil && afterUnlink() != nil {
		return zero, ErrDurableRuleReclaim
	}
	if p.dir.Sync() != nil || l.revalidateLocked(bounded, key) != nil ||
		verifyReclaimRoot(bounded, p) != nil {
		return zero, ErrDurableRuleReclaim
	}
	fourth, err := inspectReclaimRuleState(bounded, p, plan, key)
	if err != nil || fourth.unlinked != third.unlinked+1 ||
		fourth.bytes != third.bytes+rule.Size || bounded.Err() != nil {
		return zero, ErrDurableRuleReclaim
	}
	return DurableRuleUnlinkResult{
		PlanSHA256: shaHex(payload), RuleSHA256: rule.SHA256,
		RuleBytes: rule.Size, RuleUnlinked: true,
		RequiresRevalidation: true, RestoreSupported: false, RestoreReady: false,
	}, nil
}

// openReclaimRuleScope derives its only target from the authoritative state
// database; no caller-supplied directory or leaf can reach the unlink API.
// The caller holds the journal-bound ciphertext lease mutex, and the parent
// candidate's flock remains active throughout this method's lifetime.
func openReclaimRuleScope(ctx context.Context, l *InertRestoreResourceLease, key [32]byte) (_ *reclaimRuleScope, err error) {
	if ctx == nil || l == nil || l.live == nil || l.candidate == nil ||
		l.revalidateLocked(ctx, key) != nil {
		return nil, ErrDurableRuleReclaim
	}
	db := l.live.Path()
	if !filepath.IsAbs(db) || filepath.Clean(db) != db {
		return nil, ErrDurableRuleReclaim
	}
	path := filepath.Join(filepath.Dir(db), dormantRuleRootName)
	if !validPortablePreviewRoot(path) ||
		path == l.candidate.parent || path == l.candidate.directory ||
		strings.HasPrefix(path, l.candidate.parent+string(os.PathSeparator)) ||
		strings.HasPrefix(l.candidate.parent, path+string(os.PathSeparator)) {
		return nil, ErrDurableRuleReclaim
	}
	receipt := SealedArchiveReceipt{
		ArchiveSHA256:   l.record.ArchiveSHA256,
		InventorySHA256: l.record.InventorySHA256,
		Bytes:           l.record.ArchiveBytes,
		Format:          l.candidate.receipt.Format,
	}
	inv, err := readAuthenticatedInventory(ctx, l.candidate.archive, key, receipt)
	if err != nil || !validLowerSHA(receipt.ArchiveSHA256) ||
		len(inv.RuleSets) == 0 || len(inv.RuleSets) > MaxClosureRuleSets {
		return nil, ErrDurableRuleReclaim
	}
	var total int64
	for _, rule := range inv.RuleSets {
		if rule.Size <= 0 || rule.Size > MaxClosureRuleBytes ||
			total > MaxClosureRuleBytes-rule.Size {
			return nil, ErrDurableRuleReclaim
		}
		total += rule.Size
	}
	p := &reclaimRuleScope{
		path: path, name: dormantRuleReclaimPrefix + receipt.ArchiveSHA256,
		receipt: receipt, inventory: inv,
	}
	defer func() {
		if err != nil {
			p.close()
		}
	}()
	p.root, err = lockSealedArchiveParent(ctx, path)
	if err != nil {
		return nil, ErrDurableRuleReclaim
	}
	p.rootInfo, err = p.root.Stat()
	if err != nil || !privatePortableDirectory(p.rootInfo) {
		return nil, ErrDurableRuleReclaim
	}
	fd, openErr := unix.Openat(int(p.root.Fd()), p.name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if openErr != nil {
		return nil, ErrDurableRuleReclaim
	}
	p.dir = os.NewFile(uintptr(fd), "inert-durable-reclaim")
	if p.dir == nil {
		_ = unix.Close(fd)
		return nil, ErrDurableRuleReclaim
	}
	p.dirInfo, err = p.dir.Stat()
	if err != nil || !privatePortableDirectory(p.dirInfo) ||
		verifyDormantRuleScope(p.root, p.name, p.dir, p.dirInfo) != nil ||
		verifyReclaimRoot(ctx, p) != nil {
		return nil, ErrDurableRuleReclaim
	}
	return p, nil
}

func verifyReclaimRoot(ctx context.Context, p *reclaimRuleScope) error {
	if ctx == nil || p == nil || ctx.Err() != nil ||
		verifyRetiredRuleParent(p.path, p.root, p.rootInfo, false) != nil ||
		verifyDormantRuleScope(p.root, p.name, p.dir, p.dirInfo) != nil {
		return ErrDurableRuleReclaim
	}
	fd, err := unix.Openat(int(p.root.Fd()), ".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrDurableRuleReclaim
	}
	reader := os.NewFile(uintptr(fd), "inert-reclaim-root-scan")
	if reader == nil {
		_ = unix.Close(fd)
		return ErrDurableRuleReclaim
	}
	defer reader.Close()
	entries, err := reader.ReadDir(MaxDormantRuleBundles + 1)
	if (err != nil && !errors.Is(err, io.EOF)) ||
		len(entries) > MaxDormantRuleBundles {
		return ErrDurableRuleReclaim
	}
	found := 0
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() {
			return ErrDurableRuleReclaim
		}
		switch {
		case name == p.name:
			found++
		case strings.HasPrefix(name, dormantRuleBundlePrefix) &&
			validLowerSHA(strings.TrimPrefix(name, dormantRuleBundlePrefix)):
			if _, err := inspectDormantRuleScopeShape(ctx, p.root, name, "published_untrusted"); err != nil {
				return ErrDurableRuleReclaim
			}
		case strings.HasPrefix(name, dormantRuleRetiredPrefix) &&
			validLowerSHA(strings.TrimPrefix(name, dormantRuleRetiredPrefix)):
			if _, err := inspectDormantRuleScopeShape(ctx, p.root, name, "published_untrusted"); err != nil {
				return ErrDurableRuleReclaim
			}
		default:
			return ErrDurableRuleReclaim
		}
	}
	if found != 1 || ctx.Err() != nil {
		return ErrDurableRuleReclaim
	}
	return nil
}

func inspectCompleteReclaimRules(ctx context.Context, p *reclaimRuleScope) (map[string]os.FileInfo, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrDurableRuleReclaim
	}
	fd, err := unix.Openat(int(p.root.Fd()), p.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrDurableRuleReclaim
	}
	reader := os.NewFile(uintptr(fd), "inert-complete-rule-scanner")
	if reader == nil {
		_ = unix.Close(fd)
		return nil, ErrDurableRuleReclaim
	}
	defer reader.Close()
	entries, err := reader.ReadDir(MaxClosureRuleSets + 1)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) != len(p.inventory.RuleSets) {
		return nil, ErrDurableRuleReclaim
	}
	result := make(map[string]os.FileInfo, len(entries))
	for _, rule := range p.inventory.RuleSets {
		leaf := strings.TrimPrefix(rule.RelativePath, "rule-sets/sha256/")
		if leaf == rule.RelativePath {
			return nil, ErrDurableRuleReclaim
		}
		ob, err := inspectTargetRule(ctx, p.dir, rule)
		if err != nil || !ob.exists || ob.info.Mode().Perm() != 0o400 || result[leaf] != nil {
			return nil, ErrDurableRuleReclaim
		}
		result[leaf] = ob.info
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || result[entry.Name()] == nil {
			return nil, ErrDurableRuleReclaim
		}
	}
	if verifyDormantRulePayload(ctx, p.root, p.name, p.dir, p.dirInfo, p.inventory.RuleSets, result) != nil {
		return nil, ErrDurableRuleReclaim
	}
	return result, nil
}

func inspectCompleteReclaimRulesEqual(ctx context.Context, p *reclaimRuleScope, expected map[string]os.FileInfo) error {
	got, err := inspectCompleteReclaimRules(ctx, p)
	if err != nil || len(got) != len(expected) {
		return ErrDurableRuleReclaim
	}
	for name, info := range expected {
		if !sameReclaimFileInfo(info, got[name]) {
			return ErrDurableRuleReclaim
		}
	}
	return nil
}

func createReclaimPlan(ctx context.Context, p *reclaimRuleScope, id int64, observed map[string]os.FileInfo, key [32]byte) (reclaimSignedPlan, error) {
	var zero reclaimSignedPlan
	st, ok := p.dirInfo.Sys().(*syscall.Stat_t)
	if !ok || id <= 0 {
		return zero, ErrDurableRuleReclaim
	}
	body := reclaimPlanBody{
		Version: reclaimPlanVersion, ArchiveSHA256: p.receipt.ArchiveSHA256,
		InventorySHA256: p.receipt.InventorySHA256, JournalID: id,
		DirectoryDevice: st.Dev, DirectoryInode: st.Ino,
	}
	for _, rule := range p.inventory.RuleSets {
		leaf := strings.TrimPrefix(rule.RelativePath, "rule-sets/sha256/")
		info := observed[leaf]
		if info == nil || info.Size() != rule.Size {
			return zero, ErrDurableRuleReclaim
		}
		meta, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return zero, ErrDurableRuleReclaim
		}
		body.Rules = append(body.Rules, reclaimPlannedRule{
			Name: leaf, SHA256: rule.SHA256, Size: rule.Size, Device: meta.Dev, Inode: meta.Ino,
		})
	}
	sort.Slice(body.Rules, func(i, j int) bool { return body.Rules[i].Name < body.Rules[j].Name })
	mac, err := reclaimPlanMAC(body, key)
	if err != nil {
		return zero, ErrDurableRuleReclaim
	}
	return reclaimSignedPlan{Body: body, MAC: mac}, nil
}

func reclaimPlanMAC(body reclaimPlanBody, key [32]byte) (string, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("karing-tui-v2/durable-rule-reclaim/plan-v1\x00"))
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func sameReclaimPlan(a, b reclaimSignedPlan) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	return err == nil && string(x) == string(y)
}

func readReclaimPlan(ctx context.Context, p *reclaimRuleScope, l *InertRestoreResourceLease, key [32]byte) (reclaimSignedPlan, []byte, error) {
	var zero reclaimSignedPlan
	data, _, err := readPrivateReclaimFile(ctx, p.dir, reclaimPlanFileName, maxReclaimPlanBytes)
	if err != nil {
		return zero, nil, ErrDurableRuleReclaim
	}
	var plan reclaimSignedPlan
	if json.Unmarshal(data, &plan) != nil ||
		plan.Body.Version != reclaimPlanVersion ||
		plan.Body.ArchiveSHA256 != p.receipt.ArchiveSHA256 ||
		plan.Body.InventorySHA256 != p.receipt.InventorySHA256 ||
		plan.Body.JournalID != l.record.ID ||
		len(plan.Body.Rules) != len(p.inventory.RuleSets) ||
		len(plan.Body.Rules) == 0 {
		return zero, nil, ErrDurableRuleReclaim
	}
	meta, ok := p.dirInfo.Sys().(*syscall.Stat_t)
	if !ok || plan.Body.DirectoryDevice != meta.Dev ||
		plan.Body.DirectoryInode != meta.Ino {
		return zero, nil, ErrDurableRuleReclaim
	}
	expected, err := reclaimPlanMAC(plan.Body, key)
	a, decodeErr := hex.DecodeString(plan.MAC)
	b, _ := hex.DecodeString(expected)
	if err != nil || decodeErr != nil || len(a) != sha256.Size || !hmac.Equal(a, b) {
		return zero, nil, ErrDurableRuleReclaim
	}
	byName := make(map[string]RuleDigest, len(p.inventory.RuleSets))
	for _, r := range p.inventory.RuleSets {
		leaf := strings.TrimPrefix(r.RelativePath, "rule-sets/sha256/")
		if leaf == r.RelativePath || byName[leaf].RelativePath != "" {
			return zero, nil, ErrDurableRuleReclaim
		}
		byName[leaf] = r
	}
	for i, r := range plan.Body.Rules {
		inv, ok := byName[r.Name]
		if !ok || r.SHA256 != inv.SHA256 || r.Size != inv.Size ||
			r.Device == 0 || r.Inode == 0 ||
			(i > 0 && plan.Body.Rules[i-1].Name >= r.Name) {
			return zero, nil, ErrDurableRuleReclaim
		}
	}
	canonical, err := json.Marshal(plan)
	if err != nil || string(canonical) != string(data) {
		return zero, nil, ErrDurableRuleReclaim
	}
	return plan, data, nil
}

func publishPrivateReclaimMarker(ctx context.Context, dir *os.File, name string, payload []byte) error {
	if ctx == nil || ctx.Err() != nil || dir == nil || filepath.Base(name) != name ||
		len(payload) == 0 || len(payload) > maxReclaimPlanBytes {
		return ErrDurableRuleReclaim
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return ErrDurableRuleReclaim
	}
	file := os.NewFile(uintptr(fd), "reclaim-durable-marker")
	if file == nil {
		_ = unix.Close(fd)
		return ErrDurableRuleReclaim
	}
	n, writeErr := file.Write(payload)
	modeErr := file.Chmod(0o400)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || n != len(payload) || modeErr != nil || syncErr != nil || closeErr != nil || ctx.Err() != nil {
		return ErrDurableRuleReclaim
	}
	return nil
}

func readPrivateReclaimFile(ctx context.Context, dir *os.File, name string, max int) ([]byte, os.FileInfo, error) {
	if ctx == nil || ctx.Err() != nil || dir == nil || filepath.Base(name) != name {
		return nil, nil, ErrDurableRuleReclaim
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, ErrDurableRuleReclaim
	}
	file := os.NewFile(uintptr(fd), "reclaim-private-reader")
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, ErrDurableRuleReclaim
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 ||
		info.Size() <= 0 || info.Size() > int64(max) {
		return nil, nil, ErrDurableRuleReclaim
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return nil, nil, ErrDurableRuleReclaim
	}
	var atPath unix.Stat_t
	if unix.Fstatat(int(dir.Fd()), name, &atPath, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		atPath.Ino != stat.Ino || uint64(atPath.Dev) != stat.Dev ||
		atPath.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, nil, ErrDurableRuleReclaim
	}
	data, err := io.ReadAll(io.LimitReader(sealedContextReader{ctx: ctx, src: file}, int64(max)+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || len(data) != int(info.Size()) ||
		!sameLeasedFile(info, after) || ctx.Err() != nil {
		return nil, nil, ErrDurableRuleReclaim
	}
	return data, info, nil
}

type reclaimState struct {
	present  map[string]os.FileInfo
	intents  map[int]bool
	prepared int
	unlinked int
	bytes    int64
}

func inspectReclaimRuleState(ctx context.Context, p *reclaimRuleScope, plan reclaimSignedPlan, key [32]byte) (reclaimState, error) {
	var zero reclaimState
	if ctx == nil || p == nil || ctx.Err() != nil {
		return zero, ErrDurableRuleReclaim
	}
	fd, err := unix.Openat(int(p.root.Fd()), p.name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, ErrDurableRuleReclaim
	}
	reader := os.NewFile(uintptr(fd), "reclaim-state-scan")
	if reader == nil {
		_ = unix.Close(fd)
		return zero, ErrDurableRuleReclaim
	}
	defer reader.Close()
	info, err := reader.Stat()
	if err != nil || !os.SameFile(p.dirInfo, info) || !privatePortableDirectory(info) {
		return zero, ErrDurableRuleReclaim
	}
	entries, err := reader.ReadDir(2*MaxClosureRuleSets + 2)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > 2*MaxClosureRuleSets+1 {
		return zero, ErrDurableRuleReclaim
	}
	state := reclaimState{present: map[string]os.FileInfo{}, intents: map[int]bool{}}
	byName := map[string]int{}
	for i, r := range plan.Body.Rules {
		byName[r.Name] = i
	}
	planSeen := 0
	planDigestBytes, _ := json.Marshal(plan)
	planDigest := shaHex(planDigestBytes)
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return zero, ErrDurableRuleReclaim
		}
		name := entry.Name()
		switch {
		case name == reclaimPlanFileName:
			planSeen++
			d, _, err := readPrivateReclaimFile(ctx, p.dir, name, maxReclaimPlanBytes)
			if err != nil || string(d) != string(planDigestBytes) {
				return zero, ErrDurableRuleReclaim
			}
		case strings.HasPrefix(name, reclaimIntentPrefix):
			indexText := strings.TrimPrefix(name, reclaimIntentPrefix)
			index, err := strconv.Atoi(indexText)
			if err != nil || index < 0 || index >= len(plan.Body.Rules) ||
				name != reclaimIntentPrefix+fmt.Sprintf("%03d", index) ||
				state.intents[index] {
				return zero, ErrDurableRuleReclaim
			}
			payload, _, err := readPrivateReclaimFile(ctx, p.dir, name, 128)
			expected := reclaimIntentMAC(key, planDigest, index, plan.Body.Rules[index].Name)
			raw, decodeErr := hex.DecodeString(string(payload))
			want, _ := hex.DecodeString(expected)
			if err != nil || decodeErr != nil || len(raw) != sha256.Size || !hmac.Equal(raw, want) {
				return zero, ErrDurableRuleReclaim
			}
			state.intents[index] = true
			state.prepared++
		default:
			index, ok := byName[name]
			if !ok || state.present[name] != nil {
				return zero, ErrDurableRuleReclaim
			}
			rule := reclaimDigestForName(p.inventory.RuleSets, name)
			if rule.RelativePath == "" {
				return zero, ErrDurableRuleReclaim
			}
			ob, err := inspectTargetRule(ctx, p.dir, rule)
			if err != nil || !ob.exists || ob.info.Mode().Perm() != 0o400 ||
				!sameReclaimInode(ob.info, plan.Body.Rules[index]) {
				return zero, ErrDurableRuleReclaim
			}
			state.present[name] = ob.info
		}
	}
	if planSeen != 1 || len(entries) != 1+state.prepared+len(state.present) {
		return zero, ErrDurableRuleReclaim
	}
	for i, r := range plan.Body.Rules {
		if state.present[r.Name] == nil {
			if !state.intents[i] {
				return zero, ErrDurableRuleReclaim
			}
			state.unlinked++
			state.bytes += r.Size
		}
	}
	if verifyDormantRuleScope(p.root, p.name, p.dir, p.dirInfo) != nil || ctx.Err() != nil {
		return zero, ErrDurableRuleReclaim
	}
	return state, nil
}

func reclaimDigestForName(rules []RuleDigest, name string) RuleDigest {
	for _, r := range rules {
		if strings.TrimPrefix(r.RelativePath, "rule-sets/sha256/") == name {
			return r
		}
	}
	return RuleDigest{}
}

func sameReclaimInode(info os.FileInfo, want reclaimPlannedRule) bool {
	if info == nil || info.Size() != want.Size || info.Mode().Perm() != 0o400 {
		return false
	}
	meta, ok := info.Sys().(*syscall.Stat_t)
	return ok && meta.Dev == want.Device && meta.Ino == want.Inode
}

func sameReclaimFileInfo(a, b os.FileInfo) bool {
	return a != nil && b != nil && sameLeasedFile(a, b)
}

func samePresentReclaimRules(a, b map[string]os.FileInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for name, info := range a {
		if !sameReclaimFileInfo(info, b[name]) {
			return false
		}
	}
	return true
}

func sameReclaimState(a, b reclaimState) bool {
	if a.prepared != b.prepared || a.unlinked != b.unlinked || a.bytes != b.bytes ||
		len(a.intents) != len(b.intents) || !samePresentReclaimRules(a.present, b.present) {
		return false
	}
	for i := range a.intents {
		if !b.intents[i] {
			return false
		}
	}
	return true
}

func reclaimIntentMAC(key [32]byte, planSHA string, index int, name string) string {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("karing-tui-v2/durable-rule-reclaim/leaf-v1\x00"))
	_, _ = mac.Write([]byte(fmt.Sprintf("%s/%03d/%s", planSHA, index, name)))
	return hex.EncodeToString(mac.Sum(nil))
}

func reclaimProgress(p *reclaimRuleScope, plan reclaimSignedPlan, payload []byte, state reclaimState) DurableRuleReclaimProgress {
	return DurableRuleReclaimProgress{
		ArchiveSHA256:   p.receipt.ArchiveSHA256,
		InventorySHA256: p.receipt.InventorySHA256,
		PlanSHA256:      shaHex(payload),
		ExpectedRules:   len(plan.Body.Rules),
		UnlinkedRules:   state.unlinked, UnlinkedBytes: state.bytes,
		PreparedIntents:      state.prepared,
		AllRulesUnlinked:     state.unlinked == len(plan.Body.Rules),
		RequiresRevalidation: true, RestoreSupported: false, RestoreReady: false,
	}
}
