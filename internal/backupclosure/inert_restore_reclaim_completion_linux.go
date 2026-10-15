//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	reclaimCompletionName = ".ktui-reclaim-complete-v1"
	reclaimCompletionVersion = "karing-tui-v2-inert-reclaim-complete-v1"
	maxReclaimCompletionBytes = 2048
)

var ErrCompletedRuleReclaim = errors.New("authenticated reclaim completion refused")

// CompletedRuleReclaimReceipt is a read-only, expiring observation, NOT an
// unlink, backup restore, active Core, or final directory-removal permit.
type CompletedRuleReclaimReceipt struct {
	ArchiveSHA256 string
	InventorySHA256 string
	PlanSHA256 string
	CompletionSHA256 string
	RuleCount int
	UnlinkedBytes int64
	CompletionSealed bool
	MetadataRetained bool
	RequiresRevalidation bool
	RestoreSupported bool
	RestoreReady bool
}

type reclaimCompletionBody struct {
	Version string `json:"version"`
	ArchiveSHA256 string `json:"archive_sha256"`
	InventorySHA256 string `json:"inventory_sha256"`
	PlanSHA256 string `json:"plan_sha256"`
	JournalID int64 `json:"journal_id"`
	DirectoryDevice uint64 `json:"directory_device"`
	DirectoryInode uint64 `json:"directory_inode"`
	RuleCount int `json:"rule_count"`
	UnlinkedBytes int64 `json:"unlinked_bytes"`
}

type reclaimSignedCompletion struct {
	Body reclaimCompletionBody `json:"body"`
	MAC string `json:"mac"`
}

// SealCompletedDurableReclaim commits a signed terminal state only after
// EVERY rule was durably authorized for deletion and none remains. The signed
// plan and all per-rule intents are RETAINED in the private scope. No unlink,
// rmdir, GC, journal update, live rule change or Core execution occurs.
func (l *InertRestoreResourceLease) SealCompletedDurableReclaim(
	ctx context.Context, key [32]byte, expected DurableRuleReclaimProgress,
) (CompletedRuleReclaimReceipt, error) {
	return l.sealCompletedDurableReclaim(ctx, key, expected, nil, nil)
}

// Package-private fault seams exercise a late live/entry race and SIGKILL
// between the completion marker's file fsync and directory fsync.
func (l *InertRestoreResourceLease) sealCompletedDurableReclaim(
	ctx context.Context, key [32]byte, expected DurableRuleReclaimProgress,
	beforeSeal, afterSeal func() error,
) (CompletedRuleReclaimReceipt, error) {
	var zero CompletedRuleReclaimReceipt
	if ctx == nil || l == nil || key == ([32]byte{}) ||
		!validLowerSHA(expected.ArchiveSHA256) ||
		!validLowerSHA(expected.InventorySHA256) ||
		!validLowerSHA(expected.PlanSHA256) ||
		!expected.AllRulesUnlinked || !expected.RequiresRevalidation ||
		expected.RestoreSupported || expected.RestoreReady ||
		expected.ExpectedRules <= 0 || expected.ExpectedRules > MaxClosureRuleSets ||
		expected.UnlinkedRules != expected.ExpectedRules ||
		expected.PreparedIntents != expected.ExpectedRules {
		return zero, ErrCompletedRuleReclaim
	}
	if err := ctx.Err(); err != nil { return zero, err }
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()

	p, err := openReclaimRuleScope(bounded, l, key)
	if err != nil { return zero, ErrCompletedRuleReclaim }
	defer p.close()
	plan, planBytes, err := readReclaimPlan(bounded, p, l, key)
	if err != nil { return zero, ErrCompletedRuleReclaim }
	first, err := inspectReclaimRuleState(bounded, p, plan, key)
	if err != nil || !completeReclaimRulesGone(first, plan) ||
		expected != reclaimProgress(p, plan, planBytes, first) ||
		verifyReclaimRoot(bounded, p) != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return zero, ErrCompletedRuleReclaim
	}
	var prior unix.Stat_t
	if statErr := unix.Fstatat(int(p.dir.Fd()), reclaimCompletionName,
		&prior, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(statErr, unix.ENOENT) {
		// Includes an existing authenticated completion, symlink or
		// interrupted/partial marker. Never overwrite or auto-repair.
		return zero, ErrCompletedRuleReclaim
	}
	payload, err := createReclaimCompletion(p, l.record.ID, plan, planBytes, key)
	if err != nil { return zero, ErrCompletedRuleReclaim }
	if beforeSeal != nil && beforeSeal() != nil { return zero, ErrCompletedRuleReclaim }
	second, err := inspectReclaimRuleState(bounded, p, plan, key)
	if err != nil || !sameReclaimState(first, second) ||
		!completeReclaimRulesGone(second, plan) ||
		verifyReclaimRoot(bounded, p) != nil ||
		l.revalidateLocked(bounded, key) != nil || bounded.Err() != nil {
		return zero, ErrCompletedRuleReclaim
	}
	if err := publishPrivateReclaimMarker(
		bounded, p.dir, reclaimCompletionName, payload); err != nil {
		return zero, ErrCompletedRuleReclaim
	}
	// From here errors indicate uncertain commit. No rollback or metadata
	// deletion. The marker might survive a crash, or be absent after power
	// failure until the directory fsync reaches stable storage.
	if afterSeal != nil && afterSeal() != nil { return zero, ErrCompletedRuleReclaim }
	if p.dir.Sync() != nil || p.root.Sync() != nil {
		return zero, ErrCompletedRuleReclaim
	}
	evidence, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, payload, key)
	if err != nil || verifyReclaimRoot(bounded, p) != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return zero, ErrCompletedRuleReclaim
	}
	again, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, payload, key)
	if err != nil || !sameSealedReclaimEvidence(evidence, again) ||
		verifyReclaimRoot(bounded, p) != nil || bounded.Err() != nil {
		return zero, ErrCompletedRuleReclaim
	}
	return completedReclaimReceipt(p, plan, planBytes, payload), nil
}

// InspectSealedDurableReclaim reopens the original journal-bound ciphertext,
// HMAC-checks the completion + complete original plan + every per-leaf signed
// intent, rejects any surviving rule or unknown entry and repeats scans/CAS.
// It is explicitly separate from ADR 0119's pre-completion inspector, which
// must continue FAILING CLOSED when it encounters the completion marker.
func (l *InertRestoreResourceLease) InspectSealedDurableReclaim(
	ctx context.Context, key [32]byte,
) (CompletedRuleReclaimReceipt, error) {
	var zero CompletedRuleReclaimReceipt
	if ctx == nil || l == nil || key == ([32]byte{}) { return zero, ErrCompletedRuleReclaim }
	if err := ctx.Err(); err != nil { return zero, err }
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	p, err := openReclaimRuleScope(bounded, l, key)
	if err != nil { return zero, ErrCompletedRuleReclaim }
	defer p.close()
	plan, planBytes, err := readReclaimPlan(bounded, p, l, key)
	if err != nil { return zero, ErrCompletedRuleReclaim }
	payload, err := createReclaimCompletion(p, l.record.ID, plan, planBytes, key)
	if err != nil { return zero, ErrCompletedRuleReclaim }
	first, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, payload, key)
	if err != nil || verifyReclaimRoot(bounded, p) != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return zero, ErrCompletedRuleReclaim
	}
	second, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, payload, key)
	if err != nil || !sameSealedReclaimEvidence(first, second) ||
		verifyReclaimRoot(bounded, p) != nil || bounded.Err() != nil {
		return zero, ErrCompletedRuleReclaim
	}
	return completedReclaimReceipt(p, plan, planBytes, payload), nil
}

func completeReclaimRulesGone(state reclaimState, plan reclaimSignedPlan) bool {
	n := len(plan.Body.Rules)
	if n == 0 || n > MaxClosureRuleSets ||
		state.unlinked != n || state.prepared != n ||
		len(state.intents) != n || len(state.present) != 0 { return false }
	var total int64
	for i, rule := range plan.Body.Rules {
		if !state.intents[i] || rule.Size <= 0 ||
			total > MaxClosureRuleBytes-rule.Size { return false }
		total += rule.Size
	}
	return state.bytes == total
}

func reclaimCompletionMAC(body reclaimCompletionBody, key [32]byte) (string,error) {
	raw, err := json.Marshal(body)
	if err != nil { return "", err }
	m := hmac.New(sha256.New, key[:])
	_, _ = m.Write([]byte("karing-tui-v2/durable-rule-reclaim/completion-v1\x00"))
	_, _ = m.Write(raw)
	return hex.EncodeToString(m.Sum(nil)), nil
}

func createReclaimCompletion(p *reclaimRuleScope, journalID int64,
	plan reclaimSignedPlan, planBytes []byte, key [32]byte) ([]byte,error) {
	if p == nil || journalID <= 0 || journalID != plan.Body.JournalID ||
		len(plan.Body.Rules) == 0 { return nil, ErrCompletedRuleReclaim }
	meta, ok := p.dirInfo.Sys().(*syscall.Stat_t)
	if !ok || meta.Dev != plan.Body.DirectoryDevice ||
		meta.Ino != plan.Body.DirectoryInode { return nil, ErrCompletedRuleReclaim }
	var total int64
	for _, r := range plan.Body.Rules {
		if r.Size <= 0 || total > MaxClosureRuleBytes-r.Size { return nil, ErrCompletedRuleReclaim }
		total += r.Size
	}
	body := reclaimCompletionBody{
		Version: reclaimCompletionVersion,
		ArchiveSHA256: p.receipt.ArchiveSHA256,
		InventorySHA256: p.receipt.InventorySHA256,
		PlanSHA256: shaHex(planBytes),
		JournalID: journalID,
		DirectoryDevice: meta.Dev,
		DirectoryInode: meta.Ino,
		RuleCount: len(plan.Body.Rules),
		UnlinkedBytes: total,
	}
	mac,err:=reclaimCompletionMAC(body,key)
	if err!=nil { return nil,ErrCompletedRuleReclaim }
	data,err:=json.Marshal(reclaimSignedCompletion{Body:body,MAC:mac})
	if err!=nil || len(data)<=0 || len(data)>maxReclaimCompletionBytes {
		return nil,ErrCompletedRuleReclaim
	}
	return data,nil
}

// This scanner has a terminal-only allowlist. No rule leaf is ever permitted;
// the signed plan, completion and ALL signed per-leaf intents must remain.
func scanSealedReclaimEvidence(ctx context.Context, p *reclaimRuleScope,
	plan reclaimSignedPlan, planBytes, completion []byte, key [32]byte,
) (map[string]os.FileInfo,error) {
	if ctx==nil || p==nil || ctx.Err()!=nil ||
		verifyReclaimRoot(ctx,p)!=nil {
		return nil,ErrCompletedRuleReclaim
	}
	fd,err:=unix.Openat(int(p.root.Fd()),p.name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,0)
	if err!=nil { return nil,ErrCompletedRuleReclaim }
	reader:=os.NewFile(uintptr(fd),"sealed-reclaim-reader")
	if reader==nil { _=unix.Close(fd);return nil,ErrCompletedRuleReclaim }
	defer reader.Close()
	identity,err:=reader.Stat()
	if err!=nil || !os.SameFile(identity,p.dirInfo) ||
		!privatePortableDirectory(identity) { return nil,ErrCompletedRuleReclaim }
	expected:=make(map[string][]byte,len(plan.Body.Rules)+2)
	expected[reclaimPlanFileName]=planBytes
	expected[reclaimCompletionName]=completion
	planSHA:=shaHex(planBytes)
	for i,rule:=range plan.Body.Rules {
		name:=reclaimIntentPrefix+fmtReclaimIndex(i)
		expected[name]=[]byte(reclaimIntentMAC(key,planSHA,i,rule.Name))
	}
	entries,err:=reader.ReadDir(len(expected)+1)
	if (err!=nil&&!errors.Is(err,io.EOF)) || len(entries)!=len(expected) {
		return nil,ErrCompletedRuleReclaim
	}
	seen:=make(map[string]os.FileInfo,len(expected))
	for _,entry:=range entries {
		want,ok:=expected[entry.Name()]
		if !ok || !entry.Type().IsRegular() || seen[entry.Name()]!=nil {
			return nil,ErrCompletedRuleReclaim
		}
		limit:=maxReclaimPlanBytes
		if entry.Name()==reclaimCompletionName { limit=maxReclaimCompletionBytes }
		if entry.Name()!=reclaimPlanFileName && entry.Name()!=reclaimCompletionName { limit=128 }
		data,info,readErr:=readPrivateReclaimFile(ctx,p.dir,entry.Name(),limit)
		if readErr!=nil || !bytes.Equal(data,want) { return nil,ErrCompletedRuleReclaim }
		seen[entry.Name()]=info
	}
	if verifyDormantRuleScope(p.root,p.name,p.dir,p.dirInfo)!=nil || ctx.Err()!=nil {
		return nil,ErrCompletedRuleReclaim
	}
	return seen,nil
}

func fmtReclaimIndex(i int) string {
	// MaxClosureRuleSets is 128; the index remains three ASCII digits.
	return string([]byte{'0'+byte(i/100), '0'+byte(i/10%10), '0'+byte(i%10)})
}

func sameSealedReclaimEvidence(a,b map[string]os.FileInfo) bool {
	if len(a)!=len(b) {return false}
	for name,info:=range a {
		if b[name]==nil || !sameLeasedFile(info,b[name]) {return false}
	}
	return true
}

func completedReclaimReceipt(p *reclaimRuleScope,
	plan reclaimSignedPlan, planBytes, completion []byte) CompletedRuleReclaimReceipt {
	var n int64
	for _,r:=range plan.Body.Rules {n+=r.Size}
	return CompletedRuleReclaimReceipt{
		ArchiveSHA256:p.receipt.ArchiveSHA256,
		InventorySHA256:p.receipt.InventorySHA256,
		PlanSHA256:shaHex(planBytes),
		CompletionSHA256:shaHex(completion),
		RuleCount:len(plan.Body.Rules),
		UnlinkedBytes:n,
		CompletionSealed:true,
		MetadataRetained:true,
		RequiresRevalidation:true,
		RestoreSupported:false,
		RestoreReady:false,
	}
}
