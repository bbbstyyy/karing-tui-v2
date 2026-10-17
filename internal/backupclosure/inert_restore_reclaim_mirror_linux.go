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
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	reclaimMirrorPrefix   = ".ktui-inert-reclaim-mirror-v1-"
	reclaimMirrorVersion  = "karing-tui-v2-inert-reclaim-proof-mirror-v1"
	maxReclaimMirrorBytes = 256 << 10
)

var ErrReclaimEvidenceMirror = errors.New("signed off-scope reclaim proof mirror refused")

// ReclaimEvidenceMirrorReceipt has no authority over the source scope or the
// encrypted restore candidate. It never means restoration or deletion is safe.
type ReclaimEvidenceMirrorReceipt struct {
	ArchiveSHA256          string
	InventorySHA256        string
	PlanSHA256             string
	CompletionSHA256       string
	AttestationSHA256      string
	MirrorSHA256           string
	RuleCount              int
	MirroredProofFiles     int
	MirroredProofBytes     int64
	MirrorRetained         bool
	OriginalProofsRetained bool
	RequiresRevalidation   bool
	RestoreSupported       bool
	RestoreReady           bool
}

type reclaimMirrorIntent struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
}

// Full canonical signed proofs are copied, not merely their digests. A future
// separate, reviewed protocol MAY revalidate these copies after a source
// scope change; this phase always requires the originals to remain present.
type reclaimMirrorBody struct {
	Version           string                `json:"version"`
	ArchiveSHA256     string                `json:"archive_sha256"`
	InventorySHA256   string                `json:"inventory_sha256"`
	PlanSHA256        string                `json:"plan_sha256"`
	CompletionSHA256  string                `json:"completion_sha256"`
	AttestationSHA256 string                `json:"attestation_sha256"`
	JournalID         int64                 `json:"journal_id"`
	ScopeDevice       uint64                `json:"scope_device"`
	ScopeInode        uint64                `json:"scope_inode"`
	RuleCount         int                   `json:"rule_count"`
	UnlinkedBytes     int64                 `json:"unlinked_bytes"`
	Plan              json.RawMessage       `json:"plan"`
	Completion        json.RawMessage       `json:"completion"`
	Attestation       json.RawMessage       `json:"attestation"`
	Intents           []reclaimMirrorIntent `json:"intents"`
}

type reclaimSignedMirror struct {
	Body reclaimMirrorBody `json:"body"`
	MAC  string            `json:"mac"`
}

// MirrorSealedReclaimEvidence explicitly publishes exactly ONE immutable,
// bounded proof bundle in the live database's existing private state parent.
// It requires the independently verified ADR 0121 anchor AND every ADR 0120
// original proof. No rules or executable bytes and no SQLite image are copied.
func (l *InertRestoreResourceLease) MirrorSealedReclaimEvidence(
	ctx context.Context, key [32]byte, expected RetainedReclaimAttestation,
) (ReclaimEvidenceMirrorReceipt, error) {
	return l.mirrorSealedReclaimEvidence(ctx, key, expected, nil, nil)
}

// Fault hooks are package-private. An error after file fsync but before
// directory fsync yields NO success receipt and never deletes partial files.
func (l *InertRestoreResourceLease) mirrorSealedReclaimEvidence(
	ctx context.Context, key [32]byte, expected RetainedReclaimAttestation,
	beforePublish, afterPublish func() error,
) (ReclaimEvidenceMirrorReceipt, error) {
	var zero ReclaimEvidenceMirrorReceipt
	if ctx == nil || l == nil || key == ([32]byte{}) ||
		!validLowerSHA(expected.ArchiveSHA256) ||
		!validLowerSHA(expected.InventorySHA256) ||
		!validLowerSHA(expected.PlanSHA256) ||
		!validLowerSHA(expected.CompletionSHA256) ||
		!validLowerSHA(expected.AttestationSHA256) ||
		expected.RuleCount <= 0 || expected.RuleCount > MaxClosureRuleSets ||
		expected.UnlinkedBytes <= 0 || expected.UnlinkedBytes > MaxClosureRuleBytes ||
		!expected.AttestationRetained || !expected.OriginalEvidenceRetained ||
		!expected.RequiresRevalidation || expected.RestoreSupported || expected.RestoreReady {
		return zero, ErrReclaimEvidenceMirror
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
		return zero, ErrReclaimEvidenceMirror
	}
	defer p.close()
	plan, planBytes, err := readReclaimPlan(bounded, p, l, key)
	if err != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	completion, err := createReclaimCompletion(p, l.record.ID, plan, planBytes, key)
	if err != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	sealed := completedReclaimReceipt(p, plan, planBytes, completion)
	anchor, err := createReclaimAttestation(p, l.record.ID, planBytes, completion, sealed, key)
	if err != nil || retainedReclaimAttestation(sealed, anchor) != expected {
		return zero, ErrReclaimEvidenceMirror
	}
	mirror, proofBytes, err := createReclaimEvidenceMirror(
		p, l.record.ID, plan, planBytes, completion, anchor, key)
	if err != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	parent, dir, err := openReclaimAttestationParent(l)
	if err != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	defer parent.Close()
	name := reclaimMirrorPrefix + p.receipt.ArchiveSHA256
	var exists unix.Stat_t
	if statErr := unix.Fstatat(int(dir.Fd()), name, &exists,
		unix.AT_SYMLINK_NOFOLLOW); !errors.Is(statErr, unix.ENOENT) {
		return zero, ErrReclaimEvidenceMirror
	}

	first, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, completion, key)
	if err != nil || verifyReclaimRoot(bounded, p) != nil ||
		l.revalidateLocked(bounded, key) != nil || parent.verify() != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	anchorFirst, err := inspectPrivateReclaimAttestation(
		bounded, dir, reclaimAttestationPrefix+p.receipt.ArchiveSHA256, anchor)
	if err != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	if beforePublish != nil && beforePublish() != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	second, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, completion, key)
	anchorSecond, anchorErr := inspectPrivateReclaimAttestation(
		bounded, dir, reclaimAttestationPrefix+p.receipt.ArchiveSHA256, anchor)
	if err != nil || anchorErr != nil ||
		!sameSealedReclaimEvidence(first, second) ||
		!sameLeasedFile(anchorFirst, anchorSecond) ||
		verifyReclaimRoot(bounded, p) != nil || parent.verify() != nil ||
		l.revalidateLocked(bounded, key) != nil || bounded.Err() != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	if publishPrivateReclaimMirror(bounded, dir, name, mirror) != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	if afterPublish != nil && afterPublish() != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	if dir.Sync() != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	mirrorFirst, err := inspectPrivateReclaimMirror(bounded, dir, name, mirror)
	if err != nil || parent.verify() != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	third, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, completion, key)
	anchorThird, anchorErr := inspectPrivateReclaimAttestation(
		bounded, dir, reclaimAttestationPrefix+p.receipt.ArchiveSHA256, anchor)
	mirrorSecond, mirrorErr := inspectPrivateReclaimMirror(bounded, dir, name, mirror)
	if err != nil || anchorErr != nil || mirrorErr != nil ||
		!sameSealedReclaimEvidence(second, third) ||
		!sameLeasedFile(anchorSecond, anchorThird) ||
		!sameLeasedFile(mirrorFirst, mirrorSecond) ||
		verifyReclaimRoot(bounded, p) != nil || parent.verify() != nil ||
		l.revalidateLocked(bounded, key) != nil || bounded.Err() != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	return mirroredReclaimReceipt(sealed, anchor, mirror, proofBytes), nil
}

// InspectMirroredReclaimEvidence authenticates both independent off-scope
// proofs and the complete source metadata after a fresh ciphertext lease.
// It NEVER treats the mirrored copy as permission to remove the originals.
func (l *InertRestoreResourceLease) InspectMirroredReclaimEvidence(
	ctx context.Context, key [32]byte,
) (ReclaimEvidenceMirrorReceipt, error) {
	var zero ReclaimEvidenceMirrorReceipt
	if ctx == nil || l == nil || key == ([32]byte{}) {
		return zero, ErrReclaimEvidenceMirror
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
		return zero, ErrReclaimEvidenceMirror
	}
	defer p.close()
	plan, planBytes, err := readReclaimPlan(bounded, p, l, key)
	if err != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	completion, err := createReclaimCompletion(p, l.record.ID, plan, planBytes, key)
	if err != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	sealed := completedReclaimReceipt(p, plan, planBytes, completion)
	anchor, err := createReclaimAttestation(p, l.record.ID, planBytes, completion, sealed, key)
	if err != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	mirror, proofBytes, err := createReclaimEvidenceMirror(
		p, l.record.ID, plan, planBytes, completion, anchor, key)
	if err != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	parent, dir, err := openReclaimAttestationParent(l)
	if err != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	defer parent.Close()

	anchorName := reclaimAttestationPrefix + p.receipt.ArchiveSHA256
	mirrorName := reclaimMirrorPrefix + p.receipt.ArchiveSHA256
	var firstSource map[string]os.FileInfo
	var firstAnchor, firstMirror os.FileInfo
	for i := 0; i < 2; i++ {
		source, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, completion, key)
		if err != nil {
			return zero, ErrReclaimEvidenceMirror
		}
		anchorInfo, err := inspectPrivateReclaimAttestation(bounded, dir, anchorName, anchor)
		if err != nil {
			return zero, ErrReclaimEvidenceMirror
		}
		mirrorInfo, err := inspectPrivateReclaimMirror(bounded, dir, mirrorName, mirror)
		if err != nil || parent.verify() != nil || verifyReclaimRoot(bounded, p) != nil ||
			l.revalidateLocked(bounded, key) != nil {
			return zero, ErrReclaimEvidenceMirror
		}
		if i > 0 && (!sameSealedReclaimEvidence(firstSource, source) ||
			!sameLeasedFile(firstAnchor, anchorInfo) ||
			!sameLeasedFile(firstMirror, mirrorInfo)) {
			return zero, ErrReclaimEvidenceMirror
		}
		firstSource, firstAnchor, firstMirror = source, anchorInfo, mirrorInfo
	}
	if bounded.Err() != nil {
		return zero, ErrReclaimEvidenceMirror
	}
	return mirroredReclaimReceipt(sealed, anchor, mirror, proofBytes), nil
}

func createReclaimEvidenceMirror(
	p *reclaimRuleScope, journalID int64, plan reclaimSignedPlan,
	planBytes, completion, anchor []byte, key [32]byte,
) ([]byte, int64, error) {
	if p == nil || journalID <= 0 || journalID != plan.Body.JournalID ||
		len(plan.Body.Rules) == 0 || len(plan.Body.Rules) > MaxClosureRuleSets {
		return nil, 0, ErrReclaimEvidenceMirror
	}
	meta, ok := p.dirInfo.Sys().(*syscall.Stat_t)
	if !ok || meta.Dev != plan.Body.DirectoryDevice ||
		meta.Ino != plan.Body.DirectoryInode {
		return nil, 0, ErrReclaimEvidenceMirror
	}
	var size int64 = int64(len(planBytes) + len(completion) + len(anchor))
	if size <= 0 || size > maxReclaimMirrorBytes {
		return nil, 0, ErrReclaimEvidenceMirror
	}
	intents := make([]reclaimMirrorIntent, 0, len(plan.Body.Rules))
	planSHA := shaHex(planBytes)
	for i, rule := range plan.Body.Rules {
		mac := reclaimIntentMAC(key, planSHA, i, rule.Name)
		if len(mac) != 2*sha256.Size {
			return nil, 0, ErrReclaimEvidenceMirror
		}
		size += int64(len(mac))
		if size > maxReclaimMirrorBytes {
			return nil, 0, ErrReclaimEvidenceMirror
		}
		intents = append(intents, reclaimMirrorIntent{
			Name: reclaimIntentPrefix + fmtReclaimIndex(i),
			MAC:  mac,
		})
	}
	body := reclaimMirrorBody{
		Version:           reclaimMirrorVersion,
		ArchiveSHA256:     p.receipt.ArchiveSHA256,
		InventorySHA256:   p.receipt.InventorySHA256,
		PlanSHA256:        planSHA,
		CompletionSHA256:  shaHex(completion),
		AttestationSHA256: shaHex(anchor),
		JournalID:         journalID,
		ScopeDevice:       meta.Dev,
		ScopeInode:        meta.Ino,
		RuleCount:         len(plan.Body.Rules),
		UnlinkedBytes:     completedReclaimReceipt(p, plan, planBytes, completion).UnlinkedBytes,
		Plan:              json.RawMessage(planBytes),
		Completion:        json.RawMessage(completion),
		Attestation:       json.RawMessage(anchor),
		Intents:           intents,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, 0, ErrReclaimEvidenceMirror
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("karing-tui-v2/durable-rule-reclaim/full-proof-mirror-v1\x00"))
	_, _ = mac.Write(raw)
	payload, err := json.Marshal(reclaimSignedMirror{
		Body: body,
		MAC:  hex.EncodeToString(mac.Sum(nil)),
	})
	if err != nil || len(payload) == 0 || len(payload) > maxReclaimMirrorBytes {
		return nil, 0, ErrReclaimEvidenceMirror
	}
	return payload, size, nil
}

// This writer has a deliberately different, bounded 256 KiB limit from the
// 96 KiB plan writer. O_EXCL and 0400 prevent replacement or partial repair.
func publishPrivateReclaimMirror(ctx context.Context, dir *os.File, name string, payload []byte) error {
	if ctx == nil || ctx.Err() != nil || dir == nil ||
		filepath.Base(name) != name || len(payload) == 0 ||
		len(payload) > maxReclaimMirrorBytes {
		return ErrReclaimEvidenceMirror
	}
	fd, err := unix.Openat(int(dir.Fd()), name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return ErrReclaimEvidenceMirror
	}
	file := os.NewFile(uintptr(fd), "reclaim-proof-mirror")
	if file == nil {
		_ = unix.Close(fd)
		return ErrReclaimEvidenceMirror
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return ErrReclaimEvidenceMirror
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) || st.Nlink != 1 {
		_ = file.Close()
		return ErrReclaimEvidenceMirror
	}
	n, writeErr := file.Write(payload)
	modeErr := file.Chmod(0o400)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || n != len(payload) || modeErr != nil ||
		syncErr != nil || closeErr != nil || ctx.Err() != nil {
		return ErrReclaimEvidenceMirror
	}
	return nil
}

func inspectPrivateReclaimMirror(
	ctx context.Context, dir *os.File, name string, expected []byte,
) (os.FileInfo, error) {
	firstBytes, first, err := readPrivateReclaimFile(ctx, dir, name, maxReclaimMirrorBytes)
	if err != nil || !bytes.Equal(firstBytes, expected) {
		return nil, ErrReclaimEvidenceMirror
	}
	secondBytes, second, err := readPrivateReclaimFile(ctx, dir, name, maxReclaimMirrorBytes)
	if err != nil || !bytes.Equal(secondBytes, expected) || !sameLeasedFile(first, second) {
		return nil, ErrReclaimEvidenceMirror
	}
	return second, nil
}

func mirroredReclaimReceipt(
	sealed CompletedRuleReclaimReceipt, anchor, mirror []byte, proofBytes int64,
) ReclaimEvidenceMirrorReceipt {
	return ReclaimEvidenceMirrorReceipt{
		ArchiveSHA256:          sealed.ArchiveSHA256,
		InventorySHA256:        sealed.InventorySHA256,
		PlanSHA256:             sealed.PlanSHA256,
		CompletionSHA256:       sealed.CompletionSHA256,
		AttestationSHA256:      shaHex(anchor),
		MirrorSHA256:           shaHex(mirror),
		RuleCount:              sealed.RuleCount,
		MirroredProofFiles:     sealed.RuleCount + 3,
		MirroredProofBytes:     proofBytes,
		MirrorRetained:         true,
		OriginalProofsRetained: true,
		RequiresRevalidation:   true,
		RestoreSupported:       false,
		RestoreReady:           false,
	}
}
