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
	reclaimAttestationPrefix   = ".ktui-inert-reclaim-attest-v1-"
	reclaimAttestationVersion  = "karing-tui-v2-inert-reclaim-attest-v1"
	maxReclaimAttestationBytes = 2048
)

var ErrRetainedReclaimAttestation = errors.New("off-scope reclaim attestation refused")

// RetainedReclaimAttestation is expiring audit evidence only. In particular it
// cannot authorize deleting the original plan, intents, scope or ciphertext.
type RetainedReclaimAttestation struct {
	ArchiveSHA256            string
	InventorySHA256          string
	PlanSHA256               string
	CompletionSHA256         string
	AttestationSHA256        string
	RuleCount                int
	UnlinkedBytes            int64
	AttestationRetained      bool
	OriginalEvidenceRetained bool
	RequiresRevalidation     bool
	RestoreSupported         bool
	RestoreReady             bool
}

type reclaimAttestationBody struct {
	Version          string `json:"version"`
	ArchiveSHA256    string `json:"archive_sha256"`
	InventorySHA256  string `json:"inventory_sha256"`
	PlanSHA256       string `json:"plan_sha256"`
	CompletionSHA256 string `json:"completion_sha256"`
	JournalID        int64  `json:"journal_id"`
	ScopeDevice      uint64 `json:"scope_device"`
	ScopeInode       uint64 `json:"scope_inode"`
	RuleCount        int    `json:"rule_count"`
	UnlinkedBytes    int64  `json:"unlinked_bytes"`
}

type reclaimSignedAttestation struct {
	Body reclaimAttestationBody `json:"body"`
	MAC  string                 `json:"mac"`
}

// AttestSealedDurableReclaim writes an independent immutable, HMAC-signed
// terminal audit anchor OUTSIDE the reclaim scope. The parent is derived from
// the live database, not chosen by a caller. All original signed proof files
// are kept. No file is removed and no restore/import/Core action is possible.
func (l *InertRestoreResourceLease) AttestSealedDurableReclaim(
	ctx context.Context, key [32]byte, expected CompletedRuleReclaimReceipt,
) (RetainedReclaimAttestation, error) {
	return l.attestSealedDurableReclaim(ctx, key, expected, nil, nil)
}

// Fault seams: before the O_EXCL publication and after file fsync, but before
// the parent directory fsync. A post-publication fault must never be reported
// as successful or trigger any automatic rollback/deletion.
func (l *InertRestoreResourceLease) attestSealedDurableReclaim(
	ctx context.Context, key [32]byte, expected CompletedRuleReclaimReceipt,
	beforePublish, afterPublish func() error,
) (RetainedReclaimAttestation, error) {
	var zero RetainedReclaimAttestation
	if ctx == nil || l == nil || key == ([32]byte{}) ||
		!validLowerSHA(expected.ArchiveSHA256) ||
		!validLowerSHA(expected.InventorySHA256) ||
		!validLowerSHA(expected.PlanSHA256) ||
		!validLowerSHA(expected.CompletionSHA256) ||
		!expected.CompletionSealed || !expected.MetadataRetained ||
		!expected.RequiresRevalidation ||
		expected.RestoreSupported || expected.RestoreReady ||
		expected.RuleCount <= 0 || expected.RuleCount > MaxClosureRuleSets ||
		expected.UnlinkedBytes <= 0 || expected.UnlinkedBytes > MaxClosureRuleBytes {
		return zero, ErrRetainedReclaimAttestation
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
		return zero, ErrRetainedReclaimAttestation
	}
	defer p.close()
	plan, planBytes, err := readReclaimPlan(bounded, p, l, key)
	if err != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	completion, err := createReclaimCompletion(p, l.record.ID, plan, planBytes, key)
	if err != nil || expected != completedReclaimReceipt(p, plan, planBytes, completion) {
		return zero, ErrRetainedReclaimAttestation
	}
	first, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, completion, key)
	if err != nil || verifyReclaimRoot(bounded, p) != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return zero, ErrRetainedReclaimAttestation
	}

	parent, dir, err := openReclaimAttestationParent(l)
	if err != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	defer parent.Close()
	name := reclaimAttestationPrefix + p.receipt.ArchiveSHA256
	var prior unix.Stat_t
	if statErr := unix.Fstatat(int(dir.Fd()), name, &prior,
		unix.AT_SYMLINK_NOFOLLOW); !errors.Is(statErr, unix.ENOENT) {
		// Never replace a prior attestation, not even a malformed one.
		return zero, ErrRetainedReclaimAttestation
	}
	payload, err := createReclaimAttestation(p, l.record.ID, planBytes, completion, expected, key)
	if err != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	if beforePublish != nil && beforePublish() != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	second, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, completion, key)
	if err != nil || !sameSealedReclaimEvidence(first, second) ||
		verifyReclaimRoot(bounded, p) != nil || parent.verify() != nil ||
		l.revalidateLocked(bounded, key) != nil || bounded.Err() != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	if publishPrivateReclaimMarker(bounded, dir, name, payload) != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	if afterPublish != nil && afterPublish() != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	if dir.Sync() != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	if verifyPrivateReclaimAttestation(bounded, dir, name, payload) != nil ||
		parent.verify() != nil || verifyReclaimRoot(bounded, p) != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	third, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, completion, key)
	if err != nil || !sameSealedReclaimEvidence(second, third) ||
		verifyPrivateReclaimAttestation(bounded, dir, name, payload) != nil ||
		parent.verify() != nil || l.revalidateLocked(bounded, key) != nil ||
		bounded.Err() != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	return retainedReclaimAttestation(expected, payload), nil
}

// InspectRetainedReclaimAttestation is a cross-restart, read-only verifier.
// It still requires the FULL original sealed scope, encrypted archive, key,
// prepared recovery journal and unchanged live CAS; its report is not a
// durable path lease or permission to remove either copy of audit evidence.
func (l *InertRestoreResourceLease) InspectRetainedReclaimAttestation(
	ctx context.Context, key [32]byte,
) (RetainedReclaimAttestation, error) {
	var zero RetainedReclaimAttestation
	if ctx == nil || l == nil || key == ([32]byte{}) {
		return zero, ErrRetainedReclaimAttestation
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
		return zero, ErrRetainedReclaimAttestation
	}
	defer p.close()
	plan, planBytes, err := readReclaimPlan(bounded, p, l, key)
	if err != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	completion, err := createReclaimCompletion(p, l.record.ID, plan, planBytes, key)
	if err != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	sealed := completedReclaimReceipt(p, plan, planBytes, completion)
	payload, err := createReclaimAttestation(p, l.record.ID, planBytes, completion, sealed, key)
	if err != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	parent, dir, err := openReclaimAttestationParent(l)
	if err != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	defer parent.Close()
	name := reclaimAttestationPrefix + p.receipt.ArchiveSHA256
	for i := 0; i < 2; i++ {
		if verifyPrivateReclaimAttestation(bounded, dir, name, payload) != nil ||
			parent.verify() != nil || verifyReclaimRoot(bounded, p) != nil {
			return zero, ErrRetainedReclaimAttestation
		}
		if _, err := scanSealedReclaimEvidence(bounded, p, plan, planBytes, completion, key); err != nil || l.revalidateLocked(bounded, key) != nil {
			return zero, ErrRetainedReclaimAttestation
		}
	}
	if bounded.Err() != nil {
		return zero, ErrRetainedReclaimAttestation
	}
	return retainedReclaimAttestation(sealed, payload), nil
}

// openPrivatePortableTargetTree verifies each path component with O_NOFOLLOW,
// and requires the derived database parent to be a UID-owned private 0700
// directory. It never opens an archive-provided path for writing.
func openReclaimAttestationParent(l *InertRestoreResourceLease) (*privatePortableTargetTree, *os.File, error) {
	if l == nil || l.live == nil {
		return nil, nil, ErrRetainedReclaimAttestation
	}
	path := filepath.Dir(l.live.Path())
	if !validPortablePreviewRoot(path) {
		return nil, nil, ErrRetainedReclaimAttestation
	}
	parent, err := openPrivatePortableTargetTree(path, false)
	if err != nil {
		return nil, nil, ErrRetainedReclaimAttestation
	}
	dir := parent.components[len(parent.components)-1].dir
	if parent.verify() != nil {
		_ = parent.Close()
		return nil, nil, ErrRetainedReclaimAttestation
	}
	return parent, dir, nil
}

func createReclaimAttestation(p *reclaimRuleScope, journalID int64, planBytes, completion []byte,
	sealed CompletedRuleReclaimReceipt, key [32]byte,
) ([]byte, error) {
	if p == nil || journalID <= 0 || !sealed.CompletionSealed ||
		!sealed.MetadataRetained || sealed.RestoreReady || sealed.RestoreSupported ||
		!validLowerSHA(sealed.ArchiveSHA256) || !validLowerSHA(sealed.InventorySHA256) ||
		sealed.PlanSHA256 != shaHex(planBytes) ||
		sealed.CompletionSHA256 != shaHex(completion) ||
		sealed.RuleCount <= 0 || sealed.RuleCount > MaxClosureRuleSets ||
		sealed.UnlinkedBytes <= 0 || sealed.UnlinkedBytes > MaxClosureRuleBytes {
		return nil, ErrRetainedReclaimAttestation
	}
	meta, ok := p.dirInfo.Sys().(*syscall.Stat_t)
	if !ok || meta.Dev == 0 || meta.Ino == 0 {
		return nil, ErrRetainedReclaimAttestation
	}
	body := reclaimAttestationBody{
		Version:          reclaimAttestationVersion,
		ArchiveSHA256:    sealed.ArchiveSHA256,
		InventorySHA256:  sealed.InventorySHA256,
		PlanSHA256:       sealed.PlanSHA256,
		CompletionSHA256: sealed.CompletionSHA256,
		JournalID:        journalID,
		ScopeDevice:      meta.Dev,
		ScopeInode:       meta.Ino,
		RuleCount:        sealed.RuleCount,
		UnlinkedBytes:    sealed.UnlinkedBytes,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, ErrRetainedReclaimAttestation
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("karing-tui-v2/durable-rule-reclaim/off-scope-attestation-v1\x00"))
	_, _ = mac.Write(raw)
	payload, err := json.Marshal(reclaimSignedAttestation{
		Body: body,
		MAC:  hex.EncodeToString(mac.Sum(nil)),
	})
	if err != nil || len(payload) == 0 || len(payload) > maxReclaimAttestationBytes {
		return nil, ErrRetainedReclaimAttestation
	}
	return payload, nil
}

func verifyPrivateReclaimAttestation(ctx context.Context, dir *os.File,
	name string, expected []byte,
) error {
	raw, first, err := readPrivateReclaimFile(ctx, dir, name, maxReclaimAttestationBytes)
	if err != nil || !bytes.Equal(raw, expected) {
		return ErrRetainedReclaimAttestation
	}
	raw, second, err := readPrivateReclaimFile(ctx, dir, name, maxReclaimAttestationBytes)
	if err != nil || !bytes.Equal(raw, expected) || !sameLeasedFile(first, second) {
		return ErrRetainedReclaimAttestation
	}
	return nil
}

func retainedReclaimAttestation(sealed CompletedRuleReclaimReceipt, payload []byte) RetainedReclaimAttestation {
	return RetainedReclaimAttestation{
		ArchiveSHA256:            sealed.ArchiveSHA256,
		InventorySHA256:          sealed.InventorySHA256,
		PlanSHA256:               sealed.PlanSHA256,
		CompletionSHA256:         sealed.CompletionSHA256,
		AttestationSHA256:        shaHex(payload),
		RuleCount:                sealed.RuleCount,
		UnlinkedBytes:            sealed.UnlinkedBytes,
		AttestationRetained:      true,
		OriginalEvidenceRetained: true,
		RequiresRevalidation:     true,
		RestoreSupported:         false,
		RestoreReady:             false,
	}
}
