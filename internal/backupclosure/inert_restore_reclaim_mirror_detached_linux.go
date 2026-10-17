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
	"strings"
)

// ErrDetachedReclaimMirror indicates that the historic signed mirror cannot
// be independently authenticated against the original encrypted archive.
var ErrDetachedReclaimMirror = errors.New("source-independent signed reclaim proof audit refused")

// DetachedReclaimMirrorAudit proves ONLY the integrity of retained historical
// signed evidence and its linkage to the still-prepared encrypted archive.
// It deliberately does not inspect the inactive source scope or prove that
// original rule bytes remain absent. It grants no cleanup or restore authority.
type DetachedReclaimMirrorAudit struct {
	ArchiveSHA256           string
	InventorySHA256         string
	PlanSHA256              string
	CompletionSHA256        string
	AttestationSHA256       string
	MirrorSHA256            string
	RuleCount               int
	DocumentedUnlinkedBytes int64
	MirroredProofFiles      int
	MirroredProofBytes      int64
	ArchiveJournalVerified  bool
	HistoryMACsVerified     bool
	SourceScopeVerified     bool
	RuleAbsenceVerified     bool
	DeletionAuthorized      bool
	RequiresRevalidation    bool
	RestoreSupported        bool
	RestoreReady            bool
}

// InspectDetachedReclaimMirror authenticates the entire ADR 0122 proof copy
// WITHOUT opening, enumerating, requiring or trusting the original reclaim
// scope. It is intentionally a separate read-only API from the source-bound
// InspectMirroredReclaimEvidence. The original ciphertext + key, exact
// prepared v18 journal and unchanged live CAS are STILL mandatory.
// A success does not imply that the source directory is missing, unchanged,
// deletable or even currently present.
func (l *InertRestoreResourceLease) InspectDetachedReclaimMirror(
	ctx context.Context, key [32]byte,
) (DetachedReclaimMirrorAudit, error) {
	var zero DetachedReclaimMirrorAudit
	if ctx == nil || l == nil || key == ([32]byte{}) {
		return zero, ErrDetachedReclaimMirror
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.revalidateLocked(bounded, key) != nil {
		return zero, ErrDetachedReclaimMirror
	}
	receipt := SealedArchiveReceipt{
		ArchiveSHA256:   l.record.ArchiveSHA256,
		InventorySHA256: l.record.InventorySHA256,
		Bytes:           l.record.ArchiveBytes,
		Format:          l.candidate.receipt.Format,
	}
	if !validLowerSHA(receipt.ArchiveSHA256) ||
		!validLowerSHA(receipt.InventorySHA256) {
		return zero, ErrDetachedReclaimMirror
	}
	inventory, err := readAuthenticatedInventory(
		bounded, l.candidate.archive, key, receipt)
	if err != nil || len(inventory.RuleSets) == 0 ||
		len(inventory.RuleSets) > MaxClosureRuleSets {
		return zero, ErrDetachedReclaimMirror
	}
	parent, dir, err := openReclaimAttestationParent(l)
	if err != nil {
		return zero, ErrDetachedReclaimMirror
	}
	defer parent.Close()
	anchorName := reclaimAttestationPrefix + receipt.ArchiveSHA256
	mirrorName := reclaimMirrorPrefix + receipt.ArchiveSHA256

	var previousAnchor, previousMirror os.FileInfo
	var previousAudit DetachedReclaimMirrorAudit
	for attempt := 0; attempt < 2; attempt++ {
		anchor, anchorInfo, readErr := readPrivateReclaimFile(
			bounded, dir, anchorName, maxReclaimAttestationBytes)
		if readErr != nil {
			return zero, ErrDetachedReclaimMirror
		}
		mirror, mirrorInfo, readErr := readPrivateReclaimFile(
			bounded, dir, mirrorName, maxReclaimMirrorBytes)
		if readErr != nil {
			return zero, ErrDetachedReclaimMirror
		}
		audit, authErr := authenticateDetachedReclaimMirror(
			key, l.record.ID, receipt, inventory, anchor, mirror)
		if authErr != nil || parent.verify() != nil ||
			l.revalidateLocked(bounded, key) != nil || bounded.Err() != nil {
			return zero, ErrDetachedReclaimMirror
		}
		if attempt > 0 &&
			(!sameLeasedFile(previousAnchor, anchorInfo) ||
				!sameLeasedFile(previousMirror, mirrorInfo) ||
				previousAudit != audit) {
			return zero, ErrDetachedReclaimMirror
		}
		previousAnchor, previousMirror = anchorInfo, mirrorInfo
		previousAudit = audit
	}
	if parent.verify() != nil || l.revalidateLocked(bounded, key) != nil ||
		bounded.Err() != nil {
		return zero, ErrDetachedReclaimMirror
	}
	return previousAudit, nil
}

// authenticateDetachedReclaimMirror independently verifies ALL nested keyed
// proofs and the original signed inventory, without relying on any on-disk
// source-scope file. It does not treat the mirror's outer HMAC as permission
// to skip validating the signatures and semantics of embedded objects.
func authenticateDetachedReclaimMirror(
	key [32]byte, journalID int64, receipt SealedArchiveReceipt,
	inventory Inventory, anchorBytes, mirrorBytes []byte,
) (DetachedReclaimMirrorAudit, error) {
	var zero DetachedReclaimMirrorAudit
	if key == ([32]byte{}) || journalID <= 0 ||
		!validLowerSHA(receipt.ArchiveSHA256) ||
		!validLowerSHA(receipt.InventorySHA256) ||
		len(anchorBytes) == 0 || len(anchorBytes) > maxReclaimAttestationBytes ||
		len(mirrorBytes) == 0 || len(mirrorBytes) > maxReclaimMirrorBytes ||
		len(inventory.RuleSets) == 0 || len(inventory.RuleSets) > MaxClosureRuleSets {
		return zero, ErrDetachedReclaimMirror
	}
	var mirror reclaimSignedMirror
	if json.Unmarshal(mirrorBytes, &mirror) != nil ||
		!canonicalReclaimJSON(mirrorBytes, mirror) ||
		mirror.Body.Version != reclaimMirrorVersion ||
		mirror.Body.ArchiveSHA256 != receipt.ArchiveSHA256 ||
		mirror.Body.InventorySHA256 != receipt.InventorySHA256 ||
		mirror.Body.JournalID != journalID ||
		mirror.Body.RuleCount != len(inventory.RuleSets) ||
		len(mirror.Body.Intents) != len(inventory.RuleSets) ||
		!validLowerSHA(mirror.Body.PlanSHA256) ||
		!validLowerSHA(mirror.Body.CompletionSHA256) ||
		!validLowerSHA(mirror.Body.AttestationSHA256) ||
		mirror.Body.ScopeDevice == 0 || mirror.Body.ScopeInode == 0 ||
		shaHex(anchorBytes) != mirror.Body.AttestationSHA256 ||
		!bytes.Equal(anchorBytes, mirror.Body.Attestation) ||
		!detachedMACValid(mirror.MAC, mirror.Body, key,
			"karing-tui-v2/durable-rule-reclaim/full-proof-mirror-v1\x00") {
		return zero, ErrDetachedReclaimMirror
	}

	var plan reclaimSignedPlan
	if len(mirror.Body.Plan) == 0 || len(mirror.Body.Plan) > maxReclaimPlanBytes ||
		json.Unmarshal(mirror.Body.Plan, &plan) != nil ||
		!canonicalReclaimJSON(mirror.Body.Plan, plan) ||
		plan.Body.Version != reclaimPlanVersion ||
		plan.Body.ArchiveSHA256 != receipt.ArchiveSHA256 ||
		plan.Body.InventorySHA256 != receipt.InventorySHA256 ||
		plan.Body.JournalID != journalID ||
		plan.Body.DirectoryDevice != mirror.Body.ScopeDevice ||
		plan.Body.DirectoryInode != mirror.Body.ScopeInode ||
		len(plan.Body.Rules) != len(inventory.RuleSets) ||
		shaHex(mirror.Body.Plan) != mirror.Body.PlanSHA256 {
		return zero, ErrDetachedReclaimMirror
	}
	planMAC, err := reclaimPlanMAC(plan.Body, key)
	if err != nil || !sameDetachedMAC(plan.MAC, planMAC) {
		return zero, ErrDetachedReclaimMirror
	}

	byName := make(map[string]RuleDigest, len(inventory.RuleSets))
	const prefix = "rule-sets/sha256/"
	for _, rule := range inventory.RuleSets {
		if !strings.HasPrefix(rule.RelativePath, prefix) {
			return zero, ErrDetachedReclaimMirror
		}
		name := strings.TrimPrefix(rule.RelativePath, prefix)
		if name == "" || strings.Contains(name, "/") ||
			!validLowerSHA(rule.SHA256) ||
			rule.Size <= 0 || rule.Size > MaxClosureRuleBytes {
			return zero, ErrDetachedReclaimMirror
		}
		if _, exists := byName[name]; exists {
			return zero, ErrDetachedReclaimMirror
		}
		byName[name] = rule
	}
	var absentBytes int64
	for i, rule := range plan.Body.Rules {
		want, exists := byName[rule.Name]
		if !exists || rule.SHA256 != want.SHA256 ||
			rule.Size != want.Size || rule.Device == 0 || rule.Inode == 0 ||
			(i > 0 && plan.Body.Rules[i-1].Name >= rule.Name) ||
			rule.Size <= 0 || absentBytes > MaxClosureRuleBytes-rule.Size {
			return zero, ErrDetachedReclaimMirror
		}
		absentBytes += rule.Size
		wantIntent := reclaimIntentMAC(key, mirror.Body.PlanSHA256, i, rule.Name)
		gotIntent := mirror.Body.Intents[i]
		if gotIntent.Name != reclaimIntentPrefix+fmtReclaimIndex(i) ||
			!sameDetachedMAC(gotIntent.MAC, wantIntent) {
			return zero, ErrDetachedReclaimMirror
		}
	}
	if absentBytes <= 0 || mirror.Body.UnlinkedBytes != absentBytes {
		return zero, ErrDetachedReclaimMirror
	}

	var completion reclaimSignedCompletion
	if len(mirror.Body.Completion) == 0 ||
		len(mirror.Body.Completion) > maxReclaimCompletionBytes ||
		json.Unmarshal(mirror.Body.Completion, &completion) != nil ||
		!canonicalReclaimJSON(mirror.Body.Completion, completion) ||
		completion.Body.Version != reclaimCompletionVersion ||
		completion.Body.ArchiveSHA256 != receipt.ArchiveSHA256 ||
		completion.Body.InventorySHA256 != receipt.InventorySHA256 ||
		completion.Body.PlanSHA256 != mirror.Body.PlanSHA256 ||
		completion.Body.JournalID != journalID ||
		completion.Body.DirectoryDevice != mirror.Body.ScopeDevice ||
		completion.Body.DirectoryInode != mirror.Body.ScopeInode ||
		completion.Body.RuleCount != len(plan.Body.Rules) ||
		completion.Body.UnlinkedBytes != absentBytes ||
		shaHex(mirror.Body.Completion) != mirror.Body.CompletionSHA256 {
		return zero, ErrDetachedReclaimMirror
	}
	completionMAC, err := reclaimCompletionMAC(completion.Body, key)
	if err != nil || !sameDetachedMAC(completion.MAC, completionMAC) {
		return zero, ErrDetachedReclaimMirror
	}

	var attestation reclaimSignedAttestation
	if json.Unmarshal(anchorBytes, &attestation) != nil ||
		!canonicalReclaimJSON(anchorBytes, attestation) ||
		attestation.Body.Version != reclaimAttestationVersion ||
		attestation.Body.ArchiveSHA256 != receipt.ArchiveSHA256 ||
		attestation.Body.InventorySHA256 != receipt.InventorySHA256 ||
		attestation.Body.PlanSHA256 != mirror.Body.PlanSHA256 ||
		attestation.Body.CompletionSHA256 != mirror.Body.CompletionSHA256 ||
		attestation.Body.JournalID != journalID ||
		attestation.Body.ScopeDevice != mirror.Body.ScopeDevice ||
		attestation.Body.ScopeInode != mirror.Body.ScopeInode ||
		attestation.Body.RuleCount != len(plan.Body.Rules) ||
		attestation.Body.UnlinkedBytes != absentBytes ||
		!detachedMACValid(attestation.MAC, attestation.Body, key,
			"karing-tui-v2/durable-rule-reclaim/off-scope-attestation-v1\x00") {
		return zero, ErrDetachedReclaimMirror
	}

	totalProofBytes := int64(len(mirror.Body.Plan) +
		len(mirror.Body.Completion) + len(mirror.Body.Attestation))
	for _, intent := range mirror.Body.Intents {
		totalProofBytes += int64(len(intent.MAC))
	}
	if totalProofBytes <= 0 || totalProofBytes > maxReclaimMirrorBytes {
		return zero, ErrDetachedReclaimMirror
	}
	return DetachedReclaimMirrorAudit{
		ArchiveSHA256:           receipt.ArchiveSHA256,
		InventorySHA256:         receipt.InventorySHA256,
		PlanSHA256:              mirror.Body.PlanSHA256,
		CompletionSHA256:        mirror.Body.CompletionSHA256,
		AttestationSHA256:       mirror.Body.AttestationSHA256,
		MirrorSHA256:            shaHex(mirrorBytes),
		RuleCount:               len(plan.Body.Rules),
		DocumentedUnlinkedBytes: absentBytes,
		MirroredProofFiles:      len(plan.Body.Rules) + 3,
		MirroredProofBytes:      totalProofBytes,
		ArchiveJournalVerified:  true,
		HistoryMACsVerified:     true,
		SourceScopeVerified:     false,
		RuleAbsenceVerified:     false,
		DeletionAuthorized:      false,
		RequiresRevalidation:    true,
		RestoreSupported:        false,
		RestoreReady:            false,
	}, nil
}

func canonicalReclaimJSON(raw []byte, parsed any) bool {
	canonical, err := json.Marshal(parsed)
	return err == nil && bytes.Equal(canonical, raw)
}

func detachedMACValid(mac string, body any, key [32]byte, domain string) bool {
	raw, err := json.Marshal(body)
	if err != nil {
		return false
	}
	calculated := hmac.New(sha256.New, key[:])
	_, _ = calculated.Write([]byte(domain))
	_, _ = calculated.Write(raw)
	return sameDetachedMAC(mac, hex.EncodeToString(calculated.Sum(nil)))
}

func sameDetachedMAC(received, expected string) bool {
	if !validLowerSHA(received) || !validLowerSHA(expected) {
		return false
	}
	have, err := hex.DecodeString(received)
	if err != nil || len(have) != sha256.Size {
		return false
	}
	want, err := hex.DecodeString(expected)
	return err == nil && len(want) == sha256.Size && hmac.Equal(have, want)
}
