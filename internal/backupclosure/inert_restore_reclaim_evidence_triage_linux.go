//go:build linux

package backupclosure

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

var ErrRetainedEvidenceTriage = errors.New("retained proof manual-hold triage refused")

const (
	retainedTriageManualPolicy = "retention_policy_unapproved"
	retainedTriageSource       = "original_source_unverifiable"
	retainedTriageUnpaired     = "unpaired_proof_names"
	retainedTriageHeadroom     = "bounded_admission_headroom_low"
)

// RetainedEvidenceTriage is a manually inspected, read-only diagnostic
// snapshot. It is never a cleanup ticket, automatic retention policy,
// cryptographic verification of foreign proof names, or live inode pin.
// The available capacity is arithmetic headroom, NOT a promise that the
// next writer can safely publish or that filesystem free space is sufficient.
type RetainedEvidenceTriage struct {
	ArchiveSHA256                string
	MirrorSHA256                 string
	SourceStatus                 string
	ReviewReason                 string
	DirectoryEntriesSeen         int
	AttestationFiles             int
	MirrorFiles                  int
	NamedPairs                   int
	UnpairedFiles                int
	RetainedBytes                int64
	FreeDirectoryEntries         int
	FreeProofSlots               int
	FreeProofBytes               int64
	WorstCaseTwoProofsFit        bool
	HistoricalProofsVerified     bool
	OriginalSourceProofsVerified bool
	ForeignProofNamesOnly        bool
	AdvisoryLockHeldDuringReview bool
	ManualHoldRequired           bool
	PolicyApproved               bool
	PowerLossReplayVerified      bool
	PhysicalCleanupAuthorized    bool
	RequiresRevalidation         bool
	RestoreSupported             bool
	RestoreReady                 bool
}

// InspectRetainedEvidenceTriage combines ADR 0124's authenticated
// source-vs-history distinction and ADR 0125's bounded name/byte census.
// It takes a nonblocking SHARED flock on the already-existing private
// state-directory inode, so cooperating ADR 0126 EXCLUSIVE publishers
// cannot interleave this read. A caller still cannot trust foreign HMACs
// or treat a point-in-time result as authorization to delete or restore.
func (l *InertRestoreResourceLease) InspectRetainedEvidenceTriage(
	ctx context.Context, key [32]byte,
) (RetainedEvidenceTriage, error) {
	return l.inspectRetainedEvidenceTriage(ctx, key, nil)
}

// A package-private hook allows tests to model a concurrent noncooperating
// file replacement or CAS drift between independently authenticated scans.
func (l *InertRestoreResourceLease) inspectRetainedEvidenceTriage(
	ctx context.Context, key [32]byte, betweenScans func() error,
) (RetainedEvidenceTriage, error) {
	var zero RetainedEvidenceTriage
	if l == nil || ctx == nil || key == ([32]byte{}) {
		return zero, ErrRetainedEvidenceTriage
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	// Complete cryptographic historical proof is mandatory, but still
	// cannot prove the current source directory exists. No diagnostic
	// result is returned at all if detached history fails authentication.
	first, err := l.ReviewTerminalReclaimRetention(ctx, key)
	if err != nil || !validTriageSourceReview(first) {
		return zero, ErrRetainedEvidenceTriage
	}
	parent, dir, err := openReclaimAttestationParent(l)
	if err != nil {
		return zero, ErrRetainedEvidenceTriage
	}
	defer parent.Close()
	if unix.Flock(int(dir.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
		return zero, ErrRetainedEvidenceTriage
	}
	defer unix.Flock(int(dir.Fd()), unix.LOCK_UN)

	if parent.verify() != nil || ctx.Err() != nil {
		return zero, ErrRetainedEvidenceTriage
	}
	footprintA, err := l.InspectReclaimEvidenceFootprint(ctx, key)
	if err != nil || !validTriageFootprint(footprintA) ||
		footprintA.ArchiveSHA256 != first.ArchiveSHA256 {
		return zero, ErrRetainedEvidenceTriage
	}
	if betweenScans != nil && betweenScans() != nil {
		return zero, ErrRetainedEvidenceTriage
	}
	// Reauthenticate the entire current archive and original source
	// after acquiring the shared lock, not just a stale signed receipt.
	second, err := l.ReviewTerminalReclaimRetention(ctx, key)
	if err != nil || second != first {
		return zero, ErrRetainedEvidenceTriage
	}
	footprintB, err := l.InspectReclaimEvidenceFootprint(ctx, key)
	if err != nil || footprintB != footprintA ||
		parent.verify() != nil || ctx.Err() != nil {
		return zero, ErrRetainedEvidenceTriage
	}
	return classifyRetainedEvidenceTriage(second, footprintB)
}

func validTriageSourceReview(r ReclaimRetentionReview) bool {
	return validLowerSHA(r.ArchiveSHA256) && validLowerSHA(r.MirrorSHA256) &&
		r.HistoricalProofsVerified && r.RequiresManualReview &&
		r.RequiresRevalidation && !r.RetentionPolicyApproved &&
		!r.PowerLossReplayVerified && !r.PhysicalCleanupAuthorized &&
		!r.RestoreSupported && !r.RestoreReady &&
		((r.SourceStatus == reclaimSourceVerified && r.SourceProofsVerified) ||
			(r.SourceStatus == reclaimSourceUnverifiable && !r.SourceProofsVerified))
}

func validTriageFootprint(p ReclaimEvidenceFootprint) bool {
	return validLowerSHA(p.ArchiveSHA256) &&
		p.NamesOnly && !p.CryptographicProofsVerified &&
		!p.QuotaEnforced && !p.PhysicalCleanupAuthorized &&
		p.RequiresManualReview && p.RequiresRevalidation &&
		!p.RestoreSupported && !p.RestoreReady &&
		p.ReviewEntryLimit == maxReclaimEvidenceDirectoryEntries &&
		p.ReviewFileLimit == maxReclaimEvidenceProofFiles &&
		p.ReviewByteLimit == maxReclaimEvidenceProofBytes &&
		p.DirectoryEntriesSeen >= 0 &&
		p.DirectoryEntriesSeen <= maxReclaimEvidenceDirectoryEntries &&
		p.AttestationFiles >= 1 && p.MirrorFiles >= 1 &&
		p.NamedPairs >= 1 && p.UnpairedFiles >= 0 &&
		p.AttestationFiles+p.MirrorFiles <= maxReclaimEvidenceProofFiles &&
		p.NamedPairs*2+p.UnpairedFiles == p.AttestationFiles+p.MirrorFiles &&
		p.RetainedBytes > 0 && p.RetainedBytes <= maxReclaimEvidenceProofBytes
}

// This helper is intentionally pure: tests cover every headroom boundary
// without manufacturing hundreds of private signed proof files.
// Classification never produces cleanup approval, including for
// authenticated source + no unpaired names + ample arithmetic capacity.
func classifyRetainedEvidenceTriage(
	review ReclaimRetentionReview, p ReclaimEvidenceFootprint,
) (RetainedEvidenceTriage, error) {
	var zero RetainedEvidenceTriage
	if !validTriageSourceReview(review) || !validTriageFootprint(p) ||
		review.ArchiveSHA256 != p.ArchiveSHA256 {
		return zero, ErrRetainedEvidenceTriage
	}
	freeEntries := maxReclaimEvidenceDirectoryEntries - p.DirectoryEntriesSeen
	freeFiles := maxReclaimEvidenceProofFiles - p.AttestationFiles - p.MirrorFiles
	freeBytes := maxReclaimEvidenceProofBytes - p.RetainedBytes
	// Worst-case *new* pair is bounded by the ORIGINAL individual
	// payload ceilings; an archive's actual next proof may be smaller.
	// This merely flags storage pressure and never reserves space.
	fits := freeEntries >= 2 && freeFiles >= 2 &&
		freeBytes >= int64(maxReclaimAttestationBytes+maxReclaimMirrorBytes)
	reason := retainedTriageManualPolicy
	switch {
	case !review.SourceProofsVerified:
		reason = retainedTriageSource
	case p.UnpairedFiles > 0:
		reason = retainedTriageUnpaired
	case !fits:
		reason = retainedTriageHeadroom
	}
	return RetainedEvidenceTriage{
		ArchiveSHA256:                review.ArchiveSHA256,
		MirrorSHA256:                 review.MirrorSHA256,
		SourceStatus:                 review.SourceStatus,
		ReviewReason:                 reason,
		DirectoryEntriesSeen:         p.DirectoryEntriesSeen,
		AttestationFiles:             p.AttestationFiles,
		MirrorFiles:                  p.MirrorFiles,
		NamedPairs:                   p.NamedPairs,
		UnpairedFiles:                p.UnpairedFiles,
		RetainedBytes:                p.RetainedBytes,
		FreeDirectoryEntries:         freeEntries,
		FreeProofSlots:               freeFiles,
		FreeProofBytes:               freeBytes,
		WorstCaseTwoProofsFit:        fits,
		HistoricalProofsVerified:     true,
		OriginalSourceProofsVerified: review.SourceProofsVerified,
		ForeignProofNamesOnly:        true,
		AdvisoryLockHeldDuringReview: true,
		ManualHoldRequired:           true,
		PolicyApproved:               false,
		PowerLossReplayVerified:      false,
		PhysicalCleanupAuthorized:    false,
		RequiresRevalidation:         true,
		RestoreSupported:             false,
		RestoreReady:                 false,
	}, nil
}
