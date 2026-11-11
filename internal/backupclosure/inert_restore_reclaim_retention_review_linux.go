//go:build linux

package backupclosure

import (
	"context"
	"errors"
)

var ErrReclaimRetentionReview = errors.New("terminal reclaim retention review refused")

// ReclaimRetentionReview is a snapshot of two distinct audit boundaries, not a
// retention decision, inode lease, filesystem safety guarantee, or cleanup
// permit. A signed historical mirror proves neither present-day rule absence
// nor durability under a real power loss.
type ReclaimRetentionReview struct {
	ArchiveSHA256             string
	InventorySHA256           string
	PlanSHA256                string
	CompletionSHA256          string
	AttestationSHA256         string
	MirrorSHA256              string
	RuleCount                 int
	DocumentedUnlinkedBytes   int64
	HistoricalProofsVerified  bool
	SourceProofsVerified      bool
	SourceStatus              string
	RetentionPolicyApproved   bool
	PowerLossReplayVerified   bool
	PhysicalCleanupAuthorized bool
	RequiresManualReview      bool
	RequiresRevalidation      bool
	RestoreSupported          bool
	RestoreReady              bool
}

const (
	reclaimSourceVerified     = "authenticated"
	reclaimSourceUnverifiable = "unverifiable"
)

// ReviewTerminalReclaimRetention separates the historical off-scope signature
// chain (ADR 0123) from the current original-scope audit (ADR 0122), for an
// explicit non-destructive operator-design preflight. The two verifications
// have separate lease mutex acquisitions. The detached proof is independently
// reauthenticated AFTER the source-bound attempt so a changed live CAS fails
// closed. Even an entirely clean result NEVER permits unlink, rmdir, GC,
// restore/import, resource publication or Core execution.
func (l *InertRestoreResourceLease) ReviewTerminalReclaimRetention(
	ctx context.Context, key [32]byte,
) (ReclaimRetentionReview, error) {
	var zero ReclaimRetentionReview
	if ctx == nil || l == nil || key == ([32]byte{}) {
		return zero, ErrReclaimRetentionReview
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	history, err := l.InspectDetachedReclaimMirror(ctx, key)
	if err != nil || !history.ArchiveJournalVerified ||
		!history.HistoryMACsVerified || history.SourceScopeVerified ||
		history.RuleAbsenceVerified || history.DeletionAuthorized ||
		history.RestoreSupported || history.RestoreReady ||
		!history.RequiresRevalidation {
		return zero, ErrReclaimRetentionReview
	}
	// Source verification can fail after an interruption or unexpected
	// namespace change. This must not erase a valid historical audit, but
	// its result is explicitly marked unverified rather than "clean".
	source, sourceErr := l.InspectMirroredReclaimEvidence(ctx, key)
	rechecked, err := l.InspectDetachedReclaimMirror(ctx, key)
	if err != nil || rechecked != history || ctx.Err() != nil {
		return zero, ErrReclaimRetentionReview
	}
	status := reclaimSourceUnverifiable
	sourceVerified := false
	if sourceErr == nil {
		if !source.MirrorRetained || !source.OriginalProofsRetained ||
			!source.RequiresRevalidation || source.RestoreSupported ||
			source.RestoreReady || source.ArchiveSHA256 != history.ArchiveSHA256 ||
			source.InventorySHA256 != history.InventorySHA256 ||
			source.PlanSHA256 != history.PlanSHA256 ||
			source.CompletionSHA256 != history.CompletionSHA256 ||
			source.AttestationSHA256 != history.AttestationSHA256 ||
			source.MirrorSHA256 != history.MirrorSHA256 ||
			source.RuleCount != history.RuleCount ||
			source.MirroredProofFiles != history.MirroredProofFiles ||
			source.MirroredProofBytes != history.MirroredProofBytes {
			return zero, ErrReclaimRetentionReview
		}
		sourceVerified = true
		status = reclaimSourceVerified
	}
	return ReclaimRetentionReview{
		ArchiveSHA256:             history.ArchiveSHA256,
		InventorySHA256:           history.InventorySHA256,
		PlanSHA256:                history.PlanSHA256,
		CompletionSHA256:          history.CompletionSHA256,
		AttestationSHA256:         history.AttestationSHA256,
		MirrorSHA256:              history.MirrorSHA256,
		RuleCount:                 history.RuleCount,
		DocumentedUnlinkedBytes:   history.DocumentedUnlinkedBytes,
		HistoricalProofsVerified:  true,
		SourceProofsVerified:      sourceVerified,
		SourceStatus:              status,
		RetentionPolicyApproved:   false,
		PowerLossReplayVerified:   false,
		PhysicalCleanupAuthorized: false,
		RequiresManualReview:      true,
		RequiresRevalidation:      true,
		RestoreSupported:          false,
		RestoreReady:              false,
	}, nil
}
