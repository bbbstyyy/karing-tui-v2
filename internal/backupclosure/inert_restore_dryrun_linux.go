//go:build linux

package backupclosure

import (
	"context"
	"errors"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var (
	ErrInertRestoreDryRunRejected = errors.New("inert restore dry-run inspection refused")
	ErrInertRestoreDryRunChanged = errors.New("inert restore dry-run baseline changed")
)

const (
	dryRunAfterInitialFence = "after_initial_fence"
	dryRunAfterCandidateVerify = "after_candidate_verification"
)

// InertRestoreDryRun is NEVER an apply permit. It is a read-only proof that
// ONE transient set of committed live bindings was observed unchanged while
// an independently encrypted, inode-locked candidate was authenticated.
// A future writer still needs a fresh operation gate, atomic SQL CAS,
// durable resource lease, isolated materialization and rollback-of-rollback.
type InertRestoreDryRun struct {
	ArchiveSHA256 string
	InventorySHA256 string
	ArchiveBytes int64
	Baseline storage.InertRestoreFence
	ArchiveAuthenticated bool
	SQLiteSchemaVerified bool
	TargetMetadataCompatible bool
	RestoreSupported bool
	RestoreReady bool
}

// InspectInertRestoreDryRun never inserts an apply attempt, never reads
// candidate plaintext into a new disk file, never changes daemon state, and
// never invokes a core. It re-reads the live fence and the candidate twice
// to reject intervening changes. The candidate must keep its live flock.
func InspectInertRestoreDryRun(
	ctx context.Context, live *storage.Store,
	candidate *InertRestoreCandidate, key [32]byte,
) (InertRestoreDryRun, error) {
	return inspectInertRestoreDryRun(ctx, live, candidate, key, nil)
}

// The phase hook is test-only, internal to backupclosure. Injected failures
// never provide an apply path; every return is either inert evidence or error.
func inspectInertRestoreDryRun(
	ctx context.Context, live *storage.Store,
	candidate *InertRestoreCandidate, key [32]byte,
	inject func(string) error,
) (InertRestoreDryRun, error) {
	var none InertRestoreDryRun
	if ctx == nil || live == nil || candidate == nil || key == ([32]byte{}) {
		return none, ErrInertRestoreDryRunRejected
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	first, err := live.ReadInertRestoreFence(ctx)
	if err != nil {
		return none, ErrInertRestoreDryRunRejected
	}
	if err := runInertDryRunFault(ctx, inject, dryRunAfterInitialFence); err != nil {
		return none, err
	}
	receipt, err := candidate.Verify(ctx, key)
	if err != nil || receipt.RestoreReady || receipt.RestoreSupported ||
		!receipt.ResourceDigestsVerified ||
		!receipt.SQLiteLogicalVerified || !receipt.SchemaCatalogVerified ||
		!validLowerSHA(receipt.ArchiveSHA256) ||
		!validLowerSHA(receipt.InventorySHA256) || receipt.ArchiveBytes <= 0 {
		return none, ErrInertRestoreDryRunRejected
	}
	if err := runInertDryRunFault(ctx, inject, dryRunAfterCandidateVerify); err != nil {
		return none, err
	}
	// A second complete authentication catches a fault injected after the
	// first pass (including a same-UID ciphertext writer in tests).
	again, err := candidate.Verify(ctx, key)
	if err != nil || !sameInertPreflightEvidence(receipt, again) ||
		!again.ResourceDigestsVerified || again.RestoreReady ||
		again.RestoreSupported {
		return none, ErrInertRestoreDryRunRejected
	}
	if err := live.RecheckInertRestoreFence(ctx, first); err != nil {
		if errors.Is(err, storage.ErrInertRestoreFenceChanged) {
			return none, ErrInertRestoreDryRunChanged
		}
		return none, ErrInertRestoreDryRunRejected
	}
	return InertRestoreDryRun{
		ArchiveSHA256: receipt.ArchiveSHA256,
		InventorySHA256: receipt.InventorySHA256,
		ArchiveBytes: receipt.ArchiveBytes,
		Baseline: first,
		ArchiveAuthenticated: true,
		SQLiteSchemaVerified: true,
		TargetMetadataCompatible: receipt.TargetMetadataCompatible,
		RestoreSupported: false,
		RestoreReady: false,
	}, nil
}

func runInertDryRunFault(
	ctx context.Context, hook func(string) error, phase string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if hook != nil {
		if err := hook(phase); err != nil {
			return ErrInertRestoreDryRunRejected
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// RecheckInertRestoreDryRun completely reauthenticates the candidate and
// fresh live baseline. A stale, forged or altered caller-carried report never
// authorizes anything, even if this second inspection succeeds.
func RecheckInertRestoreDryRun(
	ctx context.Context, live *storage.Store,
	candidate *InertRestoreCandidate, key [32]byte,
	expected InertRestoreDryRun,
) error {
	if expected.RestoreReady || expected.RestoreSupported ||
		!expected.ArchiveAuthenticated || !expected.SQLiteSchemaVerified ||
		!validLowerSHA(expected.ArchiveSHA256) ||
		!validLowerSHA(expected.InventorySHA256) ||
		expected.ArchiveBytes <= 0 {
		return ErrInertRestoreDryRunRejected
	}
	observed, err := InspectInertRestoreDryRun(ctx, live, candidate, key)
	if err != nil {
		return err
	}
	if observed != expected {
		return ErrInertRestoreDryRunChanged
	}
	return nil
}
