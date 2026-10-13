//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrInertRestoreJournalRefused = errors.New("inert encrypted recovery preparation journal refused")

// PrepareInertRestoreCandidateRecord writes ONLY an inert, non-activating
// journal row. It reauthenticates the encrypted candidate and live read fence
// before entering the SAME SQLite transaction for guarded CAS and INSERT.
//
// It never extracts the backup, stops the core, changes applied/LKG state,
// creates apply_journal entries, or grants a restore permit.
func PrepareInertRestoreCandidateRecord(
	ctx context.Context, live *storage.Store,
	candidate *InertRestoreCandidate, key [32]byte,
	dryRun InertRestoreDryRun,
) (storage.InertRestorePreparation, error) {
	var none storage.InertRestorePreparation
	if ctx == nil || live == nil || candidate == nil ||
		key == ([32]byte{}) || dryRun.RestoreReady || dryRun.RestoreSupported ||
		!dryRun.ArchiveAuthenticated || !dryRun.SQLiteSchemaVerified ||
		!validLowerSHA(dryRun.ArchiveSHA256) ||
		!validLowerSHA(dryRun.InventorySHA256) || dryRun.ArchiveBytes <= 0 {
		return none, ErrInertRestoreJournalRefused
	}
	if err := RecheckInertRestoreDryRun(ctx, live, candidate, key, dryRun); err != nil {
		return none, ErrInertRestoreJournalRefused
	}
	directory := candidate.Directory()
	if !validInertRestoreCandidateDir(directory) {
		return none, ErrInertRestoreJournalRefused
	}
	input := storage.InertRestorePreparationInput{
		CandidateScope:  filepath.Base(directory),
		ArchiveSHA256:   dryRun.ArchiveSHA256,
		InventorySHA256: dryRun.InventorySHA256,
		ArchiveBytes:    dryRun.ArchiveBytes,
		Baseline:        dryRun.Baseline,
	}
	result, err := live.PrepareInertRestoreRecord(ctx, input)
	if err != nil {
		return none, err
	}
	return result, nil
}

// RevalidateInertRestoreCandidateRecord is a post-restart READ-ONLY check:
// the caller reacquires an exclusive candidate flock and supplies the key.
// The method re-reads the canonical journal, confirms the same encrypted
// archive identity and complete current-state digest fence, and still does
// not authorize or start a recovery.
func RevalidateInertRestoreCandidateRecord(
	ctx context.Context, live *storage.Store,
	candidate *InertRestoreCandidate, key [32]byte,
	recordID int64,
) error {
	if ctx == nil || live == nil || candidate == nil ||
		key == ([32]byte{}) || recordID <= 0 {
		return ErrInertRestoreJournalRefused
	}
	records, err := live.InspectInertRestoreRecords(ctx)
	if err != nil {
		return ErrInertRestoreJournalRefused
	}
	directory := candidate.Directory()
	if !validInertRestoreCandidateDir(directory) {
		return ErrInertRestoreJournalRefused
	}
	var found *storage.InertRestorePreparation
	for i := range records {
		if records[i].ID == recordID {
			found = &records[i]
			break
		}
	}
	if found == nil || found.Phase != storage.InertRestorePrepared ||
		found.RestoreReady || found.RestoreSupported ||
		found.CandidateScope != filepath.Base(directory) {
		return ErrInertRestoreJournalRefused
	}
	receipt, err := candidate.Verify(ctx, key)
	if err != nil || receipt.RestoreSupported || receipt.RestoreReady ||
		!receipt.SchemaCatalogVerified || !receipt.SQLiteLogicalVerified ||
		receipt.ArchiveSHA256 != found.ArchiveSHA256 ||
		receipt.InventorySHA256 != found.InventorySHA256 ||
		receipt.ArchiveBytes != found.ArchiveBytes {
		return ErrInertRestoreJournalRefused
	}
	if err := live.RecheckInertRestoreFence(ctx, found.Baseline); err != nil {
		return ErrInertRestoreJournalRefused
	}
	// The journal can be concurrently abandoned; a final read proves that
	// this same inert row is still pending. Its success is STILL not a CAS.
	again, err := live.InspectInertRestoreRecords(ctx)
	if err != nil {
		return ErrInertRestoreJournalRefused
	}
	for _, row := range again {
		if row.ID == found.ID && row.Phase == storage.InertRestorePrepared &&
			row.ArchiveSHA256 == found.ArchiveSHA256 &&
			row.InventorySHA256 == found.InventorySHA256 &&
			row.Baseline == found.Baseline {
			return nil
		}
	}
	return ErrInertRestoreJournalRefused
}
