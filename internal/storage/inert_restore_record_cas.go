package storage

import (
	"context"
	"database/sql"
	"errors"
)

// ErrInertRestoreRecordChanged signals a missing, abandoned, replaced, or
// inconsistent durable record. A pending row is not a recovery permit.
var ErrInertRestoreRecordChanged = errors.New("inert restore resource journal changed")

// CheckInertRestoreRecordCAS atomically rechecks an EXISTING inert journal
// identity and the complete committed live fence while holding SQLite's
// single-writer reservation. It never commits, changes a value, or grants
// activation rights. Successful return does NOT reserve anything afterwards.
func (s *Store) CheckInertRestoreRecordCAS(
	ctx context.Context, expected InertRestorePreparation,
) error {
	return s.checkInertRestoreRecordCAS(ctx, expected, nil)
}

// afterFence is an unexported, synchronous fault-injection seam. It executes
// under the writer reservation; it must never do file/network/core I/O.
func (s *Store) checkInertRestoreRecordCAS(
	ctx context.Context, expected InertRestorePreparation,
	afterFence func() error,
) error {
	if s == nil || s.db == nil || ctx == nil ||
		expected.ID <= 0 || expected.Phase != InertRestorePrepared ||
		!expected.RequiresRevalidation ||
		expected.RestoreSupported || expected.RestoreReady ||
		!validInertRestorePreparationInput(InertRestorePreparationInput{
			CandidateScope:  expected.CandidateScope,
			ArchiveSHA256:   expected.ArchiveSHA256,
			InventorySHA256: expected.InventorySHA256,
			ArchiveBytes:    expected.ArchiveBytes,
			Baseline:        expected.Baseline,
		}) || expected.CreatedAt.IsZero() || expected.UpdatedAt.IsZero() {
		return ErrInertRestorePreparationRefused
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, inertRestoreWriteCASDeadline)
	defer cancel()
	tx, err := s.db.BeginTx(bounded, &sql.TxOptions{})
	if err != nil {
		return ErrInertRestorePreparationRefused
	}
	defer tx.Rollback()
	// Same guarded live UPDATE and complete generation/declaration/selection
	// hashes as ADR 0106, now in the SAME writer transaction as row lookup.
	if err := checkInertRestoreWriteCASTx(bounded, tx, expected.Baseline); err != nil {
		return err
	}
	if afterFence != nil {
		if err := afterFence(); err != nil {
			return ErrInertRestorePreparationRefused
		}
	}
	if err := bounded.Err(); err != nil {
		return err
	}
	var pending int
	if err := tx.QueryRowContext(bounded,
		"SELECT COUNT(*) FROM inert_restore_preparations WHERE phase='prepared' AND active_slot=1",
	).Scan(&pending); err != nil || pending != 1 {
		return ErrInertRestoreRecordChanged
	}
	actual, ok := scanInertRestorePreparation(
		tx.QueryRowContext(bounded, inertRestoreJournalSelect+" WHERE id = ?", expected.ID))
	if !ok || !sameInertRestoreRecord(actual, expected) {
		return ErrInertRestoreRecordChanged
	}
	if err := bounded.Err(); err != nil {
		return err
	}
	// Checked rollback: no writer reservation survives or becomes durable.
	if err := tx.Rollback(); err != nil {
		return ErrInertRestorePreparationRefused
	}
	return nil
}

// All persisted fields, timestamps and the CAS baseline must match. In
// particular, matching a digest alone never proves a journal generation ID.
func sameInertRestoreRecord(a, b InertRestorePreparation) bool {
	return a.ID == b.ID &&
		a.CandidateScope == b.CandidateScope &&
		a.ArchiveSHA256 == b.ArchiveSHA256 &&
		a.InventorySHA256 == b.InventorySHA256 &&
		a.ArchiveBytes == b.ArchiveBytes &&
		a.Baseline == b.Baseline &&
		a.Phase == b.Phase &&
		a.CreatedAt.Equal(b.CreatedAt) &&
		a.UpdatedAt.Equal(b.UpdatedAt) &&
		a.RequiresRevalidation && b.RequiresRevalidation &&
		!a.RestoreSupported && !b.RestoreSupported &&
		!a.RestoreReady && !b.RestoreReady
}
