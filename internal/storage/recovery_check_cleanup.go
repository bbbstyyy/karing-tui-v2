package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrHistoricalCheckCleanupUnsafe means a journal entry cannot be proven to
// be a failed, never-activated historical dry-run candidate. It is never safe
// to guess a different generation or prune all retained history instead.
var ErrHistoricalCheckCleanupUnsafe = errors.New("historical check candidate cannot be safely reclaimed")

// ReclaimAbortedHistoricalCheck reclaims ONLY an aborted pre-activation
// historical dry-run candidate. It archives the failed journal entry before
// removing the unconfirmed candidate bytes, in the same SQLite transaction.
//
// It does not prune general history, current applied/LKG payloads, another
// journal's rollback target, or any user-authored generation. In particular,
// it must never be called for a committed/activating/rolling-back generation.
// The daemon's operation gate and detached cleanup timeout guard the caller;
// the transaction separately enforces its own fail-closed references.
func (s *Store) ReclaimAbortedHistoricalCheck(ctx context.Context, attemptID int64) error {
	if s == nil || s.db == nil || attemptID <= 0 {
		return ErrHistoricalCheckCleanupUnsafe
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin historical check cleanup: %w", err)
	}
	defer tx.Rollback()

	var (
		generationID int64
		phase string
		activeSlot sql.NullInt64
		restoreOrigin sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `SELECT
		j.generation_id, j.phase, j.active_slot, g.restore_origin_generation_id
		FROM apply_journal j
		JOIN generations g ON g.id = j.generation_id
		WHERE j.id = ?`, attemptID).
		Scan(&generationID, &phase, &activeSlot, &restoreOrigin)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrHistoricalCheckCleanupUnsafe
	}
	if err != nil {
		return fmt.Errorf("read historical check cleanup journal: %w", err)
	}
	if phase != string(PhaseFailed) || activeSlot.Valid || generationID <= 0 ||
		!restoreOrigin.Valid || restoreOrigin.Int64 <= 0 ||
		restoreOrigin.Int64 == generationID {
		return ErrHistoricalCheckCleanupUnsafe
	}

	var (
		applied sql.NullInt64
		lkg sql.NullInt64
		recoveryRequired int
	)
	if err := tx.QueryRowContext(ctx, `SELECT
		applied_generation_id, last_known_good_generation_id, recovery_required
		FROM daemon_state WHERE singleton = 1`).Scan(&applied, &lkg, &recoveryRequired); err != nil {
		return fmt.Errorf("read fallback references before historical check cleanup: %w", err)
	}
	if recoveryRequired != 0 || (applied.Valid && applied.Int64 == generationID) ||
		(lkg.Valid && lkg.Int64 == generationID) {
		return ErrHistoricalCheckCleanupUnsafe
	}

	// The candidate must be uniquely owned by this aborted attempt. A
	// second journal/archived rollback edge makes deletion unsafe even if
	// the candidate never entered the active apply slot.
	var otherReferences int
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM apply_journal
			WHERE id <> ? AND (generation_id = ? OR previous_generation_id = ?))
		+
		(SELECT COUNT(*) FROM apply_history
			WHERE id <> ? AND (generation_id = ? OR previous_generation_id = ?))
	`, attemptID, generationID, generationID,
		attemptID, generationID, generationID).Scan(&otherReferences); err != nil {
		return fmt.Errorf("read historical check cleanup references: %w", err)
	}
	if otherReferences != 0 {
		return ErrHistoricalCheckCleanupUnsafe
	}

	// Keep the journal's failure provenance even though its large payload
	// is no longer needed. A uniqueness collision must roll back entirely.
	archivedAt := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO apply_history (
		id, generation_id, previous_generation_id, base_revision,
		target_revision, phase, config_sha256, manifest_sha256,
		source_map_sha256, error, started_at, updated_at,
		generation_created_at, archived_at
	)
	SELECT j.id, j.generation_id, j.previous_generation_id,
		j.base_revision, j.target_revision, j.phase,
		g.config_sha256, g.manifest_sha256, g.source_map_sha256,
		j.error, j.started_at, j.updated_at, g.created_at, ?
	FROM apply_journal j
	JOIN generations g ON g.id = j.generation_id
	WHERE j.id = ? AND j.phase = ? AND j.active_slot IS NULL
		AND g.restore_origin_generation_id = ?
	`, archivedAt, attemptID, PhaseFailed, restoreOrigin.Int64)
	if err != nil {
		return fmt.Errorf("archive aborted historical check: %w", err)
	}

	deletedJournal, err := tx.ExecContext(ctx, `DELETE FROM apply_journal
		WHERE id = ? AND generation_id = ? AND phase = ? AND active_slot IS NULL`,
		attemptID, generationID, PhaseFailed)
	if err != nil {
		return fmt.Errorf("delete aborted historical check journal: %w", err)
	}
	journalRows, err := deletedJournal.RowsAffected()
	if err != nil || journalRows != 1 {
		return ErrHistoricalCheckCleanupUnsafe
	}

	deletedGeneration, err := tx.ExecContext(ctx, `DELETE FROM generations
		WHERE id = ? AND restore_origin_generation_id = ?
			AND NOT EXISTS (
				SELECT 1 FROM daemon_state
				WHERE applied_generation_id = ? OR last_known_good_generation_id = ?
			)
			AND NOT EXISTS (
				SELECT 1 FROM apply_journal
				WHERE generation_id = ? OR previous_generation_id = ?
			)`,
		generationID, restoreOrigin.Int64, generationID, generationID,
		generationID, generationID)
	if err != nil {
		return fmt.Errorf("reclaim aborted historical generation: %w", err)
	}
	generationRows, err := deletedGeneration.RowsAffected()
	if err != nil || generationRows != 1 {
		return ErrHistoricalCheckCleanupUnsafe
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit historical check cleanup: %w", err)
	}
	return nil
}
