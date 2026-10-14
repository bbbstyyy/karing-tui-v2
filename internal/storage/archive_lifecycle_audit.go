package storage

import (
	"context"
	"database/sql"
)

// verifyArchivedStableLifecycle is a read-only, non-authorizing gate for both
// newly captured and previously sealed SQLite images. A crash during apply,
// or a failed rollback requiring operator reconciliation, is not a stable
// backup generation. This checks the SAME SQLite snapshot as the archive
// schema and profile auditors, never a separate read of the live daemon.
//
// Historical failed/interrupted attempts are allowed when inactive; they do
// not make a candidate restorable. A brand-new database without an applied
// generation may be inspected but still has no configuration to activate.
func verifyArchivedStableLifecycle(ctx context.Context, conn *sql.Conn) error {
	if ctx == nil || conn == nil || ctx.Err() != nil {
		return ErrArchiveDomainInvalid
	}
	var revision, recoveryRequired int64
	var applied, lastGood sql.NullInt64
	err := conn.QueryRowContext(ctx, `
		SELECT config_revision, applied_generation_id,
		       last_known_good_generation_id, recovery_required
		FROM daemon_state WHERE singleton = 1
	`).Scan(&revision, &applied, &lastGood, &recoveryRequired)
	if err != nil || revision < 0 || recoveryRequired != 0 {
		return ErrArchiveDomainInvalid
	}

	var active int
	if err := conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM apply_journal WHERE active_slot = 1",
	).Scan(&active); err != nil || active != 0 {
		return ErrArchiveDomainInvalid
	}
	if revision == 0 {
		if applied.Valid || lastGood.Valid {
			return ErrArchiveDomainInvalid
		}
		return nil
	}
	if !applied.Valid || !lastGood.Valid ||
		applied.Int64 <= 0 || lastGood.Int64 <= 0 {
		return ErrArchiveDomainInvalid
	}
	if err := verifyArchivedCommittedGeneration(ctx, conn, applied.Int64, revision, revision); err != nil {
		return err
	}
	if lastGood.Int64 != applied.Int64 {
		if err := verifyArchivedCommittedGeneration(ctx, conn, lastGood.Int64, 0, revision); err != nil {
			return err
		}
	}
	return nil
}

// expectedRevision=0 means a historical LKG may be older than the active
// revision, but never newer. Both applied and LKG must reference a retained generation with
// matching committed history; never infer success from a dangling ID alone.
// The history may have been compacted from apply_journal to apply_history.
func verifyArchivedCommittedGeneration(
	ctx context.Context, conn *sql.Conn, generationID, expectedRevision, maxRevision int64,
) error {
	var targetRevision int64
	if err := conn.QueryRowContext(ctx,
		"SELECT target_revision FROM generations WHERE id = ?",
		generationID,
	).Scan(&targetRevision); err != nil || targetRevision <= 0 || targetRevision > maxRevision ||
		(expectedRevision != 0 && targetRevision != expectedRevision) {
		return ErrArchiveDomainInvalid
	}
	var committed int
	if err := conn.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT id FROM apply_journal
			WHERE generation_id = ? AND target_revision = ? AND phase = 'committed'
			UNION ALL
			SELECT id FROM apply_history
			WHERE generation_id = ? AND target_revision = ? AND phase = 'committed'
		)
	`, generationID, targetRevision, generationID, targetRevision).Scan(&committed); err != nil ||
		committed != 1 {
		return ErrArchiveDomainInvalid
	}
	return nil
}
