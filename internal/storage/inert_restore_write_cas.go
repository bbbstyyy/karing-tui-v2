package storage

import (
	"context"
	"errors"
	"time"
)

// InertRestoreWriteCAS is an internal-only, non-persisting write-intent
// precondition check. It obtains SQLite's single-writer reservation using
// a guarded no-change UPDATE, revalidates the entire live fence under that
// same transaction, then MUST ROLLBACK. A successful return is NOT a
// restore permit: no reservation survives Rollback or process death.
const inertRestoreWriteCASDeadline = 4 * time.Second

var ErrInertRestoreWriteCASUnavailable = errors.New("inert restore write-intent precondition unavailable")

// CheckInertRestoreWriteCAS narrows the read-to-write race at this one
// instant, but does not close a later apply race. An eventual restore writer
// must repeat the CAS inside the SAME transaction as its durable changes,
// under the daemon operation gate, with verified resource leases.
func (s *Store) CheckInertRestoreWriteCAS(
	ctx context.Context, expected InertRestoreFence,
) error {
	return s.checkInertRestoreWriteCAS(ctx, expected, nil)
}

// afterLock is intentionally unexported fault injection. It runs with the
// SQLite writer reservation acquired; it MUST NOT call back into this Store
// or perform blocking file/network/core work in production paths.
func (s *Store) checkInertRestoreWriteCAS(
	ctx context.Context, expected InertRestoreFence,
	afterLock func() error,
) error {
	if s == nil || s.db == nil || ctx == nil || !validInertRestoreFence(expected) {
		return ErrInertRestoreWriteCASUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, inertRestoreWriteCASDeadline)
	defer cancel()

	tx, err := s.db.BeginTx(bounded, nil)
	if err != nil {
		return ErrInertRestoreWriteCASUnavailable
	}
	defer tx.Rollback()

	// SQLite starts a RESERVED WAL writer transaction even though the
	// predicate sets the existing value to itself. Nothing is committed.
	// Bind state columns and the active apply/recovery guards in the SAME
	// statement that establishes write intent, not in an earlier read.
	res, err := tx.ExecContext(bounded, `
		UPDATE daemon_state SET config_revision = config_revision
		WHERE singleton = 1
			AND config_revision = ?
			AND applied_generation_id = ?
			AND last_known_good_generation_id = ?
			AND recovery_required = 0
			AND core_desired_state = ?
			AND routing_mode = ?
			AND private_direct = ?
			AND NOT EXISTS(
				SELECT 1 FROM apply_journal WHERE active_slot = 1
			)
			AND EXISTS(
				SELECT 1 FROM declaration_state ds
				JOIN declaration_revisions dr ON dr.revision = ds.current_revision
				WHERE ds.singleton = 1 AND ds.current_revision = ?
					AND dr.document_sha256 = ?
			)
			AND EXISTS(
				SELECT 1 FROM selection_state ss
				WHERE ss.singleton = 1 AND ss.revision = ?
			)
	`,
		int64(expected.ConfigRevision),
		expected.AppliedGenerationID,
		expected.LastKnownGoodGenerationID,
		expected.CoreDesiredState,
		expected.RoutingMode,
		boolToIntInertFence(expected.PrivateDirect),
		int64(expected.DeclarationRevision),
		expected.DeclarationSHA256,
		int64(expected.SelectionRevision),
	)
	if err != nil {
		return ErrInertRestoreWriteCASUnavailable
	}
	changed, err := res.RowsAffected()
	if err != nil || changed < 0 || changed > 1 {
		return ErrInertRestoreWriteCASUnavailable
	}
	if changed != 1 {
		return ErrInertRestoreFenceChanged
	}
	// Every content digest, selection JSON hash and historical generation
	// identity is checked *after* acquiring the SQLite write reservation.
	fresh, err := readInertRestoreFenceTx(bounded, tx)
	if err != nil {
		return ErrInertRestoreWriteCASUnavailable
	}
	if fresh != expected {
		return ErrInertRestoreFenceChanged
	}
	if afterLock != nil {
		if err := afterLock(); err != nil {
			return ErrInertRestoreWriteCASUnavailable
		}
	}
	if err := bounded.Err(); err != nil {
		return err
	}
	// Rollback is checked explicitly. No success, journal or receipt is
	// returned if SQLite cannot verify that the transaction was closed.
	if err := tx.Rollback(); err != nil {
		return ErrInertRestoreWriteCASUnavailable
	}
	return nil
}

func boolToIntInertFence(value bool) int {
	if value {
		return 1
	}
	return 0
}
