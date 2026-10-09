package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const MaxSelectionTargetBytes = 4096

var (
	ErrInvalidSelectionIntent = errors.New("invalid current selection intent")
	ErrSelectionRevisionConflict = errors.New("current selection CAS conflict")
)

// SelectionPrecondition binds the requested selection revision to a precise
// configuration snapshot. Nil generation requires a matching current
// declaration revision. A non-nil generation is immutable and already bound
// to a declaration by the verified manifest in the coordinator.
type SelectionPrecondition struct {
	Revision            uint64
	ConfigRevision      uint64
	AppliedGenerationID *int64
	DeclarationRevision uint64
}

type SelectionIntent struct {
	TargetJSON []byte
	UpdatedAt  time.Time
	Revision   uint64
}

func (s *Store) CurrentSelectionIntent(ctx context.Context) (SelectionIntent, bool, error) {
	var (
		target    []byte
		updatedAt sql.NullString
		revision  int64
	)
	if err := s.db.QueryRowContext(ctx, `
		SELECT current_target_json, updated_at, revision
		FROM selection_state
		WHERE singleton = 1
	`).Scan(&target, &updatedAt, &revision); err != nil {
		return SelectionIntent{}, false, fmt.Errorf("read current selection intent: %w", err)
	}
	if revision < 0 {
		return SelectionIntent{}, false, ErrInvalidSelectionIntent
	}
	if len(target) == 0 {
		return SelectionIntent{Revision: uint64(revision)}, false, nil
	}
	if !json.Valid(target) {
		return SelectionIntent{}, false, fmt.Errorf("%w: persisted target is not valid JSON", ErrInvalidSelectionIntent)
	}
	if !updatedAt.Valid || updatedAt.String == "" {
		return SelectionIntent{}, false, fmt.Errorf("%w: persisted target has no timestamp", ErrInvalidSelectionIntent)
	}
	parsed, err := time.Parse(time.RFC3339Nano, updatedAt.String)
	if err != nil {
		return SelectionIntent{}, false, fmt.Errorf("parse current selection timestamp: %w", err)
	}
	return SelectionIntent{
		TargetJSON: append([]byte(nil), target...),
		UpdatedAt:  parsed,
		Revision:   uint64(revision),
	}, true, nil
}

func validateSelectionTargetJSON(target []byte) error {
	if len(target) == 0 || !json.Valid(target) {
		return ErrInvalidSelectionIntent
	}
	if len(target) > MaxSelectionTargetBytes {
		return fmt.Errorf("%w: target exceeds %d bytes", ErrInvalidSelectionIntent, MaxSelectionTargetBytes)
	}
	return nil
}

// Legacy, intentionally unconditional clients still increment the same
// selection revision, invalidating any stale guarded read/confirm operation.
func (s *Store) SetCurrentSelectionIntent(ctx context.Context, target []byte) (SelectionIntent, error) {
	if err := validateSelectionTargetJSON(target); err != nil {
		return SelectionIntent{}, err
	}
	now := time.Now().UTC()
	var revision int64
	err := s.db.QueryRowContext(ctx, `
		UPDATE selection_state
		SET current_target_json = ?, updated_at = ?, revision = revision + 1
		WHERE singleton = 1 AND revision < 9223372036854775807
		RETURNING revision
	`, target, now.Format(time.RFC3339Nano)).Scan(&revision)
	if err != nil {
		return SelectionIntent{}, fmt.Errorf("persist current selection intent: %w", err)
	}
	return SelectionIntent{
		TargetJSON: append([]byte(nil), target...),
		UpdatedAt:  now,
		Revision:   uint64(revision),
	}, nil
}

// SetCurrentSelectionIntentChecked uses a single SQLite UPDATE with atomic
// predicates. It is impossible for a concurrently committed legacy write,
// applied-generation switch or current-declaration update to pass stale CAS.
// No network I/O is performed in the write; live core reconciliation is done
// after the atomic commit by the daemon coordinator.
func (s *Store) SetCurrentSelectionIntentChecked(
	ctx context.Context, target []byte, expected SelectionPrecondition,
) (SelectionIntent, error) {
	if err := validateSelectionTargetJSON(target); err != nil {
		return SelectionIntent{}, err
	}
	if expected.DeclarationRevision == 0 || expected.Revision >= 9223372036854775807 {
		return SelectionIntent{}, ErrInvalidSelectionIntent
	}
	var generation any
	if expected.AppliedGenerationID != nil {
		if *expected.AppliedGenerationID <= 0 {
			return SelectionIntent{}, ErrInvalidSelectionIntent
		}
		generation = *expected.AppliedGenerationID
	}
	now := time.Now().UTC()
	var revision int64
	err := s.db.QueryRowContext(ctx, `
		UPDATE selection_state
		SET current_target_json = ?, updated_at = ?, revision = revision + 1
		WHERE singleton = 1 AND revision = ?
		  AND EXISTS (
			SELECT 1 FROM daemon_state AS d
			WHERE d.singleton = 1
			  AND d.config_revision = ?
			  AND d.applied_generation_id IS ?
			  AND d.recovery_required = 0
			  AND NOT EXISTS (SELECT 1 FROM apply_journal WHERE active_slot = 1)
		  )
		  AND (? IS NOT NULL OR EXISTS (
			SELECT 1 FROM declaration_state AS ds
			WHERE ds.singleton = 1 AND ds.current_revision = ?
		  ))
		RETURNING revision
	`, target, now.Format(time.RFC3339Nano), expected.Revision,
		expected.ConfigRevision, generation, generation, expected.DeclarationRevision).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return SelectionIntent{}, ErrSelectionRevisionConflict
	}
	if err != nil {
		return SelectionIntent{}, fmt.Errorf("persist checked current selection intent: %w", err)
	}
	return SelectionIntent{
		TargetJSON: append([]byte(nil), target...),
		UpdatedAt:  now,
		Revision:   uint64(revision),
	}, nil
}
