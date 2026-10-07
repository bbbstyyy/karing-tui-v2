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

var ErrInvalidSelectionIntent = errors.New("invalid current selection intent")

type SelectionIntent struct {
	TargetJSON []byte
	UpdatedAt  time.Time
}

func (s *Store) CurrentSelectionIntent(ctx context.Context) (SelectionIntent, bool, error) {
	var (
		target    []byte
		updatedAt sql.NullString
	)
	if err := s.db.QueryRowContext(ctx, `
		SELECT current_target_json, updated_at
		FROM selection_state
		WHERE singleton = 1
	`).Scan(&target, &updatedAt); err != nil {
		return SelectionIntent{}, false, fmt.Errorf("read current selection intent: %w", err)
	}
	if len(target) == 0 {
		return SelectionIntent{}, false, nil
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
	}, true, nil
}

func (s *Store) SetCurrentSelectionIntent(ctx context.Context, target []byte) (SelectionIntent, error) {
	if len(target) == 0 || !json.Valid(target) {
		return SelectionIntent{}, ErrInvalidSelectionIntent
	}
	if len(target) > MaxSelectionTargetBytes {
		return SelectionIntent{}, fmt.Errorf("%w: %d bytes > %d bytes", ErrInvalidSelectionIntent, len(target), MaxSelectionTargetBytes)
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE selection_state
		SET current_target_json = ?, updated_at = ?
		WHERE singleton = 1
	`, target, now.Format(time.RFC3339Nano))
	if err != nil {
		return SelectionIntent{}, fmt.Errorf("persist current selection intent: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return SelectionIntent{}, fmt.Errorf("read current selection update result: %w", err)
	}
	if affected != 1 {
		return SelectionIntent{}, fmt.Errorf("persist current selection intent: updated %d rows", affected)
	}
	return SelectionIntent{
		TargetJSON: append([]byte(nil), target...),
		UpdatedAt:  now,
	}, nil
}
