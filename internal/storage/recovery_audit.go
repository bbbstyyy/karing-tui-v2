package storage

import (
	"context"
	"fmt"
)

const MaxConfirmedGenerationAudit = 16

// ConfirmedGenerationRef describes only immutable successful apply history.
// An audit reference does not authorize a restore, even when its payload
// remains retained; generation files may be pruned or become unavailable.
type ConfirmedGenerationRef struct {
	GenerationID         int64
	TargetConfigRevision uint64
	PayloadRetained      bool
}

// ConfirmedGenerationRefs merges compact archived history with unarchived
// journal rows. Failed/prepared generations are never offered as candidates.
// A LIMIT+1 bound makes truncation explicit without loading any private JSON.
func (s *Store) ConfirmedGenerationRefs(ctx context.Context, limit int) ([]ConfirmedGenerationRef, bool, error) {
	if s == nil || limit < 1 || limit > MaxConfirmedGenerationAudit {
		return nil, false, fmt.Errorf("invalid confirmed generation audit limit")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT history.generation_id, history.target_revision,
		       EXISTS(SELECT 1 FROM generations g WHERE g.id = history.generation_id)
		FROM (
			SELECT generation_id, MAX(target_revision) AS target_revision
			FROM (
				SELECT generation_id, target_revision FROM apply_journal WHERE phase = 'committed'
				UNION ALL
				SELECT generation_id, target_revision FROM apply_history WHERE phase = 'committed'
			)
			WHERE generation_id > 0 AND target_revision > 0
			GROUP BY generation_id
		) history
		ORDER BY history.target_revision DESC, history.generation_id DESC
		LIMIT ?
	`, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("query confirmed generation references: %w", err)
	}
	defer rows.Close()
	result := make([]ConfirmedGenerationRef, 0, limit)
	truncated := false
	for rows.Next() {
		var id, rev int64
		var retained int
		if err := rows.Scan(&id, &rev, &retained); err != nil {
			return nil, false, fmt.Errorf("scan confirmed generation reference: %w", err)
		}
		if len(result) == limit {
			truncated = true
			break
		}
		result = append(result, ConfirmedGenerationRef{
			GenerationID: id, TargetConfigRevision: uint64(rev), PayloadRetained: retained == 1,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate confirmed generation references: %w", err)
	}
	return result, truncated, nil
}
