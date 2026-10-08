package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

const MaxProfileNodeOverlaysPerProfile = 8192

var (
	ErrProfileNodeOverlayNotFound         = errors.New("profile node overlay not found")
	ErrProfileNodeOverlayRevisionConflict = errors.New("profile node overlay revision conflict")
	ErrProfileNodeOverlayLimit            = errors.New("profile node overlay limit reached")
	ErrProfileNodeOverlayNodeUnavailable  = errors.New("profile node is not present in the current accepted snapshot")
)

type ProfileNodeOverlayState struct {
	Revision  uint64
	Overlay   profile.NodeOverlay
	UpdatedAt time.Time
}

func (s *Store) CommitProfileNodeOverlay(
	ctx context.Context,
	expectedRevision uint64,
	overlay profile.NodeOverlay,
) (ProfileNodeOverlayState, error) {
	if err := overlay.Validate(); err != nil {
		return ProfileNodeOverlayState{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProfileNodeOverlayState{}, fmt.Errorf("begin profile node overlay transaction: %w", err)
	}
	defer tx.Rollback()

	exists, err := currentProfileNodeExistsTx(ctx, tx, overlay.ProfileID, overlay.NodeID)
	if err != nil {
		return ProfileNodeOverlayState{}, err
	}
	if !exists {
		return ProfileNodeOverlayState{}, ErrProfileNodeOverlayNodeUnavailable
	}

	var currentRevision int64
	err = tx.QueryRowContext(ctx, `
		SELECT revision
		FROM profile_node_overlays
		WHERE profile_id = ? AND node_id = ?
	`, overlay.ProfileID, overlay.NodeID).Scan(&currentRevision)

	now := time.Now().UTC()
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if expectedRevision != 0 {
			return ProfileNodeOverlayState{}, fmt.Errorf(
				"%w: expected %d, current 0",
				ErrProfileNodeOverlayRevisionConflict,
				expectedRevision,
			)
		}
		var count int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM profile_node_overlays
			WHERE profile_id = ?
		`, overlay.ProfileID).Scan(&count); err != nil {
			return ProfileNodeOverlayState{}, fmt.Errorf("count profile node overlays: %w", err)
		}
		if count >= MaxProfileNodeOverlaysPerProfile {
			return ProfileNodeOverlayState{}, fmt.Errorf(
				"%w: profile %q already has %d overlay rows",
				ErrProfileNodeOverlayLimit,
				overlay.ProfileID,
				count,
			)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO profile_node_overlays(
				profile_id,
				node_id,
				revision,
				disabled,
				favorite,
				alias,
				sort_rank,
				updated_at
			)
			VALUES(?, ?, 1, ?, ?, ?, ?, ?)
		`,
			overlay.ProfileID,
			overlay.NodeID,
			boolInt(overlay.Disabled),
			boolInt(overlay.Favorite),
			overlay.Alias,
			nullableOverlaySortRank(overlay.SortRank),
			now.Format(time.RFC3339Nano),
		); err != nil {
			return ProfileNodeOverlayState{}, fmt.Errorf("insert profile node overlay: %w", err)
		}
	case err != nil:
		return ProfileNodeOverlayState{}, fmt.Errorf("read profile node overlay before commit: %w", err)
	default:
		if currentRevision <= 0 || uint64(currentRevision) != expectedRevision {
			return ProfileNodeOverlayState{}, fmt.Errorf(
				"%w: expected %d, current %d",
				ErrProfileNodeOverlayRevisionConflict,
				expectedRevision,
				currentRevision,
			)
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE profile_node_overlays
			SET revision = revision + 1,
				disabled = ?,
				favorite = ?,
				alias = ?,
				sort_rank = ?,
				updated_at = ?
			WHERE profile_id = ?
			  AND node_id = ?
			  AND revision = ?
		`,
			boolInt(overlay.Disabled),
			boolInt(overlay.Favorite),
			overlay.Alias,
			nullableOverlaySortRank(overlay.SortRank),
			now.Format(time.RFC3339Nano),
			overlay.ProfileID,
			overlay.NodeID,
			currentRevision,
		)
		if err != nil {
			return ProfileNodeOverlayState{}, fmt.Errorf("update profile node overlay: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return ProfileNodeOverlayState{}, fmt.Errorf("read profile node overlay update result: %w", err)
		}
		if affected != 1 {
			return ProfileNodeOverlayState{}, ErrProfileNodeOverlayRevisionConflict
		}
	}

	if err := tx.Commit(); err != nil {
		return ProfileNodeOverlayState{}, fmt.Errorf("commit profile node overlay: %w", err)
	}
	return s.ProfileNodeOverlay(ctx, overlay.ProfileID, overlay.NodeID)
}

func (s *Store) ProfileNodeOverlay(
	ctx context.Context,
	profileID string,
	nodeID string,
) (ProfileNodeOverlayState, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return ProfileNodeOverlayState{}, err
	}
	if err := profile.ValidateNodeID(nodeID); err != nil {
		return ProfileNodeOverlayState{}, err
	}
	row := s.db.QueryRowContext(ctx, profileNodeOverlaySelect+`
		WHERE profile_id = ? AND node_id = ?
	`, profileID, nodeID)
	return scanProfileNodeOverlay(row)
}

func (s *Store) ProfileNodeOverlays(
	ctx context.Context,
	profileID string,
) ([]ProfileNodeOverlayState, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, profileNodeOverlaySelect+`
		WHERE profile_id = ?
		ORDER BY node_id
	`, profileID)
	if err != nil {
		return nil, fmt.Errorf("list profile node overlays: %w", err)
	}
	defer rows.Close()

	var result []ProfileNodeOverlayState
	for rows.Next() {
		item, err := scanProfileNodeOverlay(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate profile node overlays: %w", err)
	}
	return result, nil
}

const profileNodeOverlaySelect = `
	SELECT
		revision,
		profile_id,
		node_id,
		disabled,
		favorite,
		alias,
		sort_rank,
		updated_at
	FROM profile_node_overlays
`

func scanProfileNodeOverlay(row scanner) (ProfileNodeOverlayState, error) {
	var (
		state     ProfileNodeOverlayState
		revision  int64
		disabled  int
		favorite  int
		sortRank  sql.NullInt64
		updatedAt string
	)
	if err := row.Scan(
		&revision,
		&state.Overlay.ProfileID,
		&state.Overlay.NodeID,
		&disabled,
		&favorite,
		&state.Overlay.Alias,
		&sortRank,
		&updatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProfileNodeOverlayState{}, ErrProfileNodeOverlayNotFound
		}
		return ProfileNodeOverlayState{}, fmt.Errorf("read profile node overlay: %w", err)
	}
	if revision <= 0 {
		return ProfileNodeOverlayState{}, errors.New("profile node overlay contains invalid revision")
	}
	state.Revision = uint64(revision)
	state.Overlay.Disabled = disabled != 0
	state.Overlay.Favorite = favorite != 0
	state.Overlay.SortRank = nullInt64ValuePtr(sortRank)
	parsed, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return ProfileNodeOverlayState{}, fmt.Errorf("parse profile node overlay updated_at: %w", err)
	}
	state.UpdatedAt = parsed
	if err := state.Overlay.Validate(); err != nil {
		return ProfileNodeOverlayState{}, fmt.Errorf("validate persisted profile node overlay: %w", err)
	}
	return state, nil
}

func currentProfileNodeExistsTx(
	ctx context.Context,
	tx *sql.Tx,
	profileID string,
	nodeID string,
) (bool, error) {
	var exists int
	err := tx.QueryRowContext(ctx, `
		SELECT 1
		FROM profile_state state
		JOIN profile_snapshot_nodes node
		  ON node.snapshot_id = state.current_snapshot_id
		WHERE state.profile_id = ?
		  AND node.node_id = ?
		LIMIT 1
	`, profileID, nodeID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("verify current profile node for overlay: %w", err)
	}
	return true, nil
}

func nullableOverlaySortRank(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}
