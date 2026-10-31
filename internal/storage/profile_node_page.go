package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

const (
	DefaultProfileNodePageSize = 100
	MaxProfileNodePageSize     = 200
	MaxProfileNodePageOffset   = 1000000
)

var ErrInvalidProfileNodePage = errors.New("invalid profile node page")

// ProfileNodePage excludes source keys and payload JSON: both can hold credentials.
// Its snapshot pointer, total and rows are read within one SQLite transaction.
type ProfileNodePage struct {
	SnapshotID *int64
	Total      int
	Nodes      []ProfileNodePageRow
}

type ProfileNodePageRow struct {
	NodeID          string
	SourceName      string
	OverlayRevision uint64
	Disabled        bool
	Favorite        bool
	Alias           string
	SortRank        *int64
}

func (s *Store) CurrentProfileNodePage(
	ctx context.Context,
	profileID string,
	offset, limit int,
) (ProfileNodePage, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return ProfileNodePage{}, err
	}
	if offset < 0 || offset > MaxProfileNodePageOffset ||
		limit <= 0 || limit > MaxProfileNodePageSize {
		return ProfileNodePage{}, fmt.Errorf("%w: offset must be 0..%d and limit 1..%d",
			ErrInvalidProfileNodePage, MaxProfileNodePageOffset, MaxProfileNodePageSize)
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ProfileNodePage{}, fmt.Errorf("begin profile node page read: %w", err)
	}
	defer tx.Rollback()

	page := ProfileNodePage{Nodes: make([]ProfileNodePageRow, 0)}
	var current sql.NullInt64
	err = tx.QueryRowContext(ctx,
		"SELECT current_snapshot_id FROM profile_state WHERE profile_id = ?", profileID,
	).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !current.Valid) {
		return page, nil
	}
	if err != nil {
		return ProfileNodePage{}, fmt.Errorf("read current profile snapshot: %w", err)
	}
	if current.Int64 <= 0 {
		return ProfileNodePage{}, errors.New("current profile snapshot identifier is invalid")
	}
	id := current.Int64
	page.SnapshotID = &id

	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM profile_snapshot_nodes WHERE snapshot_id = ?", id,
	).Scan(&page.Total); err != nil {
		return ProfileNodePage{}, fmt.Errorf("count current profile nodes: %w", err)
	}
	rows, err := tx.QueryContext(ctx,
		"SELECT node.node_id, node.source_name, "+
			"COALESCE(overlay.revision, 0), COALESCE(overlay.disabled, 0), "+
			"COALESCE(overlay.favorite, 0), COALESCE(overlay.alias, ''), overlay.sort_rank "+
			"FROM profile_snapshot_nodes AS node "+
			"LEFT JOIN profile_node_overlays AS overlay "+
			"ON overlay.profile_id = ? AND overlay.node_id = node.node_id "+
			"WHERE node.snapshot_id = ? ORDER BY node.ordinal LIMIT ? OFFSET ?",
		profileID, id, limit, offset,
	)
	if err != nil {
		return ProfileNodePage{}, fmt.Errorf("query current profile node page: %w", err)
	}
	for rows.Next() {
		var row ProfileNodePageRow
		var revision int64
		var disabled, favorite int
		var rank sql.NullInt64
		if err := rows.Scan(
			&row.NodeID, &row.SourceName, &revision, &disabled, &favorite,
			&row.Alias, &rank,
		); err != nil {
			rows.Close()
			return ProfileNodePage{}, fmt.Errorf("scan profile node page: %w", err)
		}
		if revision < 0 {
			rows.Close()
			return ProfileNodePage{}, errors.New("profile node overlay revision is invalid")
		}
		row.OverlayRevision = uint64(revision)
		row.Disabled = disabled != 0
		row.Favorite = favorite != 0
		if rank.Valid {
			value := rank.Int64
			row.SortRank = &value
		}
		page.Nodes = append(page.Nodes, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ProfileNodePage{}, fmt.Errorf("iterate profile node page: %w", err)
	}
	if err := rows.Close(); err != nil {
		return ProfileNodePage{}, fmt.Errorf("close profile node page rows: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ProfileNodePage{}, fmt.Errorf("finish profile node page read: %w", err)
	}
	return page, nil
}
