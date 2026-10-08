package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

// ErrProfileDeclarationGuardConflict means the accepted source snapshot,
// source revision or node overlays changed while building a declaration.
var ErrProfileDeclarationGuardConflict = errors.New("profile declaration staging guard conflict")

// CommitProfileDeclarationGuarded stages a new immutable declaration revision.
// This transaction atomically checks the source pointer and every overlay
// revision together with the declaration revision CAS. It never applies core
// configuration or updates a runtime generation.
func (s *Store) CommitProfileDeclarationGuarded(
	ctx context.Context,
	profileID string,
	snapshotID int64,
	expectedSourceRevision uint64,
	expectedOverlays []ProfileNodeOverlayState,
	expectedDeclarationRevision uint64,
	document []byte,
	source string,
) (DeclarationRevision, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return DeclarationRevision{}, err
	}
	if snapshotID <= 0 || expectedSourceRevision == 0 || expectedDeclarationRevision == 0 {
		return DeclarationRevision{}, ErrProfileDeclarationGuardConflict
	}
	if err := validateDeclarationCommit(document, source); err != nil {
		return DeclarationRevision{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeclarationRevision{}, fmt.Errorf("begin guarded profile declaration transaction: %w", err)
	}
	defer tx.Rollback()

	var sourceRevision int64
	var currentSnapshot sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT source.revision, state.current_snapshot_id
		FROM profile_sources AS source
		LEFT JOIN profile_state AS state ON state.profile_id = source.profile_id
		WHERE source.profile_id = ?
	`, profileID).Scan(&sourceRevision, &currentSnapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return DeclarationRevision{}, ErrProfileSourceNotFound
	}
	if err != nil {
		return DeclarationRevision{}, fmt.Errorf("read staged profile source guard: %w", err)
	}
	if sourceRevision <= 0 || uint64(sourceRevision) != expectedSourceRevision ||
		!currentSnapshot.Valid || currentSnapshot.Int64 != snapshotID {
		return DeclarationRevision{}, ErrProfileDeclarationGuardConflict
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT node_id, revision FROM profile_node_overlays
		WHERE profile_id = ? ORDER BY node_id
	`, profileID)
	if err != nil {
		return DeclarationRevision{}, fmt.Errorf("read staged node overlay guard: %w", err)
	}
	index := 0
	for rows.Next() {
		var nodeID string
		var revision int64
		if err := rows.Scan(&nodeID, &revision); err != nil {
			rows.Close()
			return DeclarationRevision{}, fmt.Errorf("scan staged node overlay guard: %w", err)
		}
		if index >= len(expectedOverlays) ||
			expectedOverlays[index].Overlay.NodeID != nodeID ||
			revision <= 0 || expectedOverlays[index].Revision != uint64(revision) {
			rows.Close()
			return DeclarationRevision{}, ErrProfileDeclarationGuardConflict
		}
		index++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return DeclarationRevision{}, fmt.Errorf("iterate staged node overlay guard: %w", err)
	}
	if err := rows.Close(); err != nil {
		return DeclarationRevision{}, fmt.Errorf("close staged node overlay guard: %w", err)
	}
	if index != len(expectedOverlays) {
		return DeclarationRevision{}, ErrProfileDeclarationGuardConflict
	}

	revision, err := commitDeclarationTx(ctx, tx, expectedDeclarationRevision, document, source)
	if err != nil {
		return DeclarationRevision{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeclarationRevision{}, fmt.Errorf("commit guarded profile declaration revision %d: %w", revision.Revision, err)
	}
	return revision, nil
}
