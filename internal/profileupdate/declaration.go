package profileupdate

import (
	"context"
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrNoBaseDeclaration = errors.New("profile snapshot update requires an existing declaration")

type DeclarationSnapshotResult struct {
	Snapshot    storage.ProfileSnapshot
	Replacement declaration.ProfileNodeReplacement
	Revision    storage.DeclarationRevision
}

func CommitSingBoxSnapshotToDeclaration(
	ctx context.Context,
	store *storage.Store,
	profileID string,
	snapshotID int64,
	expectedDeclarationRevision uint64,
) (DeclarationSnapshotResult, error) {
	if store == nil {
		return DeclarationSnapshotResult{}, errors.New("profile snapshot store is nil")
	}
	snapshot, err := store.ProfileSnapshotByID(ctx, profileID, snapshotID)
	if err != nil {
		return DeclarationSnapshotResult{}, err
	}
	result := DeclarationSnapshotResult{Snapshot: snapshot}

	nodes, err := MaterializeBasicSingBoxSnapshot(snapshot)
	if err != nil {
		return result, err
	}

	if expectedDeclarationRevision == 0 {
		return result, ErrNoBaseDeclaration
	}
	base, err := store.Declaration(ctx, expectedDeclarationRevision)
	if err != nil {
		return result, err
	}
	if len(base.DocumentJSON) == 0 {
		return result, ErrNoBaseDeclaration
	}

	replacement, err := declaration.ReplaceProfileNodesV1(base.DocumentJSON, profileID, nodes)
	result.Replacement = replacement
	if err != nil {
		return result, err
	}

	revision, err := store.CommitDeclaration(
		ctx,
		expectedDeclarationRevision,
		replacement.Document,
		fmt.Sprintf("profile-snapshot/%d", snapshotID),
	)
	if err != nil {
		return result, err
	}
	result.Revision = revision
	return result, nil
}
