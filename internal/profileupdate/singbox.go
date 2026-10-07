package profileupdate

import (
	"context"
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	singboximport "github.com/bbbstyyy/karing-tui-v2/internal/importer/singbox"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrImportBlocked = errors.New("profile import is blocked by compatibility diagnostics")

type Options struct {
	AllowEmpty bool
}

type SingBoxCommitResult struct {
	Analysis singboximport.ProfileAnalysis
	Commit   storage.ProfileSnapshotCommit
	Nodes    []domain.Node
}

func CommitBasicSingBoxProfile(
	ctx context.Context,
	store *storage.Store,
	profileID string,
	sourceRevision string,
	data []byte,
	options Options,
) (SingBoxCommitResult, error) {
	if store == nil {
		return SingBoxCommitResult{}, errors.New("profile snapshot store is nil")
	}
	analysis, err := singboximport.AnalyzeBasicProfile(data, profileID)
	if err != nil {
		return SingBoxCommitResult{}, err
	}
	result := SingBoxCommitResult{Analysis: analysis}
	if analysis.HasBlockingDiagnostics() {
		return result, ErrImportBlocked
	}

	sourceNodes := make([]profile.SourceNode, 0, len(analysis.Nodes))
	for _, node := range analysis.Nodes {
		source := node.Source
		source.PayloadJSON = append([]byte(nil), source.PayloadJSON...)
		sourceNodes = append(sourceNodes, source)
	}

	commit, err := store.CommitProfileSnapshot(ctx, storage.ProfileSnapshotCandidate{
		ProfileID:      profileID,
		SourceKind:     "sing-box",
		SourceRevision: sourceRevision,
		SourceSHA256:   analysis.SourceSHA256,
		Nodes:          sourceNodes,
	}, storage.ProfileSnapshotCommitOptions{AllowEmpty: options.AllowEmpty})
	if err != nil {
		return result, err
	}
	result.Commit = commit

	nodes, err := MaterializeBasicSingBoxSnapshot(commit.Snapshot)
	if err != nil {
		return result, fmt.Errorf("materialize committed sing-box snapshot: %w", err)
	}
	result.Nodes = nodes
	return result, nil
}

func MaterializeBasicSingBoxSnapshot(snapshot storage.ProfileSnapshot) ([]domain.Node, error) {
	if snapshot.SourceKind != "sing-box" {
		return nil, fmt.Errorf("profile snapshot source kind %q is not sing-box", snapshot.SourceKind)
	}
	nodes := make([]domain.Node, 0, len(snapshot.Nodes))
	for index, stored := range snapshot.Nodes {
		node, err := singboximport.DecodeBasicNode(stored.PayloadJSON, stored.Identity)
		if err != nil {
			return nil, fmt.Errorf("snapshot node %d %q: %w", index, stored.Identity.SourceKey, err)
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}
