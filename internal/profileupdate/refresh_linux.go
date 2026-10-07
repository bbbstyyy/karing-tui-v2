//go:build linux

package profileupdate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	singboximport "github.com/bbbstyyy/karing-tui-v2/internal/importer/singbox"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/profilefetch"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrNotModifiedWithoutSnapshot = errors.New("profile source returned not modified without an accepted snapshot")

type Fetcher interface {
	Fetch(
		context.Context,
		profile.SourceSpec,
		profilefetch.ConditionalRequest,
	) (profilefetch.Result, error)
}

type RefreshResult struct {
	SourceBefore storage.ProfileSourceState
	SourceAfter  storage.ProfileSourceState
	Lease        storage.ProfileUpdateLease
	Fetch        profilefetch.Result
	Analysis     singboximport.ProfileAnalysis
	Commit       storage.ProfileSnapshotCommit
	Nodes        []domain.Node
	NotModified  bool
}

func RefreshProfileSource(
	ctx context.Context,
	store *storage.Store,
	fetcher Fetcher,
	profileID string,
	expectedSourceRevision uint64,
	updateID string,
	options Options,
) (RefreshResult, error) {
	if store == nil {
		return RefreshResult{}, errors.New("profile store is nil")
	}
	if fetcher == nil {
		return RefreshResult{}, errors.New("profile fetcher is nil")
	}

	source, err := store.ProfileSource(ctx, profileID)
	if err != nil {
		return RefreshResult{}, err
	}
	result := RefreshResult{SourceBefore: source}

	lease, err := store.BeginProfileUpdate(ctx, profileID, expectedSourceRevision, updateID)
	if err != nil {
		return result, err
	}
	result.Lease = lease

	fetched, err := fetcher.Fetch(ctx, source.Spec, profilefetch.ConditionalRequest{
		ETag:         source.ETag,
		LastModified: source.LastModified,
	})
	result.Fetch = fetched
	if err != nil {
		return result, finishRefreshFailure(ctx, store, lease, err)
	}

	if fetched.NotModified {
		if source.CurrentSnapshotID == nil {
			return result, finishRefreshFailure(ctx, store, lease, ErrNotModifiedWithoutSnapshot)
		}
		sourceRevision := source.LastSourceRevision
		if sourceRevision == "" {
			snapshot, snapshotErr := store.ProfileSnapshotByID(
				ctx,
				profileID,
				*source.CurrentSnapshotID,
			)
			if snapshotErr != nil {
				return result, finishRefreshFailure(ctx, store, lease, snapshotErr)
			}
			sourceRevision = snapshot.SourceRevision
		}
		if err := store.FinishProfileUpdateSuccess(ctx, lease, storage.ProfileUpdateSuccess{
			SourceRevision: sourceRevision,
			ETag:           fetched.ETag,
			LastModified:   fetched.LastModified,
		}); err != nil {
			return result, err
		}
		result.NotModified = true
		result.SourceAfter, err = store.ProfileSource(ctx, profileID)
		if err != nil {
			return result, err
		}
		return result, nil
	}

	switch source.Spec.Format {
	case profile.SourceFormatSingBox:
		analysis, analyzeErr := singboximport.AnalyzeBasicProfile(fetched.Body, profileID)
		result.Analysis = analysis
		if analyzeErr != nil {
			return result, finishRefreshFailure(ctx, store, lease, analyzeErr)
		}
		if analysis.HasBlockingDiagnostics() {
			return result, finishRefreshFailure(ctx, store, lease, ErrImportBlocked)
		}

		sourceRevision := refreshSourceRevision(fetched, analysis.SourceSHA256)
		sourceNodes := make([]profile.SourceNode, 0, len(analysis.Nodes))
		for _, node := range analysis.Nodes {
			item := node.Source
			item.PayloadJSON = append([]byte(nil), item.PayloadJSON...)
			sourceNodes = append(sourceNodes, item)
		}
		commit, commitErr := store.CommitProfileUpdateSnapshot(
			ctx,
			lease,
			storage.ProfileSnapshotCandidate{
				ProfileID:      profileID,
				SourceKind:     string(source.Spec.Format),
				SourceRevision: sourceRevision,
				SourceSHA256:   analysis.SourceSHA256,
				Nodes:          sourceNodes,
			},
			storage.ProfileSnapshotCommitOptions{AllowEmpty: options.AllowEmpty},
			storage.ProfileUpdateSuccess{
				SourceRevision: sourceRevision,
				ETag:           fetched.ETag,
				LastModified:   fetched.LastModified,
			},
		)
		result.Commit = commit
		if commitErr != nil {
			return result, finishRefreshFailure(ctx, store, lease, commitErr)
		}

		nodes, materializeErr := MaterializeBasicSingBoxSnapshot(commit.Snapshot)
		if materializeErr != nil {
			return result, materializeErr
		}
		result.Nodes = nodes
	default:
		return result, finishRefreshFailure(
			ctx,
			store,
			lease,
			fmt.Errorf("unsupported profile source format %q", source.Spec.Format),
		)
	}

	result.SourceAfter, err = store.ProfileSource(ctx, profileID)
	if err != nil {
		return result, err
	}
	return result, nil
}

func refreshSourceRevision(fetched profilefetch.Result, sourceSHA256 string) string {
	switch {
	case fetched.ETag != "":
		return "etag:" + fetched.ETag
	case fetched.LastModified != "":
		return "last-modified:" + fetched.LastModified
	default:
		return "sha256:" + sourceSHA256
	}
}

func finishRefreshFailure(
	ctx context.Context,
	store *storage.Store,
	lease storage.ProfileUpdateLease,
	cause error,
) error {
	retryAfter := retryAfterFromError(cause)
	status := safeRefreshFailure(cause)
	if err := store.FinishProfileUpdateFailure(ctx, lease, status, retryAfter); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func retryAfterFromError(err error) *time.Time {
	var statusErr *profilefetch.HTTPStatusError
	if !errors.As(err, &statusErr) {
		return nil
	}
	return statusErr.RetryAfter
}

func safeRefreshFailure(err error) string {
	if err == nil {
		return "profile update failed"
	}
	value := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, err.Error())
	value = strings.TrimSpace(value)
	if value == "" {
		value = "profile update failed"
	}
	const limit = 2048
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
