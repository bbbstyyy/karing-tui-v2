//go:build linux

package profileupdate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/profilefetch"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type MetadataFetcher interface {
	FetchMetadata(context.Context, profile.SourceSpec) (profilefetch.MetadataResult, error)
}

type MetadataRefreshResult struct {
	SourceBefore storage.ProfileSourceState
	SourceAfter  storage.ProfileSourceState
	Fetch        profilefetch.MetadataResult
	ObservedAt   time.Time
	Applied      bool
}

func RefreshProfileSourceMetadata(
	ctx context.Context,
	store *storage.Store,
	fetcher MetadataFetcher,
	profileID string,
	expectedSourceRevision uint64,
) (MetadataRefreshResult, error) {
	if store == nil {
		return MetadataRefreshResult{}, errors.New("profile metadata store is nil")
	}
	if fetcher == nil {
		return MetadataRefreshResult{}, errors.New("profile metadata fetcher is nil")
	}

	result := MetadataRefreshResult{}
	source, err := store.ProfileSource(ctx, profileID)
	if err != nil {
		return result, err
	}
	result.SourceBefore = source
	if source.Revision != expectedSourceRevision {
		return result, fmt.Errorf(
			"%w: expected %d, current %d",
			storage.ErrProfileSourceRevisionConflict,
			expectedSourceRevision,
			source.Revision,
		)
	}
	if !source.Spec.Enabled {
		return result, storage.ErrProfileSourceDisabled
	}
	if source.ActiveUpdateID != "" {
		return result, fmt.Errorf(
			"%w: %s",
			storage.ErrProfileUpdateInProgress,
			source.ActiveUpdateID,
		)
	}

	// Record the request-start instant. A HEAD response that returns after a
	// newer full refresh must not overwrite that refresh's metadata.
	result.ObservedAt = time.Now().UTC()
	fetched, err := fetcher.FetchMetadata(ctx, source.Spec)
	result.Fetch = fetched
	if err != nil {
		return result, err
	}

	applied, err := store.CommitProfileSubscriptionMetadata(
		ctx,
		profileID,
		expectedSourceRevision,
		result.ObservedAt,
		fetched.UsageMetadataObserved,
		fetched.SubscriptionUsage,
		fetched.UsageMetadataError,
	)
	if err != nil {
		return result, err
	}
	result.Applied = applied
	result.SourceAfter, err = store.ProfileSource(ctx, profileID)
	if err != nil {
		return result, err
	}
	return result, nil
}
