//go:build linux

package profileupdate

import (
	"context"
	"errors"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/profilefetch"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type metadataFetcherFunc func(context.Context, profile.SourceSpec) (profilefetch.MetadataResult, error)

func (f metadataFetcherFunc) FetchMetadata(
	ctx context.Context,
	spec profile.SourceSpec,
) (profilefetch.MetadataResult, error) {
	return f(ctx, spec)
}

func TestRefreshProfileSourceMetadataPersistsUsageWithoutTouchingRefreshHealth(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(ctx, 0, profile.SourceSpec{
		ProfileID:    "profile-a",
		Format:       profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationURL,
		Location:     "https://example.com/subscription",
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	upload := int64(11)
	download := int64(22)
	total := int64(100)
	fetcher := metadataFetcherFunc(func(_ context.Context, spec profile.SourceSpec) (profilefetch.MetadataResult, error) {
		if spec.ProfileID != "profile-a" {
			t.Fatalf("metadata source = %+v", spec)
		}
		return profilefetch.MetadataResult{
			SubscriptionUsage:     &profile.SubscriptionUsage{
				UploadBytes:   &upload,
				DownloadBytes: &download,
				TotalBytes:    &total,
			},
			UsageMetadataObserved: true,
		}, nil
	})

	result, err := RefreshProfileSourceMetadata(
		ctx,
		store,
		fetcher,
		"profile-a",
		source.Revision,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied ||
		result.ObservedAt.IsZero() ||
		result.SourceAfter.SubscriptionUsage == nil ||
		result.SourceAfter.SubscriptionUsage.TotalBytes == nil ||
		*result.SourceAfter.SubscriptionUsage.TotalBytes != total ||
		result.SourceAfter.SubscriptionMetadataObservedAt == nil ||
		result.SourceAfter.LastAttemptAt != nil ||
		result.SourceAfter.LastSuccessAt != nil ||
		result.SourceAfter.ConsecutiveFailures != 0 {
		t.Fatalf("metadata refresh result = %+v", result)
	}

	malformed := metadataFetcherFunc(func(context.Context, profile.SourceSpec) (profilefetch.MetadataResult, error) {
		return profilefetch.MetadataResult{
			UsageMetadataObserved: true,
			UsageMetadataError:    "invalid Subscription-Userinfo metadata",
		}, nil
	})
	second, err := RefreshProfileSourceMetadata(
		ctx,
		store,
		malformed,
		"profile-a",
		source.Revision,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Applied ||
		second.SourceAfter.SubscriptionUsage == nil ||
		second.SourceAfter.SubscriptionUsage.TotalBytes == nil ||
		*second.SourceAfter.SubscriptionUsage.TotalBytes != total ||
		second.SourceAfter.LastMetadataError == "" ||
		second.SourceAfter.ConsecutiveFailures != 0 {
		t.Fatalf("malformed metadata result = %+v", second)
	}
}

func TestRefreshProfileSourceMetadataNetworkFailureDoesNotChangeSourceHealth(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(ctx, 0, profile.SourceSpec{
		ProfileID:    "profile-a",
		Format:       profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationURL,
		Location:     "https://example.com/subscription",
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	fetcher := metadataFetcherFunc(func(context.Context, profile.SourceSpec) (profilefetch.MetadataResult, error) {
		return profilefetch.MetadataResult{}, profilefetch.ErrFetchNetwork
	})
	_, err = RefreshProfileSourceMetadata(
		ctx,
		store,
		fetcher,
		"profile-a",
		source.Revision,
	)
	if !errors.Is(err, profilefetch.ErrFetchNetwork) {
		t.Fatalf("metadata fetch error = %v", err)
	}
	after, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if after.LastAttemptAt != nil ||
		after.LastSuccessAt != nil ||
		after.ConsecutiveFailures != 0 ||
		after.SubscriptionMetadataObservedAt != nil {
		t.Fatalf("metadata network failure changed refresh health: %+v", after)
	}
}

func TestRefreshProfileSourceMetadataFailsClosedOnSourceRevisionChange(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(ctx, 0, profile.SourceSpec{
		ProfileID:    "profile-a",
		Format:       profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationURL,
		Location:     "https://example.com/subscription",
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	total := int64(100)
	fetcher := metadataFetcherFunc(func(ctx context.Context, spec profile.SourceSpec) (profilefetch.MetadataResult, error) {
		changed := spec
		changed.Location = "https://example.net/new-subscription"
		if _, err := store.CommitProfileSource(ctx, source.Revision, changed); err != nil {
			t.Fatal(err)
		}
		return profilefetch.MetadataResult{
			SubscriptionUsage:     &profile.SubscriptionUsage{TotalBytes: &total},
			UsageMetadataObserved: true,
		}, nil
	})

	_, err = RefreshProfileSourceMetadata(
		ctx,
		store,
		fetcher,
		"profile-a",
		source.Revision,
	)
	if !errors.Is(err, storage.ErrProfileSourceRevisionConflict) {
		t.Fatalf("revision-change metadata error = %v", err)
	}
	after, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if after.Spec.Location != "https://example.net/new-subscription" ||
		after.SubscriptionUsage != nil ||
		after.SubscriptionMetadataObservedAt != nil {
		t.Fatalf("stale metadata touched changed source: %+v", after)
	}
}
