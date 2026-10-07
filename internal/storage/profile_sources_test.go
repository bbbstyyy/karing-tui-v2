package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

func TestProfileSourceCASAndCurrentSnapshotLink(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	spec := testRemoteProfileSource("profile-a", profile.FetchDirect)
	created, err := store.CommitProfileSource(ctx, 0, spec)
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || created.Spec != spec || created.CurrentSnapshotID != nil {
		t.Fatalf("created profile source = %+v", created)
	}
	if created.LastAttemptAt != nil || created.LastSuccessAt != nil ||
		created.LastError != "" || created.ConsecutiveFailures != 0 ||
		created.ActiveUpdateID != "" || created.ActiveUpdateStarted != nil {
		t.Fatalf("new profile source has unexpected update state: %+v", created)
	}

	snapshot, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("a", 64),
		Nodes: []profile.SourceNode{{
			SourceKey:   "proxy-a",
			SourceName:  "Proxy A",
			PayloadJSON: []byte(`{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}`),
		}},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	linked, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if linked.CurrentSnapshotID == nil || *linked.CurrentSnapshotID != snapshot.Snapshot.ID {
		t.Fatalf("profile source current snapshot = %+v, want %d", linked.CurrentSnapshotID, snapshot.Snapshot.ID)
	}

	updatedSpec := spec
	updatedSpec.Fetch = profile.FetchPolicy{Mode: profile.FetchSelected}
	updatedSpec.UserAgent = "karing-tui-v2/test"
	updatedSpec.UpdateInterval = profile.DefaultUpdateInterval
	updated, err := store.CommitProfileSource(ctx, 1, updatedSpec)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.Spec != updatedSpec {
		t.Fatalf("updated profile source = %+v", updated)
	}
	if updated.CreatedAt != created.CreatedAt || updated.UpdatedAt.Before(created.UpdatedAt) {
		t.Fatalf("profile source timestamps changed unexpectedly: created=%+v updated=%+v", created, updated)
	}

	if _, err := store.CommitProfileSource(ctx, 1, spec); !errors.Is(err, ErrProfileSourceRevisionConflict) {
		t.Fatalf("stale source CAS error = %v", err)
	}
}

func TestListProfileSourcesIsStableAndCarriesSchedule(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	second := testRemoteProfileSource("profile-b", profile.FetchDirect)
	second.UpdateInterval = profile.MaxUpdateInterval
	if _, err := store.CommitProfileSource(ctx, 0, second); err != nil {
		t.Fatal(err)
	}
	first := testRemoteProfileSource("profile-a", profile.FetchSelected)
	first.UpdateInterval = profile.DefaultUpdateInterval
	if _, err := store.CommitProfileSource(ctx, 0, first); err != nil {
		t.Fatal(err)
	}

	items, err := store.ListProfileSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 ||
		items[0].Spec.ProfileID != "profile-a" ||
		items[0].Spec.UpdateInterval != profile.DefaultUpdateInterval ||
		items[1].Spec.ProfileID != "profile-b" ||
		items[1].Spec.UpdateInterval != profile.MaxUpdateInterval {
		t.Fatalf("profile source list = %+v", items)
	}
}

func TestProfileUpdateLeaseFailureThenSuccess(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	spec := testRemoteProfileSource("profile-a", profile.FetchDirect)
	source, err := store.CommitProfileSource(ctx, 0, spec)
	if err != nil {
		t.Fatal(err)
	}

	first, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "update-1")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "update-1" || first.ProfileID != "profile-a" ||
		first.SourceRevision != source.Revision || first.StartedAt.IsZero() {
		t.Fatalf("first update lease = %+v", first)
	}
	if _, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "update-2"); !errors.Is(err, ErrProfileUpdateInProgress) {
		t.Fatalf("duplicate update begin error = %v", err)
	}
	if _, err := store.CommitProfileSource(ctx, source.Revision, spec); !errors.Is(err, ErrProfileUpdateInProgress) {
		t.Fatalf("source mutation during active update error = %v", err)
	}

	retryAfter := time.Now().UTC().Add(5 * time.Minute).Round(time.Second)
	if err := store.FinishProfileUpdateFailure(ctx, first, "temporary network failure", &retryAfter); err != nil {
		t.Fatal(err)
	}
	failed, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if failed.ActiveUpdateID != "" || failed.ActiveUpdateStarted != nil ||
		failed.LastAttemptAt == nil || failed.LastSuccessAt != nil ||
		failed.LastError != "temporary network failure" ||
		failed.ConsecutiveFailures != 1 ||
		failed.RetryAfterAt == nil ||
		!failed.RetryAfterAt.Equal(retryAfter) {
		t.Fatalf("failed update state = %+v", failed)
	}

	second, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "update-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishProfileUpdateSuccess(ctx, second, ProfileUpdateSuccess{
		SourceRevision: "source-revision-2",
		ETag:           "\"etag-2\"",
		LastModified:   "Wed, 07 Oct 2026 16:00:00 GMT",
	}); err != nil {
		t.Fatal(err)
	}
	succeeded, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if succeeded.ActiveUpdateID != "" || succeeded.ActiveUpdateStarted != nil ||
		succeeded.LastAttemptAt == nil || succeeded.LastSuccessAt == nil ||
		succeeded.LastError != "" || succeeded.LastSourceRevision != "source-revision-2" ||
		succeeded.ETag != "\"etag-2\"" ||
		succeeded.LastModified != "Wed, 07 Oct 2026 16:00:00 GMT" ||
		succeeded.ConsecutiveFailures != 0 || succeeded.RetryAfterAt != nil {
		t.Fatalf("successful update state = %+v", succeeded)
	}
	if succeeded.LastSuccessAt.Before(*succeeded.LastAttemptAt) {
		t.Fatalf("last success precedes last attempt: %+v", succeeded)
	}

	if err := store.FinishProfileUpdateSuccess(ctx, first, ProfileUpdateSuccess{SourceRevision: "stale"}); !errors.Is(err, ErrProfileUpdateLeaseMismatch) {
		t.Fatalf("stale lease completion error = %v", err)
	}
}

func TestProfileUpdateRejectsDisabledAndStaleSource(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	spec := testRemoteProfileSource("profile-a", profile.FetchDirect)
	spec.Enabled = false
	source, err := store.CommitProfileSource(ctx, 0, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "disabled-1"); !errors.Is(err, ErrProfileSourceDisabled) {
		t.Fatalf("disabled update begin error = %v", err)
	}

	spec.Enabled = true
	source, err = store.CommitProfileSource(ctx, source.Revision, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision-1, "stale-1"); !errors.Is(err, ErrProfileSourceRevisionConflict) {
		t.Fatalf("stale source revision error = %v", err)
	}
	if _, err := store.BeginProfileUpdate(ctx, "missing", 1, "missing-1"); !errors.Is(err, ErrProfileSourceNotFound) {
		t.Fatalf("missing profile source error = %v", err)
	}
}

func TestProfileUpdateRecoveryClearsInterruptedLease(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)

	source, err := store.CommitProfileSource(ctx, 0, testRemoteProfileSource("profile-a", profile.FetchDirect))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "crash-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	before, err := reopened.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if before.ActiveUpdateID != lease.ID || before.ActiveUpdateStarted == nil {
		t.Fatalf("persisted active update disappeared before recovery: %+v", before)
	}

	interrupted, err := reopened.RecoverInterruptedProfileUpdates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(interrupted) != 1 ||
		interrupted[0].ProfileID != "profile-a" ||
		interrupted[0].UpdateID != lease.ID ||
		interrupted[0].StartedAt.IsZero() {
		t.Fatalf("interrupted profile updates = %+v", interrupted)
	}

	after, err := reopened.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if after.ActiveUpdateID != "" || after.ActiveUpdateStarted != nil ||
		after.LastError != "daemon restarted during profile update" ||
		after.ConsecutiveFailures != 1 {
		t.Fatalf("recovered profile source = %+v", after)
	}

	next, err := reopened.BeginProfileUpdate(ctx, "profile-a", source.Revision, "retry-1")
	if err != nil {
		t.Fatal(err)
	}
	if next.ID != "retry-1" {
		t.Fatalf("retry lease = %+v", next)
	}
}

func TestProfileUpdateIDAndStatusAreBoundedTerminalSafe(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(ctx, 0, testRemoteProfileSource("profile-a", profile.FetchDirect))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "bad update"); !errors.Is(err, ErrInvalidProfileUpdateID) {
		t.Fatalf("unsafe update ID error = %v", err)
	}
	lease, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "safe-update")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinishProfileUpdateFailure(ctx, lease, "bad\nterminal", nil); !errors.Is(err, ErrInvalidProfileUpdateStatus) {
		t.Fatalf("unsafe failure status error = %v", err)
	}
	state, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveUpdateID != lease.ID {
		t.Fatalf("rejected unsafe status unexpectedly cleared lease: %+v", state)
	}
	if err := store.FinishProfileUpdateFailure(ctx, lease, "safe failure", nil); err != nil {
		t.Fatal(err)
	}
}

func testRemoteProfileSource(profileID string, mode profile.FetchMode) profile.SourceSpec {
	return profile.SourceSpec{
		ProfileID:    profileID,
		Format:       profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationURL,
		Location:     "https://example.com/subscription?token=secret",
		UserAgent:    "",
		Fetch:        profile.FetchPolicy{Mode: mode},
		Enabled:      true,
	}
}
