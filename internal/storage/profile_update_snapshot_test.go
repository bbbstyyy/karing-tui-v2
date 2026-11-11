package storage

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

func TestCommitProfileUpdateSnapshotAtomicallyAdvancesSnapshotAndSuccessState(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(ctx, 0, testRemoteProfileSource("profile-a", profile.FetchDirect))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "atomic-1")
	if err != nil {
		t.Fatal(err)
	}

	candidate := ProfileSnapshotCandidate{
		ProfileID:      "profile-a",
		SourceKind:     "sing-box",
		SourceRevision: "remote-v1",
		SourceSHA256:   strings.Repeat("a", 64),
		Nodes: []profile.SourceNode{{
			SourceKey:   "proxy-a",
			SourceName:  "Proxy A",
			PayloadJSON: []byte(`{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}`),
		}},
	}
	success := ProfileUpdateSuccess{
		SourceRevision: "remote-v1",
		ETag:           "\"etag-v1\"",
		LastModified:   "Wed, 07 Oct 2026 16:00:00 GMT",
	}
	commit, err := store.CommitProfileUpdateSnapshot(
		ctx,
		lease,
		candidate,
		ProfileSnapshotCommitOptions{},
		success,
	)
	if err != nil {
		t.Fatal(err)
	}

	state, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveUpdateID != "" || state.ActiveUpdateStarted != nil ||
		state.LastSuccessAt == nil ||
		state.LastSourceRevision != success.SourceRevision ||
		state.ETag != success.ETag ||
		state.LastModified != success.LastModified ||
		state.CurrentSnapshotID == nil ||
		*state.CurrentSnapshotID != commit.Snapshot.ID {
		t.Fatalf("profile source after atomic success = %+v", state)
	}
	current, ok, err := store.CurrentProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.ID != commit.Snapshot.ID || len(current.Nodes) != 1 {
		t.Fatalf("current snapshot after atomic success = %+v ok=%v", current, ok)
	}
}

func TestCommitProfileUpdateSnapshotStaleLeaseRollsBackSnapshot(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(ctx, 0, testRemoteProfileSource("profile-a", profile.FetchDirect))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "active-1")
	if err != nil {
		t.Fatal(err)
	}
	stale := lease
	stale.ID = "stale-1"

	_, err = store.CommitProfileUpdateSnapshot(
		ctx,
		stale,
		ProfileSnapshotCandidate{
			ProfileID:      "profile-a",
			SourceKind:     "sing-box",
			SourceRevision: "remote-v1",
			SourceSHA256:   strings.Repeat("b", 64),
			Nodes: []profile.SourceNode{{
				SourceKey:   "proxy-a",
				SourceName:  "Proxy A",
				PayloadJSON: []byte(`{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}`),
			}},
		},
		ProfileSnapshotCommitOptions{},
		ProfileUpdateSuccess{SourceRevision: "remote-v1"},
	)
	if !errors.Is(err, ErrProfileUpdateLeaseMismatch) {
		t.Fatalf("stale atomic lease error = %v", err)
	}

	var snapshots int
	if err := store.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM profile_snapshots WHERE profile_id = ?`,
		"profile-a",
	).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if snapshots != 0 {
		t.Fatalf("stale lease left %d committed snapshots, want 0", snapshots)
	}
	state, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.CurrentSnapshotID != nil || state.ActiveUpdateID != lease.ID {
		t.Fatalf("stale lease changed durable source state: %+v", state)
	}
	if err := store.FinishProfileUpdateFailure(ctx, lease, "cleanup after stale test", nil); err != nil {
		t.Fatal(err)
	}
}

func TestCommitProfileUpdateSnapshotRejectsRevisionMismatchBeforeMutation(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(ctx, 0, testRemoteProfileSource("profile-a", profile.FetchDirect))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "revision-1")
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.CommitProfileUpdateSnapshot(
		ctx,
		lease,
		ProfileSnapshotCandidate{
			ProfileID:      "profile-a",
			SourceKind:     "sing-box",
			SourceRevision: "snapshot-v1",
			SourceSHA256:   strings.Repeat("c", 64),
			Nodes: []profile.SourceNode{{
				SourceKey:   "proxy-a",
				SourceName:  "Proxy A",
				PayloadJSON: []byte(`{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}`),
			}},
		},
		ProfileSnapshotCommitOptions{},
		ProfileUpdateSuccess{SourceRevision: "different-v1"},
	)
	if !errors.Is(err, ErrInvalidProfileSnapshot) {
		t.Fatalf("source revision mismatch error = %v", err)
	}
	state, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveUpdateID != lease.ID || state.CurrentSnapshotID != nil {
		t.Fatalf("revision mismatch changed source state: %+v", state)
	}
}
