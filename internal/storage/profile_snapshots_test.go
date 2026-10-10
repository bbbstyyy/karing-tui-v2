package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

func TestProfileSnapshotsPreserveIdentityAndBoundHistory(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	first, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:      "profile-a",
		SourceKind:     "sing-box",
		SourceRevision: "etag-1",
		SourceSHA256:   strings.Repeat("a", 64),
		Nodes: []profile.SourceNode{
			testProfileSourceNode("tag-a", "Alpha", 8080),
			testProfileSourceNode("tag-b", "Same Name", 8081),
		},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Added) != 2 || len(first.Removed) != 0 || len(first.Renamed) != 0 {
		t.Fatalf("unexpected first reconciliation: %+v", first)
	}
	firstByKey := identitiesBySourceKey(first.Snapshot.Nodes)

	second, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:      "profile-a",
		SourceKind:     "sing-box",
		SourceRevision: "etag-2",
		SourceSHA256:   strings.Repeat("b", 64),
		Nodes: []profile.SourceNode{
			testProfileSourceNode("tag-a", "Alpha Renamed", 9080),
			testProfileSourceNode("tag-c", "Same Name", 9081),
		},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secondByKey := identitiesBySourceKey(second.Snapshot.Nodes)
	if secondByKey["tag-a"].NodeID != firstByKey["tag-a"].NodeID {
		t.Fatalf("stable source key changed NodeID: first=%+v second=%+v", firstByKey["tag-a"], secondByKey["tag-a"])
	}
	if secondByKey["tag-c"].NodeID == firstByKey["tag-b"].NodeID {
		t.Fatalf("same display name rebound removed node identity: old=%+v new=%+v", firstByKey["tag-b"], secondByKey["tag-c"])
	}
	if len(second.Renamed) != 1 ||
		second.Renamed[0].SourceKey != "tag-a" ||
		second.Renamed[0].BeforeName != "Alpha" ||
		second.Renamed[0].AfterName != "Alpha Renamed" {
		t.Fatalf("rename report = %+v", second.Renamed)
	}
	if len(second.Removed) != 1 || second.Removed[0].SourceKey != "tag-b" {
		t.Fatalf("removed report = %+v", second.Removed)
	}
	if len(second.Added) != 1 || second.Added[0].SourceKey != "tag-c" {
		t.Fatalf("added report = %+v", second.Added)
	}

	previous, ok, err := store.PreviousProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || previous.ID != first.Snapshot.ID {
		t.Fatalf("previous snapshot = %+v ok=%v, want first %d", previous, ok, first.Snapshot.ID)
	}
	if len(previous.Nodes) != 2 || !strings.Contains(string(previous.Nodes[0].PayloadJSON), `"server_port":8080`) {
		t.Fatalf("previous snapshot payload changed: %+v", previous.Nodes)
	}

	third, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:      "profile-a",
		SourceKind:     "sing-box",
		SourceRevision: "etag-3",
		SourceSHA256:   strings.Repeat("c", 64),
		Nodes: []profile.SourceNode{
			testProfileSourceNode("tag-a", "Alpha Renamed", 10080),
			testProfileSourceNode("tag-c", "Same Name", 10081),
		},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if third.Snapshot.ID == second.Snapshot.ID {
		t.Fatalf("new accepted source did not create immutable snapshot: %+v", third.Snapshot)
	}
	previous, ok, err = store.PreviousProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || previous.ID != second.Snapshot.ID {
		t.Fatalf("previous snapshot after third commit = %+v ok=%v, want second %d", previous, ok, second.Snapshot.ID)
	}

	var snapshotCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM profile_snapshots WHERE profile_id = ?`, "profile-a").Scan(&snapshotCount); err != nil {
		t.Fatal(err)
	}
	if snapshotCount != 2 {
		t.Fatalf("retained profile snapshots = %d, want 2", snapshotCount)
	}
	var firstCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM profile_snapshots WHERE id = ?`, first.Snapshot.ID).Scan(&firstCount); err != nil {
		t.Fatal(err)
	}
	if firstCount != 0 {
		t.Fatalf("oldest profile snapshot %d was not pruned", first.Snapshot.ID)
	}
}

func TestProfileSnapshotRejectsEmptyWithoutReplacingCurrent(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	initial, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("a", 64),
		Nodes:        []profile.SourceNode{testProfileSourceNode("tag-a", "Alpha", 8080)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("b", 64),
		Nodes:        nil,
	}, ProfileSnapshotCommitOptions{})
	if !errors.Is(err, ErrEmptyProfileSnapshot) {
		t.Fatalf("empty profile error = %v", err)
	}
	current, ok, err := store.CurrentProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.ID != initial.Snapshot.ID || len(current.Nodes) != 1 {
		t.Fatalf("rejected empty snapshot changed current state: %+v ok=%v", current, ok)
	}

	accepted, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("c", 64),
		Nodes:        nil,
	}, ProfileSnapshotCommitOptions{AllowEmpty: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted.Snapshot.Nodes) != 0 || len(accepted.Removed) != 1 {
		t.Fatalf("explicit empty commit = %+v", accepted)
	}
}

func TestProfileSnapshotInvalidReconciliationIsAtomic(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	initial, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("a", 64),
		Nodes:        []profile.SourceNode{testProfileSourceNode("tag-a", "Alpha", 8080)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("b", 64),
		Nodes: []profile.SourceNode{
			testProfileSourceNode("duplicate", "One", 8081),
			testProfileSourceNode("duplicate", "Two", 8082),
		},
	}, ProfileSnapshotCommitOptions{})
	if !errors.Is(err, ErrInvalidProfileSnapshot) {
		t.Fatalf("duplicate reconciliation error = %v", err)
	}
	current, ok, err := store.CurrentProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.ID != initial.Snapshot.ID {
		t.Fatalf("failed reconciliation advanced current snapshot: %+v ok=%v", current, ok)
	}
	var snapshotCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM profile_snapshots WHERE profile_id = ?`, "profile-a").Scan(&snapshotCount); err != nil {
		t.Fatal(err)
	}
	if snapshotCount != 1 {
		t.Fatalf("failed reconciliation left %d snapshots, want 1", snapshotCount)
	}
}

func TestProfileSnapshotSurvivesStoreReopenAndVerifiesPayloadHash(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)

	committed, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:      "profile-a",
		SourceKind:     "sing-box",
		SourceRevision: "v1",
		SourceSHA256:   strings.Repeat("d", 64),
		Nodes:          []profile.SourceNode{testProfileSourceNode("tag-a", "Alpha", 8080)},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	originalHash := committed.Snapshot.Nodes[0].PayloadSHA256
	committed.Snapshot.Nodes[0].PayloadJSON[0] = 'x'
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current, ok, err := reopened.CurrentProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.ID != committed.Snapshot.ID ||
		current.SourceRevision != "v1" ||
		current.SourceSHA256 != strings.Repeat("d", 64) ||
		len(current.Nodes) != 1 ||
		current.Nodes[0].Identity.SourceKey != "tag-a" ||
		current.Nodes[0].PayloadSHA256 != originalHash ||
		!strings.Contains(string(current.Nodes[0].PayloadJSON), `"server_port":8080`) {
		t.Fatalf("reopened profile snapshot = %+v ok=%v", current, ok)
	}
}

func TestProfileSnapshotValidatesSourceMetadataAndPayloadBeforeTransaction(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	_, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   " sing-box ",
		SourceSHA256: strings.Repeat("a", 64),
		Nodes:        []profile.SourceNode{testProfileSourceNode("tag-a", "Alpha", 8080)},
	}, ProfileSnapshotCommitOptions{})
	if !errors.Is(err, ErrInvalidProfileSnapshot) {
		t.Fatalf("source-kind validation error = %v", err)
	}
	_, err = store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: "not-a-hash",
		Nodes:        []profile.SourceNode{testProfileSourceNode("tag-a", "Alpha", 8080)},
	}, ProfileSnapshotCommitOptions{})
	if !errors.Is(err, ErrInvalidProfileSnapshot) {
		t.Fatalf("source hash validation error = %v", err)
	}
	_, err = store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-a",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("a", 64),
		Nodes: []profile.SourceNode{{
			SourceKey: "tag-a", SourceName: "Alpha", PayloadJSON: []byte("{"),
		}},
	}, ProfileSnapshotCommitOptions{})
	if !errors.Is(err, ErrInvalidProfileSnapshot) {
		t.Fatalf("invalid payload error = %v", err)
	}
}

func identitiesBySourceKey(nodes []ProfileSnapshotNode) map[string]profile.NodeIdentity {
	result := make(map[string]profile.NodeIdentity, len(nodes))
	for _, node := range nodes {
		result[node.Identity.SourceKey] = node.Identity
	}
	return result
}

func testProfileSourceNode(key, name string, port int) profile.SourceNode {
	return profile.SourceNode{
		SourceKey:  key,
		SourceName: name,
		PayloadJSON: []byte(
			`{"type":"http","tag":"` + key + `","server":"127.0.0.1","server_port":` +
				fmt.Sprint(port) + `}`,
		),
	}
}
