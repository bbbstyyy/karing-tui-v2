package storage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

type guardedStageFixture struct {
	store          *Store
	profileID      string
	snapshotID     int64
	sourceRevision uint64
	declRevision   uint64
	nodeID         string
}

func newGuardedStageFixture(t *testing.T) guardedStageFixture {
	t.Helper()
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	spec := testRemoteProfileSource("profile-a", profile.FetchDirect)
	source, err := store.CommitProfileSource(ctx, 0, spec)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID: "profile-a", SourceKind: "sing-box", SourceSHA256: strings.Repeat("a", 64),
		Nodes: []profile.SourceNode{
			testProfileSourceNode("proxy-a", "Alpha", 8080),
		},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	decl, err := store.CommitDeclaration(ctx, 0, []byte(`{"base":true}`), "test")
	if err != nil {
		t.Fatal(err)
	}
	return guardedStageFixture{
		store: store, profileID: "profile-a",
		snapshotID: snapshot.Snapshot.ID, sourceRevision: source.Revision,
		declRevision: decl.Revision, nodeID: snapshot.Snapshot.Nodes[0].Identity.NodeID,
	}
}

func (f guardedStageFixture) commit(ctx context.Context, overlays []ProfileNodeOverlayState) (DeclarationRevision, error) {
	return f.store.CommitProfileDeclarationGuarded(ctx, f.profileID,
		f.snapshotID, f.sourceRevision, overlays, f.declRevision,
		[]byte(`{"staged":true}`), "test:staged")
}

func TestGuardedProfileStageAtomicallyRejectsStaleSourceSnapshotAndOverlays(t *testing.T) {
	for _, test := range []struct {
		name string
		mutate func(*testing.T, guardedStageFixture) []ProfileNodeOverlayState
	}{
		{name: "source-revision", mutate: func(t *testing.T, f guardedStageFixture) []ProfileNodeOverlayState {
			source, err := f.store.ProfileSource(context.Background(), f.profileID)
			if err != nil {
				t.Fatal(err)
			}
			spec := source.Spec
			spec.UserAgent = "updated"
			if _, err := f.store.CommitProfileSource(context.Background(), source.Revision, spec); err != nil {
				t.Fatal(err)
			}
			return nil
		}},
		{name: "snapshot-pointer", mutate: func(t *testing.T, f guardedStageFixture) []ProfileNodeOverlayState {
			_, err := f.store.CommitProfileSnapshot(context.Background(), ProfileSnapshotCandidate{
				ProfileID: f.profileID, SourceKind: "sing-box", SourceSHA256: strings.Repeat("b", 64),
				Nodes: []profile.SourceNode{testProfileSourceNode("proxy-a", "Alpha", 9090)},
			}, ProfileSnapshotCommitOptions{})
			if err != nil {
				t.Fatal(err)
			}
			return nil
		}},
		{name: "overlay-revision", mutate: func(t *testing.T, f guardedStageFixture) []ProfileNodeOverlayState {
			first, err := f.store.CommitProfileNodeOverlay(context.Background(), 0, profile.NodeOverlay{
				ProfileID: f.profileID, NodeID: f.nodeID,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.store.CommitProfileNodeOverlay(context.Background(), first.Revision, profile.NodeOverlay{
				ProfileID: f.profileID, NodeID: f.nodeID, Favorite: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			return []ProfileNodeOverlayState{first}
		}},
		{name: "new-overlay", mutate: func(t *testing.T, f guardedStageFixture) []ProfileNodeOverlayState {
			_, err := f.store.CommitProfileNodeOverlay(context.Background(), 0, profile.NodeOverlay{
				ProfileID: f.profileID, NodeID: f.nodeID, Disabled: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			return nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGuardedStageFixture(t)
			defer fixture.store.Close()
			overlays := test.mutate(t, fixture)
			_, err := fixture.commit(context.Background(), overlays)
			if !errors.Is(err, ErrProfileDeclarationGuardConflict) {
				t.Fatalf("stale stage error = %v", err)
			}
			current, err := fixture.store.CurrentDeclaration(context.Background())
			if err != nil || current.Revision != fixture.declRevision {
				t.Fatalf("stale guard advanced declaration: %+v %v", current, err)
			}
		})
	}
}

func TestGuardedProfileStageSerializesConcurrentDeclarationCAS(t *testing.T) {
	fixture := newGuardedStageFixture(t)
	defer fixture.store.Close()
	const contenders = 4
	start := make(chan struct{})
	results := make(chan error, contenders)
	var wg sync.WaitGroup
	wg.Add(contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := fixture.commit(context.Background(), nil)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	accepted, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrDeclarationRevisionConflict):
			rejected++
		default:
			t.Fatalf("unexpected concurrent stage error: %v", err)
		}
	}
	if accepted != 1 || rejected != contenders-1 {
		t.Fatalf("concurrent guard accepted=%d rejected=%d", accepted, rejected)
	}
	current, err := fixture.store.CurrentDeclaration(context.Background())
	if err != nil || current.Revision != fixture.declRevision+1 || current.Source != "test:staged" {
		t.Fatalf("concurrent guarded stage result = %+v %v", current, err)
	}
	runtime, err := fixture.store.Snapshot(context.Background())
	if err != nil || runtime.Revision != 0 {
		t.Fatalf("staging altered runtime state: %+v %v", runtime, err)
	}
}
