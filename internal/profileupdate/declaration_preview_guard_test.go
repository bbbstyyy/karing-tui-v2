package profileupdate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestProfileOverlayRevisionComparison(t *testing.T) {
	base := []storage.ProfileNodeOverlayState{{Revision: 1, Overlay: profile.NodeOverlay{
		ProfileID: "profile-a", NodeID: "node-a",
	}}}
	changed := []storage.ProfileNodeOverlayState{{Revision: 2, Overlay: base[0].Overlay}}
	if !sameProfileOverlayRevisions(base, base) {
		t.Fatal("same overlay revisions were rejected")
	}
	if sameProfileOverlayRevisions(base, changed) || sameProfileOverlayRevisions(base, nil) {
		t.Fatal("changed overlay revisions were accepted")
	}
	if sameProfileOverlayRevisions(base, []storage.ProfileNodeOverlayState{{
		Revision: 1, Overlay: profile.NodeOverlay{ProfileID: "profile-a", NodeID: "node-b"},
	}}) {
		t.Fatal("node ID substitution was accepted")
	}
}

func TestProfileStageRejectsSourceRevisionChangeWithUnchangedSnapshot(t *testing.T) {
	ctx := context.Background()
	store, _ := newDeclarationUpdateStore(t, ctx)
	defer store.Close()
	spec := profile.SourceSpec{
		ProfileID:    "profile-a",
		Format:       profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationFile,
		Location:     "/tmp/karing-profile-source.json",
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	}
	source, err := store.CommitProfileSource(ctx, 0, spec)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.CommitProfileSnapshot(ctx, storage.ProfileSnapshotCandidate{
		ProfileID: "profile-a", SourceKind: "sing-box", SourceSHA256: strings.Repeat("a", 64),
		Nodes: []profile.SourceNode{{
			SourceKey: "proxy-a", SourceName: "Alpha",
			PayloadJSON: []byte(`{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}`),
		}},
	}, storage.ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	base, err := store.CommitDeclaration(ctx, 0, declarationForProfileNode(
		"profile-a", snapshot.Snapshot.Nodes[0].Identity.NodeID, 8080,
	), "test")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewProfileSnapshotDeclaration(ctx, store, "profile-a", snapshot.Snapshot.ID, base.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if preview.SourceRevision != source.Revision {
		t.Fatalf("preview source revision = %d, want %d", preview.SourceRevision, source.Revision)
	}
	spec.UserAgent = "updated-client"
	updated, err := store.CommitProfileSource(ctx, source.Revision, spec)
	if err != nil {
		t.Fatal(err)
	}
	if updated.CurrentSnapshotID == nil || *updated.CurrentSnapshotID != snapshot.Snapshot.ID {
		t.Fatal("editing source unexpectedly changed current snapshot")
	}
	newPreview, err := PreviewProfileSnapshotDeclaration(ctx, store, "profile-a", snapshot.Snapshot.ID, base.Revision)
	if err != nil || newPreview.SourceRevision != updated.Revision {
		t.Fatalf("new preview source revision = %+v, err=%v", newPreview, err)
	}
	if newPreview.CandidateSHA256 != preview.CandidateSHA256 ||
		newPreview.RuntimeOverlaySHA256 != preview.RuntimeOverlaySHA256 {
		t.Fatal("source-only change incorrectly changed candidate or overlay digest")
	}
	_, err = StageProfileSnapshotDeclaration(ctx, store, "profile-a", snapshot.Snapshot.ID,
		preview.SourceRevision, base.Revision, preview.CandidateSHA256, preview.RuntimeOverlaySHA256)
	if !errors.Is(err, ErrProfileStagePreviewMismatch) {
		t.Fatalf("stale source revision was accepted: %v", err)
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil || current.Revision != base.Revision {
		t.Fatalf("stale source revision modified declaration: %+v %v", current, err)
	}
	result, err := StageProfileSnapshotDeclaration(ctx, store, "profile-a", snapshot.Snapshot.ID,
		newPreview.SourceRevision, base.Revision, newPreview.CandidateSHA256, newPreview.RuntimeOverlaySHA256)
	if err != nil || result.Revision.Revision != base.Revision+1 {
		t.Fatalf("newly previewed source could not stage: %+v %v", result, err)
	}
}
